package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

func routeCert(r Route) string {
	h := sha256.Sum256([]byte(r.SNI))
	return fmt.Sprintf("route_%d_%x", r.ID, h[:6])
}
func aclPattern(s string) string {
	if strings.HasPrefix(s, "*.") {
		return "-m reg ^[^.]+\\." + strings.ReplaceAll(s[2:], ".", "\\.") + "$"
	}
	return "-i " + s
}
func (a *App) writeConfig() error {
	a.configMu.Lock()
	defer a.configMu.Unlock()
	a.mu.RLock()
	routes := make([]*RouteState, 0, len(a.routes))
	for _, s := range a.routes {
		routes = append(routes, s)
	}
	a.mu.RUnlock()
	sort.Slice(routes, func(i, j int) bool {
		wi := strings.HasPrefix(routes[i].Route.SNI, "*.")
		wj := strings.HasPrefix(routes[j].Route.SNI, "*.")
		if wi != wj {
			return !wi
		}
		return len(routes[i].Route.SNI) > len(routes[j].Route.SNI)
	})
	var b bytes.Buffer
	fmt.Fprintln(&b, "global\n  maxconn 20000\n  stats socket "+filepath.Join(a.data, "haproxy.sock")+" mode 660 level admin\n  tune.ssl.default-dh-param 2048")
	fmt.Fprintln(&b, "defaults\n  mode http\n  timeout connect 10s\n  timeout client 1h\n  timeout server 1h\n  timeout tunnel 1h")
	fmt.Fprintln(&b, "frontend public_sni\n  mode tcp\n  bind :443\n  tcp-request inspect-delay 5s\n  tcp-request content accept if { req.ssl_hello_type 1 }")
	fmt.Fprintf(&b, "  acl primary req.ssl_sni -i %s\n  use_backend relay_fallback if primary\n", a.domain)
	for _, s := range routes {
		r := s.Route
		fmt.Fprintf(&b, "  acl sni_%d req.ssl_sni %s\n", r.ID, aclPattern(r.SNI))
	}
	for _, s := range routes {
		fmt.Fprintf(&b, "  use_backend relay_%d if sni_%d\n", s.Route.ID, s.Route.ID)
	}
	fmt.Fprintln(&b, "  default_backend relay_fallback")
	fmt.Fprintln(&b, "backend relay_fallback\n  mode tcp\n  server relay 127.0.0.1:9999")
	for _, s := range routes {
		fmt.Fprintf(&b, "backend relay_%d\n  mode tcp\n  server relay 127.0.0.1:%d\n", s.Route.ID, 10000+s.Route.ID)
	}
	fmt.Fprintf(&b, "frontend internal_tls\n  mode http\n  bind 127.0.0.1:8443 ssl crt %s", filepath.Join(a.data, "certs", "fallback.pem"))
	for _, s := range routes {
		fmt.Fprintf(&b, " crt %s", filepath.Join(a.data, "certs", routeCert(s.Route)+".pem"))
	}
	fmt.Fprintln(&b, " alpn http/1.1\n  http-request set-header X-Forwarded-Proto https")
	fmt.Fprintf(&b, "  acl primary ssl_fc_sni -i %s\n  use_backend fallback_page if primary\n", a.domain)
	for _, s := range routes {
		r := s.Route
		fmt.Fprintf(&b, "  acl host_%d ssl_fc_sni %s\n", r.ID, aclPattern(r.SNI))
	}
	for _, s := range routes {
		r := s.Route
		s.mu.Lock()
		blocked := s.blocked()
		s.mu.Unlock()
		if r.Paused {
			fmt.Fprintf(&b, "  http-request deny deny_status 503 if host_%d\n", r.ID)
		} else if blocked {
			fmt.Fprintf(&b, "  http-request deny deny_status 429 if host_%d\n", r.ID)
		}
	}
	for _, s := range routes {
		fmt.Fprintf(&b, "  use_backend target_%d if host_%d\n", s.Route.ID, s.Route.ID)
	}
	fmt.Fprintln(&b, "  default_backend fallback_page\nbackend fallback_page\n  server page 127.0.0.1:8181")
	for _, s := range routes {
		r := s.Route
		fmt.Fprintf(&b, "backend target_%d\n  mode http\n  server target %s", r.ID, net.JoinHostPort(r.IP, fmt.Sprint(r.Port)))
		if r.TLS {
			fmt.Fprint(&b, " ssl")
			if r.Verify {
				fmt.Fprintf(&b, " verify required ca-file @system-ca verifyhost %s sni str(%s)", r.VerifyName, r.VerifyName)
			} else {
				fmt.Fprint(&b, " verify none sni ssl_fc_sni")
			}
		}
		fmt.Fprintln(&b, " check")
	}
	tmp := filepath.Join(a.data, "haproxy.cfg.candidate")
	if err := os.WriteFile(tmp, b.Bytes(), 0600); err != nil {
		return err
	}
	if path, err := exec.LookPath("haproxy"); err == nil {
		out, err := exec.Command(path, "-c", "-f", tmp).CombinedOutput()
		if err != nil {
			return fmt.Errorf("HAProxy config: %s: %w", strings.TrimSpace(string(out)), err)
		}
	}
	return os.Rename(tmp, filepath.Join(a.data, "haproxy.cfg"))
}
