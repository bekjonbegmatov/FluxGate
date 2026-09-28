package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
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
	domain := a.domain
	routes := make([]Route, 0, len(a.routes))
	for _, s := range a.routes {
		s.mu.Lock()
		routes = append(routes, s.Route)
		s.mu.Unlock()
	}
	a.mu.RUnlock()
	sort.Slice(routes, func(i, j int) bool {
		wi := strings.HasPrefix(routes[i].SNI, "*.")
		wj := strings.HasPrefix(routes[j].SNI, "*.")
		if wi != wj {
			return !wi
		}
		if len(routes[i].SNI) != len(routes[j].SNI) {
			return len(routes[i].SNI) > len(routes[j].SNI)
		}
		return routes[i].ID < routes[j].ID
	})
	var b bytes.Buffer
	socketGroup := ""
	if a.data != "/data" {
		socketGroup = " group fluxgate"
	}
	fmt.Fprintln(&b, "global\n  maxconn 20000\n  hard-stop-after 1h\n  stats socket "+filepath.Join(a.data, "haproxy.sock")+" mode 660"+socketGroup+" level admin expose-fd listeners\n  tune.ssl.default-dh-param 2048\n  ssl-default-bind-options ssl-min-ver TLSv1.2")
	fmt.Fprintln(&b, "defaults\n  mode http\n  timeout connect 5s\n  timeout client 1h\n  timeout server 1h\n  timeout tunnel 1h\n  timeout http-request 15s\n  timeout http-keep-alive 30s\n  timeout queue 10s\n  timeout client-fin 30s\n  timeout server-fin 30s\n  option clitcpka\n  option srvtcpka")
	fmt.Fprintln(&b, "frontend public_sni\n  mode tcp\n  bind :443\n  tcp-request inspect-delay 5s\n  tcp-request content accept if { req.ssl_hello_type 1 }")
	fmt.Fprintf(&b, "  acl primary req.ssl_sni -i %s\n  use_backend relay_fallback if primary\n", domain)
	for _, r := range routes {
		fmt.Fprintf(&b, "  acl sni_%d req.ssl_sni %s\n", r.ID, aclPattern(r.SNI))
	}
	for _, r := range routes {
		fmt.Fprintf(&b, "  use_backend relay_%d if sni_%d\n", r.ID, r.ID)
	}
	fmt.Fprintln(&b, "  default_backend relay_fallback")
	fmt.Fprintln(&b, "backend relay_fallback\n  mode tcp\n  server relay 127.0.0.1:9999")
	for _, r := range routes {
		fmt.Fprintf(&b, "backend relay_%d\n  mode tcp\n  server relay 127.0.0.1:%d\n", r.ID, 10000+r.ID)
	}
	fmt.Fprintf(&b, "frontend internal_tls\n  mode http\n  bind 127.0.0.1:8443 ssl crt %s", filepath.Join(a.data, "certs", "fallback.pem"))
	for _, r := range routes {
		fmt.Fprintf(&b, " crt %s", filepath.Join(a.data, "certs", routeCert(r)+".pem"))
	}
	fmt.Fprintln(&b, " alpn http/1.1\n  http-request set-header X-Forwarded-Proto https")
	fmt.Fprintf(&b, "  acl primary ssl_fc_sni -i %s\n  use_backend fallback_page if primary\n", domain)
	for _, r := range routes {
		fmt.Fprintf(&b, "  acl host_%d ssl_fc_sni %s\n", r.ID, aclPattern(r.SNI))
	}
	for _, r := range routes {
		fmt.Fprintf(&b, "  use_backend target_%d if host_%d\n", r.ID, r.ID)
	}
	fmt.Fprintln(&b, "  default_backend fallback_page\nbackend fallback_page\n  server page 127.0.0.1:8181")
	for _, r := range routes {
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
	path := filepath.Join(a.data, "haproxy.cfg")
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, b.Bytes()) {
		return nil
	}
	tmp := filepath.Join(a.data, "haproxy.cfg.candidate")
	if err := os.WriteFile(tmp, b.Bytes(), 0600); err != nil {
		return err
	}
	if path, err := exec.LookPath("haproxy"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, path, "-c", "-f", tmp).CombinedOutput()
		if err != nil {
			return fmt.Errorf("HAProxy config: %s: %w", strings.TrimSpace(string(out)), err)
		}
	}
	return os.Rename(tmp, path)
}
