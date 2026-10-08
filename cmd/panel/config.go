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
	"strconv"
	"strings"
	"time"
)

func supportsDirectVersion(output string) bool {
	fields := strings.Fields(output)
	if len(fields) < 3 || fields[0] != "HAProxy" || fields[1] != "version" {
		return false
	}
	parts := strings.Split(fields[2], ".")
	if len(parts) < 2 {
		return false
	}
	major, e1 := strconv.Atoi(parts[0])
	minor, e2 := strconv.Atoi(parts[1])
	return e1 == nil && e2 == nil && (major > 3 || major == 3 && minor >= 2)
}

// Also check at startup/restore: those paths do not pass through the settings
// Runtime API preflight. Standard Docker/native deployments install this binary.
func checkDirectHAProxyVersion() error {
	path, err := exec.LookPath("haproxy")
	if err != nil {
		return nil // same optional local validator as writeConfig (unit/dev builds)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "-v").CombinedOutput()
	if err != nil || !supportsDirectVersion(string(out)) {
		return fmt.Errorf("direct mode requires HAProxy 3.2 or newer")
	}
	return nil
}

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
	direct := a.proxyMode == "direct"
	directLimits := a.directLimits
	routes := make([]Route, 0, len(a.routes))
	for _, s := range a.routes {
		s.mu.Lock()
		routes = append(routes, s.Route)
		s.mu.Unlock()
	}
	a.mu.RUnlock()
	mixedDirect := false
	for _, r := range routes {
		mixedDirect = mixedDirect || (direct && r.TLSPassthrough)
	}
	if direct {
		if err := checkDirectHAProxyVersion(); err != nil {
			return err
		}
	}
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
	publicLimit := a.connectionLimit()
	reserve := max(8, min(256, publicLimit/10))
	globalLimit := 2*publicLimit + reserve
	if direct && !mixedDirect {
		globalLimit = publicLimit + reserve
	}
	// A terminated two-hop client consumes an outer AND an inner session. Without an
	// outer cap, pending TLS handshakes can consume every global slot and prevent
	// their own inner frontend from accepting, while CPU remains mostly idle.
	fmt.Fprintf(&b, "global\n  maxconn %d\n  hard-stop-after 1h\n  stats timeout 2m\n  stats socket "+filepath.Join(a.data, "haproxy.sock")+" mode 660"+socketGroup+" level admin expose-fd listeners\n  tune.ssl.default-dh-param 2048\n  ssl-default-bind-options ssl-min-ver TLSv1.2\n", globalLimit)
	fmt.Fprintln(&b, "defaults\n  mode http\n  timeout connect 5s\n  timeout client 1h\n  timeout server 1h\n  timeout tunnel 1h\n  timeout http-request 15s\n  timeout http-keep-alive 30s\n  timeout queue 10s\n  timeout client-fin 30s\n  timeout server-fin 30s\n  option clitcpka\n  option srvtcpka")
	if !direct {
		fmt.Fprintf(&b, "frontend public_sni\n  mode tcp\n  maxconn %d\n  bind :443\n  tcp-request inspect-delay 5s\n  tcp-request content accept if { req.ssl_hello_type 1 }\n  tcp-request content reject if WAIT_END\n", publicLimit)
		fmt.Fprintf(&b, "  acl primary req.ssl_sni -i %s\n  use_backend relay_fallback if primary\n", domain)
		for _, r := range routes {
			fmt.Fprintf(&b, "  acl sni_%d req.ssl_sni %s\n", r.ID, aclPattern(r.SNI))
		}
		for _, r := range routes {
			fmt.Fprintf(&b, "  use_backend relay_%d if sni_%d\n", r.ID, r.ID)
		}
		fmt.Fprintln(&b, "  default_backend relay_fallback")
		fmt.Fprintf(&b, "backend relay_fallback\n  mode tcp\n  server relay %s\n", relaySocket(a.data, 0))
		for _, r := range routes {
			fmt.Fprintf(&b, "backend relay_%d\n  mode tcp\n  server relay %s\n", r.ID, relaySocket(a.data, r.ID))
		}
		fmt.Fprintf(&b, "frontend internal_tls\n  mode http\n  maxconn %d\n  timeout client 30s\n  bind %s ssl crt %s", publicLimit+reserve, internalTLSBind(), filepath.Join(a.data, "certs", "fallback.pem"))
	} else if mixedDirect {
		// Only the SNI dispatcher sees all connections. Terminated routes use
		// a second frontend; opaque routes go straight to their final backend.
		fmt.Fprintf(&b, "frontend public_direct\n  mode tcp\n  option contstats\n  maxconn %d\n  bind :443\n  tcp-request inspect-delay 5s\n  tcp-request content accept if { req.ssl_hello_type 1 }\n  tcp-request content reject if WAIT_END\n", publicLimit)
		fmt.Fprintf(&b, "  acl primary req.ssl_sni -i %s\n  use_backend tls_bridge if primary\n", domain)
		// Include ordinary routes too: an exact terminated SNI must win over
		// a wildcard passthrough SNI, not just the other way around.
		for _, r := range routes {
			backend := "tls_bridge"
			if r.TLSPassthrough {
				backend = routeBackend(r, true)
			}
			fmt.Fprintf(&b, "  acl sni_%d req.ssl_sni %s\n  use_backend %s if sni_%d\n", r.ID, aclPattern(r.SNI), backend, r.ID)
		}
		fmt.Fprintln(&b, "  default_backend tls_bridge\nbackend tls_bridge\n  mode tcp\n  balance leastconn")
		for i := 0; i < internalTLSShards; i++ {
			fmt.Fprintf(&b, "  server tls%d 127.0.0.1:%d\n", i, internalTLSFirstPort+i)
		}
		fmt.Fprintf(&b, "frontend internal_tls\n  mode http\n  option contstats\n  maxconn %d\n  timeout client 30s\n  bind %s ssl crt %s", publicLimit+reserve, internalTLSBind(), filepath.Join(a.data, "certs", "fallback.pem"))
	} else {
		fmt.Fprintf(&b, "frontend public_direct\n  mode http\n  option contstats\n  maxconn %d\n  timeout client 30s\n  bind :443 ssl crt %s", publicLimit, filepath.Join(a.data, "certs", "fallback.pem"))
	}
	for _, r := range routes {
		if r.TLSPassthrough {
			continue
		}
		fmt.Fprintf(&b, " crt %s", filepath.Join(a.data, "certs", routeCert(r)+".pem"))
	}
	fmt.Fprintln(&b, " alpn http/1.1\n  http-request set-header X-Forwarded-Proto https")
	fmt.Fprintf(&b, "  acl primary ssl_fc_sni -i %s\n  use_backend fallback_page if primary\n", domain)
	for _, r := range routes {
		if r.TLSPassthrough {
			continue
		}
		fmt.Fprintf(&b, "  acl host_%d ssl_fc_sni %s\n", r.ID, aclPattern(r.SNI))
	}
	for _, r := range routes {
		if r.TLSPassthrough {
			continue
		}
		fmt.Fprintf(&b, "  use_backend %s if host_%d\n", routeBackend(r, direct), r.ID)
	}
	fmt.Fprintln(&b, "  default_backend fallback_page\nbackend fallback_page\n  server page 127.0.0.1:8181")
	for _, r := range routes {
		if r.TLSPassthrough && !direct {
			// Go owns the strict relay path.
			continue
		}
		mode, rule := "http", "http-request"
		if r.TLSPassthrough {
			mode, rule = "tcp", "tcp-request content"
		}
		fmt.Fprintf(&b, "backend %s\n  mode %s\n", routeBackend(r, direct), mode)
		if direct && r.Paused {
			if r.TLSPassthrough {
				fmt.Fprintln(&b, "  tcp-request content reject")
			} else {
				fmt.Fprintln(&b, "  http-request deny deny_status 503")
			}
		}
		if direct && directLimits {
			if r.UpBPS > 0 || r.DownBPS > 0 {
				fmt.Fprintln(&b, "  stick-table type integer size 1 expire 1m store bytes_in_rate(1s),bytes_out_rate(1s)")
			}
			if r.UpBPS > 0 {
				fmt.Fprintf(&b, "  filter bwlim-in upload limit %d key int(1)\n  %s set-bandwidth-limit upload\n", r.UpBPS, rule)
			}
			if r.DownBPS > 0 {
				fmt.Fprintf(&b, "  filter bwlim-out download limit %d key int(1)\n  %s set-bandwidth-limit download\n", r.DownBPS, rule)
			}
			if r.DailyLimit > 0 || r.MonthlyLimit > 0 {
				// Watchdog can recover this policy even when the agent is dead.
				fmt.Fprintf(&b, "  # fluxgate-quota %s\n", routeBackend(r, true))
			}
		}
		fmt.Fprintf(&b, "  server target %s", net.JoinHostPort(r.IP, fmt.Sprint(r.Port)))
		if r.TLS && !r.TLSPassthrough {
			fmt.Fprint(&b, " ssl")
			if r.Verify {
				fmt.Fprintf(&b, " verify required ca-file @system-ca verifyhost %s sni str(%s)", r.VerifyName, r.VerifyName)
			} else {
				fmt.Fprint(&b, " verify none sni ssl_fc_sni")
			}
		}
		if direct && directLimits && (r.DailyLimit > 0 || r.MonthlyLimit > 0) {
			fmt.Fprint(&b, " disabled") // fail closed until fresh stats are reconciled
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
