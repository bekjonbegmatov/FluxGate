package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"time"
)

func (a *App) healthAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if a.closing.Load() || a.db.PingContext(ctx) != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	// TCP accept alone does not prove that the TLS/relay/HTTP chain responds.
	if last := a.publicProbe.lastOK.Load(); last == 0 || time.Since(time.Unix(last, 0)) > 45*time.Second {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	// Check both services, not only that the SPA is being served from disk.
	addresses := []struct{ network, address string }{{"unix", filepath.Join(a.data, "haproxy.sock")}, {"tcp", "127.0.0.1:443"}, {"tcp", "127.0.0.1:8181"}}
	if !a.directMode() {
		addresses = append(addresses, struct{ network, address string }{"tcp", "127.0.0.1:8443"})
	}
	for _, addr := range addresses {
		c, err := (&net.Dialer{}).DialContext(ctx, addr.network, addr.address)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = c.Close()
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func checkPanelHealth() error {
	host, port, err := net.SplitHostPort(env("PANEL_LISTEN", ":9389"))
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := &http.Client{Timeout: 3 * time.Second}
	res, err := c.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("readiness: HTTP %d", res.StatusCode)
	}
	return nil
}
