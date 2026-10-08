package main

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPassthroughMigrationAndRouteAPI(t *testing.T) {
	dir, err := os.MkdirTemp("", "fg-pass-") // short enough for Darwin Unix sockets
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	db, err := sql.Open("sqlite", filepath.Join(dir, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE routes(id INTEGER PRIMARY KEY,name TEXT,sni TEXT UNIQUE,ip TEXT,port INTEGER,tls INTEGER,verify INTEGER,verify_name TEXT,paused INTEGER,daily_limit INTEGER,monthly_limit INTEGER,count_mode TEXT,down_bps INTEGER,up_bps INTEGER,threshold INTEGER,created_at INTEGER,up_total INTEGER DEFAULT 0,down_total INTEGER DEFAULT 0,monitor INTEGER);
CREATE TABLE periods(route_id INTEGER,kind TEXT,key TEXT,used INTEGER,extra INTEGER,threshold_sent INTEGER,exhausted_sent INTEGER,PRIMARY KEY(route_id,kind,key));
INSERT INTO routes VALUES(1,'Legacy','legacy.example.test','127.0.0.1',8080,0,0,'',0,0,0,'both',0,0,80,1,123,456,0);`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err = migrateRoutePassthrough(db); err != nil {
			t.Fatal(err)
		}
	}
	a := &App{db: db, data: dir, domain: "fallback.example.test", secretPath: "admin", routes: map[int64]*RouteState{}, location: time.UTC}
	if err = os.MkdirAll(filepath.Join(dir, "certs"), 0700); err != nil {
		t.Fatal(err)
	}
	defer a.stopRelays()
	if err = a.loadRoutes(); err != nil {
		t.Fatal(err)
	}
	if r := a.routes[1].Route; r.TLSPassthrough || r.UpTotal != 123 || r.DownTotal != 456 {
		t.Fatal("legacy metadata/counters changed", r)
	}
	if err = a.ensureCert("fallback", a.domain); err != nil {
		t.Fatal(err)
	}
	if err = a.ensureRouteCert(a.routes[1].Route); err != nil {
		t.Fatal(err)
	}
	v := Route{Name: "Opaque", SNI: "opaque.example.test", IP: "::1", Port: 443, TLS: true, TLSPassthrough: true, CountMode: "both", Threshold: 80}
	w := httptest.NewRecorder()
	a.createRoute(w, v)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	if err = json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if !v.TLSPassthrough {
		t.Fatal("POST lost flag")
	}
	if _, err = os.Stat(filepath.Join(dir, "certs", routeCert(v)+".pem")); !os.IsNotExist(err) {
		t.Fatal("passthrough created a termination certificate", err)
	}
	// An older API client omits the new field: it must not turn off passthrough.
	payload, _ := json.Marshal(v)
	var body map[string]any
	_ = json.Unmarshal(payload, &body)
	delete(body, "tls_passthrough")
	body["name"] = "Renamed"
	payload, _ = json.Marshal(body)
	w = httptest.NewRecorder()
	a.routeAPI(w, httptest.NewRequest("PUT", fmt.Sprintf("/admin/api/routes/%d", v.ID), bytes.NewReader(payload)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var saved int
	if err = db.QueryRow("SELECT tls_passthrough FROM routes WHERE id=?", v.ID).Scan(&saved); err != nil || saved != 1 {
		t.Fatal(saved, err)
	}
	reloaded := &App{db: db, routes: map[int64]*RouteState{}, location: time.UTC}
	if err = reloaded.loadRoutes(); err != nil || !reloaded.routes[v.ID].Route.TLSPassthrough {
		t.Fatal("reload lost flag", err)
	}
	// A failed UPDATE restores the mode just like other metadata.
	_, err = db.Exec("CREATE TRIGGER fail_route BEFORE UPDATE ON routes BEGIN SELECT RAISE(FAIL,'injected'); END")
	if err != nil {
		t.Fatal(err)
	}
	v.TLSPassthrough = false
	payload, _ = json.Marshal(v)
	w = httptest.NewRecorder()
	a.routeAPI(w, httptest.NewRequest("PUT", fmt.Sprintf("/admin/api/routes/%d", v.ID), bytes.NewReader(payload)))
	if w.Code != 500 || !a.routes[v.ID].Route.TLSPassthrough {
		t.Fatal("failed update changed mode", w.Code)
	}
	if _, err = db.Exec("DROP TRIGGER fail_route"); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	a.routeAPI(w, httptest.NewRequest("PUT", fmt.Sprintf("/admin/api/routes/%d", v.ID), bytes.NewReader(payload)))
	if w.Code != 200 || a.routes[v.ID].Route.TLSPassthrough {
		t.Fatal("explicit false ignored", w.Code, w.Body.String())
	}
}

func TestPassthroughValidation(t *testing.T) {
	r := Route{Name: "Test", SNI: "api.example.test", IP: "2001:db8::1", Port: 443, TLS: true, TLSPassthrough: true, CountMode: "both", Threshold: 80}
	if err := validateRoute(&r); err != nil {
		t.Fatal(err)
	}
	r.TLS = false
	if validateRoute(&r) == nil {
		t.Fatal("HTTP upstream accepted")
	}
	r.TLS, r.Verify, r.VerifyName = true, true, "api.example.test"
	if validateRoute(&r) == nil {
		t.Fatal("impossible proxy certificate verification accepted")
	}
}

func TestPassthroughConfig(t *testing.T) {
	a, s := trafficApp(t)
	a.data, a.domain, a.maxConnections = t.TempDir(), "main.example.test", 100000
	if err := os.MkdirAll(filepath.Join(a.data, "certs"), 0700); err != nil {
		t.Fatal(err)
	}
	s.Route.SNI, s.Route.IP, s.Route.Port = "*.example.test", "2001:db8::1", 443
	s.Route.TLS, s.Route.TLSPassthrough, s.Route.Paused = true, true, true
	s.Route.DailyLimit, s.Route.UpBPS, s.Route.DownBPS = 1000, 1234, 5678
	normal := Route{ID: 2, SNI: "api.example.test", IP: "127.0.0.1", Port: 8080}
	a.routes[2] = &RouteState{Route: normal}
	if err := a.ensureCert("fallback", a.domain); err != nil {
		t.Fatal(err)
	}
	if err := a.ensureRouteCert(normal); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"relay", "direct"} {
		a.proxyMode, a.directLimits = mode, true
		if err := a.writeConfig(); err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(filepath.Join(a.data, "haproxy.cfg"))
		cfg := string(raw)
		for _, want := range []string{"global\n  maxconn 200256\n", "  maxconn 100000\n", "  maxconn 100256\n", "bind 127.0.0.1:8443-8458 ssl"} {
			if !strings.Contains(cfg, want) {
				t.Fatal("missing", want)
			}
		}
		if strings.Contains(cfg, routeCert(s.Route)+".pem") || strings.Contains(cfg, "acl host_1 ") {
			t.Fatal("opaque route exposed to TLS termination")
		}
		if !a.needsInternalTLS() {
			t.Fatal("readiness skipped inner listeners")
		}
		if mode == "relay" {
			if strings.Contains(cfg, "server target [2001:db8::1]") || !strings.Contains(cfg, "server relay "+relaySocket(a.data, 1)) {
				t.Fatal("passthrough bypassed Go quota")
			}
			continue
		}
		for _, want := range []string{"frontend public_direct\n  mode tcp", "backend tls_bridge\n  mode tcp\n  balance leastconn", "tcp-request content reject", "tcp-request content set-bandwidth-limit upload", "tcp-request content set-bandwidth-limit download", "# fluxgate-quota " + routeBackend(s.Route, true), "server target [2001:db8::1]:443 disabled check"} {
			if !strings.Contains(cfg, want) {
				t.Fatal("missing", want)
			}
		}
		if strings.Contains(cfg, "backend relay_") || strings.Contains(cfg, "[2001:db8::1]:443 ssl") {
			t.Fatal("direct TLS was decrypted or relayed")
		}
		for i := 0; i < internalTLSShards; i++ {
			if !strings.Contains(cfg, fmt.Sprintf("server tls%d 127.0.0.1:%d", i, internalTLSFirstPort+i)) {
				t.Fatal("missing bridge shard", i)
			}
		}
		if strings.Index(cfg, "use_backend tls_bridge if sni_2") > strings.Index(cfg, "use_backend "+routeBackend(s.Route, true)+" if sni_1") {
			t.Fatal("wildcard took priority over exact SNI")
		}
	}
}

func TestPassthroughRelayPreservesTLSAndRejectsWithoutCertificate(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "opaque response") }))
	defer origin.Close()
	a, s := trafficApp(t)
	s.Route.TLS, s.Route.TLSPassthrough = true, true
	addr := origin.Listener.Addr().(*net.TCPAddr)
	s.Route.IP, s.Route.Port = addr.IP.String(), addr.Port
	client, relayClient := tcpPair(t)
	done := make(chan struct{})
	go func() { a.handleConn(s, relayClient); close(done) }()
	secure := tls.Client(client, &tls.Config{InsecureSkipVerify: true}) // fixture cert identity is checked below
	_ = secure.SetDeadline(time.Now().Add(3 * time.Second))
	if err := secure.Handshake(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secure.ConnectionState().PeerCertificates[0].Raw, origin.Certificate().Raw) {
		t.Fatal("TLS terminated by relay")
	}
	fmt.Fprint(secure, "GET / HTTP/1.1\r\nHost: opaque.example.test\r\nConnection: close\r\n\r\n")
	body, err := io.ReadAll(secure)
	if err != nil || !bytes.Contains(body, []byte("opaque response")) {
		t.Fatal(string(body), err)
	}
	secure.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not close")
	}
	s.mu.Lock()
	if s.Route.UpTotal == 0 || s.Route.DownTotal == 0 || len(s.conns) != 0 {
		t.Error("TLS bytes/lifecycle not accounted")
	}
	s.Route.Paused = true
	s.mu.Unlock()
	client, relayClient = tcpPair(t)
	go a.handleConn(s, relayClient)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if n, err := client.Read(b[:]); n != 0 || err == nil {
		t.Fatal("paused TLS returned application bytes")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("paused TLS attempted a handshake")
	}
}
