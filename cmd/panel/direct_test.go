package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDirectCollectionContinuesWhileWriterBlocked(t *testing.T) {
	a, s, backend := directApp(t)
	now := time.Now()
	a.observeDirect("worker", map[string]directCounter{backend: {down: 100}}, now)
	conn, err := a.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan error, 1)
	go func() { done <- a.flushTraffic(now) }()
	deadline := time.Now().Add(2 * time.Second)
	for a.db.Stats().WaitCount == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if a.db.Stats().WaitCount == 0 {
		t.Fatal("writer did not reach DB")
	}
	observed := make(chan struct{})
	go func() {
		a.observeDirect("worker", map[string]directCounter{backend: {down: 250}}, now)
		close(observed)
	}()
	select {
	case <-observed:
	case <-time.After(time.Second):
		t.Fatal("SQL blocked direct collection")
	}
	conn.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if s.pendingDown != 150 {
		t.Fatalf("lost concurrent delta: %d", s.pendingDown)
	}
	var checkpoint int64
	if err := a.db.QueryRow("SELECT down FROM direct_checkpoints").Scan(&checkpoint); err != nil || checkpoint != 100 {
		t.Fatalf("checkpoint ahead of totals: %d %v", checkpoint, err)
	}
	if !a.directWorkerPending("worker") {
		t.Fatal("prematurely released draining worker")
	}
	if err := a.flushTraffic(now); err != nil {
		t.Fatal(err)
	}
	if a.directWorkerPending("worker") {
		t.Fatal("checkpoint not committed")
	}
	if err := a.db.QueryRow("SELECT down FROM direct_checkpoints").Scan(&checkpoint); err != nil || checkpoint != 250 {
		t.Fatalf("checkpoint=%d %v", checkpoint, err)
	}
	if err := a.db.QueryRow("SELECT SUM(down) FROM samples").Scan(&checkpoint); err != nil || checkpoint != 250 {
		t.Fatalf("samples=%d %v", checkpoint, err)
	}
}

func TestDirectObservationDuringDeletionRollback(t *testing.T) {
	a, s, backend := directApp(t)
	a.observeDirect("worker", map[string]directCounter{backend: {down: 100}}, time.Now())
	delete(a.routes, 1)
	a.deleting = map[int64]*RouteState{1: s}
	a.observeDirect("worker", map[string]directCounter{backend: {down: 250}}, time.Now())
	a.routes[1] = s
	delete(a.deleting, 1)
	if err := a.flushTraffic(time.Now()); err != nil {
		t.Fatal(err)
	}
	if s.Route.DownTotal != 250 {
		t.Fatal("rollback lost direct traffic", s.Route.DownTotal)
	}
}

func TestDirectQuotaOptInAndTopup(t *testing.T) {
	a, s, backend := directApp(t)
	s.Route.DailyLimit = 100
	a.observeDirect("worker", map[string]directCounter{backend: {down: 101}}, time.Now())
	if !a.allowedDirectBackends()[backend] {
		t.Fatal("legacy direct unexpectedly limited")
	}
	a.directLimits = true
	if a.allowedDirectBackends()[backend] {
		t.Fatal("daily quota bypassed")
	}
	s.Daily.Extra = 100
	if !a.allowedDirectBackends()[backend] {
		t.Fatal("topup did not reopen route")
	}
	s.Route.MonthlyLimit = 50
	if a.allowedDirectBackends()[backend] {
		t.Fatal("monthly quota bypassed")
	}
	s.Monthly.Extra = 100
	if !a.allowedDirectBackends()[backend] {
		t.Fatal("monthly topup ignored")
	}
	s.Route.Paused = true
	if a.allowedDirectBackends()[backend] {
		t.Fatal("paused route reopened")
	}
}

func directApp(t *testing.T) (*App, *RouteState, string) {
	t.Helper()
	a, s := trafficApp(t)
	if err := a.initDirectMeter(); err != nil {
		t.Fatal(err)
	}
	if err := a.ensureMeterID(&s.Route); err != nil {
		t.Fatal(err)
	}
	a.proxyMode = "direct"
	return a, s, routeBackend(s.Route, true)
}

func TestDirectHAProxyVersion(t *testing.T) {
	for output, want := range map[string]bool{
		"HAProxy version 3.2.25-abcdef 2026/09/22\n": true,
		"HAProxy version 3.3.0-dev1":                 true,
		"HAProxy version 4.0.1":                      true,
		"HAProxy version 3.1.12":                     false,
		"HAProxy version 2.8.15-ubuntu":              false,
		"HAProxy version unknown":                    false,
		"":                                           false,
	} {
		if got := supportsDirectVersion(output); got != want {
			t.Errorf("%q: got %v want %v", output, got, want)
		}
	}
}

func TestDirectCheckpointsAtomicAndRestart(t *testing.T) {
	a, s, backend := directApp(t)
	now := time.Now()
	a.observeDirect("worker-a", map[string]directCounter{backend: {up: 100, down: 900}}, now)
	if s.Route.DownTotal != 900 || s.Daily.Used != 1000 {
		t.Fatalf("initial: %+v", s.Route)
	}
	if _, err := a.db.Exec("CREATE TRIGGER fail_direct BEFORE INSERT ON direct_checkpoints BEGIN SELECT RAISE(FAIL,'injected'); END"); err != nil {
		t.Fatal(err)
	}
	if err := a.flushTraffic(now); err == nil {
		t.Fatal("expected transaction failure")
	}
	var down int64
	if err := a.db.QueryRow("SELECT down_total FROM routes WHERE id=1").Scan(&down); err != nil || down != 0 {
		t.Fatalf("partial commit: %d %v", down, err)
	}
	a.observeDirect("worker-a", map[string]directCounter{backend: {up: 110, down: 990}}, now)
	if _, err := a.db.Exec("DROP TRIGGER fail_direct"); err != nil {
		t.Fatal(err)
	}
	if err := a.flushTraffic(now); err != nil {
		t.Fatal(err)
	}
	if s.pendingDown != 0 || len(a.direct.pending) != 0 {
		t.Fatal("pending deltas not cleared")
	}
	// Reload just the persisted baseline, as a panel process restart does.
	if err := a.initDirectMeter(); err != nil {
		t.Fatal(err)
	}
	a.observeDirect("worker-a", map[string]directCounter{backend: {up: 120, down: 1080}}, now)
	a.observeDirect("worker-a", map[string]directCounter{backend: {up: 120, down: 1080}}, now)
	// A new worker starts at zero, even when its counters exceed the old ones.
	a.observeDirect("worker-b", map[string]directCounter{backend: {up: 1000, down: 2000}}, now)
	if err := a.flushTraffic(now); err != nil {
		t.Fatal(err)
	}
	if s.Route.UpTotal != 1120 || s.Route.DownTotal != 3080 {
		t.Fatalf("double/missing count: %+v", s.Route)
	}
	if err := a.db.QueryRow("SELECT SUM(down) FROM samples").Scan(&down); err != nil || down != 3080 {
		t.Fatalf("samples: %d %v", down, err)
	}
}

func TestDirectNoDoubleCountWithRelayOrReusedRouteID(t *testing.T) {
	a, s, backend := directApp(t)
	now := time.Now()
	a.observeDirect("old", map[string]directCounter{backend: {up: 10, down: 20}}, now)
	oldID := s.Route.MeterID
	if _, err := a.db.Exec("DELETE FROM route_meter_ids WHERE route_id=1"); err != nil {
		t.Fatal(err)
	}
	if err := a.ensureMeterID(&s.Route); err != nil {
		t.Fatal(err)
	}
	if s.Route.MeterID == oldID {
		t.Fatal("reused route identity")
	}
	a.proxyMode = "relay" // old direct worker must STILL be accounted
	a.observeDirect("old", map[string]directCounter{backend: {up: 1000, down: 2000}}, now)
	if s.Route.DownTotal != 20 {
		t.Fatal("deleted route traffic leaked into new route")
	}
	a.observeDirect("new", map[string]directCounter{routeBackend(s.Route, true): {up: 30, down: 40}}, now)
	if s.Route.DownTotal != 60 {
		t.Fatal("old direct worker lost on switch to relay")
	}
}

func TestDirectCountModesAndIdempotentMigration(t *testing.T) {
	for _, mode := range []string{"up", "down", "both"} {
		t.Run(mode, func(t *testing.T) {
			a, s, backend := directApp(t)
			s.Route.CountMode = mode
			id := s.Route.MeterID
			if err := a.initDirectMeter(); err != nil {
				t.Fatal(err)
			}
			if err := a.ensureMeterID(&s.Route); err != nil || id != s.Route.MeterID {
				t.Fatal("migration changed identity", err)
			}
			a.observeDirect("w", map[string]directCounter{backend: {up: 17, down: 43}}, time.Now())
			want := int64(60)
			if mode == "up" {
				want = 17
			}
			if mode == "down" {
				want = 43
			}
			if s.Daily.Used != want || s.Monthly.Used != want {
				t.Fatal("count mode not respected")
			}
		})
	}
}

func TestParseDirectCounters(t *testing.T) {
	name := "direct_7_" + strings.Repeat("a", 32)
	raw := []byte("# pxname,svname,bin,bout\ntarget_7,BACKEND,400,500\n" + name + ",target,40,50\n" + name + ",BACKEND,4000000000000,5000000000000\n")
	got, err := parseDirectStats(raw)
	if err != nil || len(got) != 1 || got[name].down != 5000000000000 {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"bad", "# pxname,svname,bin,bout\ndirect_7_BAD,BACKEND,1,2\n", "# pxname,svname,bin,bout\n" + name + ",BACKEND,-1,2\n"} {
		if _, err := parseDirectStats([]byte(bad)); err == nil {
			t.Fatal("invalid counters accepted")
		}
	}
}

func TestDirectConfigHasNoRelayAndPreservesPause(t *testing.T) {
	a, s, _ := directApp(t)
	a.data = t.TempDir()
	a.domain = "main.example.test"
	s.Route.SNI = "api.example.test"
	s.Route.IP = "127.0.0.1"
	s.Route.Port = 8080
	s.Route.Paused = true
	if err := a.writeConfig(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(a.data, "haproxy.cfg"))
	if err != nil {
		t.Fatal(err)
	}
	config := string(raw)
	for _, v := range []string{"frontend public_direct", "bind :443 ssl", "option contstats", "http-request deny deny_status 503", "use_backend " + routeBackend(s.Route, true), "server target 127.0.0.1:8080"} {
		if !strings.Contains(config, v) {
			t.Fatalf("missing %s", v)
		}
	}
	for _, v := range []string{"frontend internal_tls", "frontend public_sni", "backend relay_", "127.0.0.1:8443"} {
		if strings.Contains(config, v) {
			t.Fatalf("unexpected relay hop %s", v)
		}
	}
}

func fakeMeterSocket(t *testing.T, dir string) {
	t.Helper()
	l, err := net.Listen("unix", filepath.Join(dir, "haproxy.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				scanner := bufio.NewScanner(c)
				for scanner.Scan() {
					switch scanner.Text() {
					case "prompt":
						fmt.Fprint(c, "\n> ")
					case "show info":
						fmt.Fprint(c, "Pid: 42\nStart_time_sec: 1700000000\nnode: test\nStopping: 0\nCurrConns: 0\n\n> ")
					case "show stat":
						fmt.Fprint(c, "# pxname,svname,bin,bout\n\n> ")
					default:
						fmt.Fprint(c, "\n> ")
					}
				}
			}()
		}
	}()
}

func TestProxyModeSettingsValidationPersistenceAndRollback(t *testing.T) {
	a, s, _ := directApp(t)
	dir, err := os.MkdirTemp("", "fg-mode-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	a.data = dir
	a.domain = "main.example.test"
	a.proxyMode = ""
	s.Route.SNI = "api.example.test"
	s.Route.IP = "127.0.0.1"
	s.Route.Port = 8080
	if _, err := a.db.Exec("CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	fakeMeterSocket(t, dir)
	put := func(mode string, limits ...bool) int {
		w := httptest.NewRecorder()
		field := ""
		if len(limits) > 0 {
			field = fmt.Sprintf(`,"direct_limits":%t`, limits[0])
		}
		a.settingsAPI(w, httptest.NewRequest("PUT", "/admin/api/settings", strings.NewReader(`{"proxy_mode":"`+mode+`","tg_api":"https://api.telegram.org","fallback_html":"ok"`+field+`}`)))
		return w.Code
	}
	if got := put("invalid"); got != 400 {
		t.Fatal(got)
	}
	if got := put("direct", true); got != 200 {
		t.Fatal(got)
	}
	if a.getSetting("proxy_mode", "") != "direct" || !a.directMode() || a.getSetting("direct_limits", "") != "true" || !a.directLimits {
		t.Fatal("mode not persisted")
	}
	w := httptest.NewRecorder()
	a.settingsAPI(w, httptest.NewRequest("PUT", "/admin/api/settings", strings.NewReader(`{"tg_api":"https://api.telegram.org"}`)))
	if w.Code != 200 || !a.directMode() || !a.directLimits {
		t.Fatal("old client reset mode")
	}
	if _, err := a.db.Exec("CREATE TRIGGER reject_settings BEFORE INSERT ON settings BEGIN SELECT RAISE(FAIL,'injected'); END"); err != nil {
		t.Fatal(err)
	}
	if got := put("relay", false); got != 500 {
		t.Fatal(got)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "haproxy.cfg"))
	if !a.directMode() || !a.directLimits || !strings.Contains(string(raw), "frontend public_direct") {
		t.Fatal("failed update did not restore active config")
	}
}

func TestRestartRequiresConfirmationAndSchedulesOnce(t *testing.T) {
	a, _, _ := directApp(t)
	a.data = t.TempDir()
	done := make(chan struct{}, 1)
	a.restartService = func() { done <- struct{}{} }
	request := func(method, body string) int {
		w := httptest.NewRecorder()
		a.restartAPI(w, httptest.NewRequest(method, "/admin/api/restart", strings.NewReader(body)))
		return w.Code
	}
	if request("GET", "") != 405 || request("POST", `{"confirm":false}`) != 400 {
		t.Fatal("unconfirmed restart accepted")
	}
	if request("POST", `{"confirm":true}`) != 202 || request("POST", `{"confirm":true}`) != 409 {
		t.Fatal("restart not idempotent")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("restart not scheduled")
	}
}

func TestRestartRefusesFailedPersistence(t *testing.T) {
	a, s, backend := directApp(t)
	a.data = t.TempDir()
	a.observeDirect("worker", map[string]directCounter{backend: {up: 30, down: 50}}, time.Now())
	if _, err := a.db.Exec("CREATE TRIGGER fail_restart BEFORE INSERT ON samples BEGIN SELECT RAISE(FAIL,'injected'); END"); err != nil {
		t.Fatal(err)
	}
	a.restartService = func() { t.Error("restarted without saved traffic") }
	w := httptest.NewRecorder()
	a.restartAPI(w, httptest.NewRequest("POST", "/admin/api/restart", strings.NewReader(`{"confirm":true}`)))
	if w.Code != 503 || a.restartRequested.Load() || s.pendingDown != 50 {
		t.Fatalf("unsafe restart: %d %+v", w.Code, s)
	}
}

func TestDirectRateWindowAndIdleDecay(t *testing.T) {
	a, s, _ := directApp(t)
	start := time.Now()
	s.rateAt = start
	for i := 1; i <= 10; i++ {
		if i == 5 || i == 10 {
			s.Route.DownTotal += 5000
		}
		a.sampleRates(start.Add(time.Duration(i) * time.Second))
	}
	if s.lastDown != 1000 {
		t.Fatalf("not smoothed over window: %d", s.lastDown)
	}
	for i := 11; i <= 20; i++ {
		a.sampleRates(start.Add(time.Duration(i) * time.Second))
	}
	if s.lastDown != 0 || len(s.rateHistory) > 12 {
		t.Fatalf("idle decay/history bound: %d %d", s.lastDown, len(s.rateHistory))
	}
}
