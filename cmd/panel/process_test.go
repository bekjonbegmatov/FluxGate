package main

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestReportPoolReadOnlyAndIndependent(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA journal_mode=WAL; CREATE TABLE test(value); INSERT INTO test VALUES(1)"); err != nil {
		t.Fatal(err)
	}
	reader, err := openReportDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE test SET value=2"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var value int
	if err := reader.QueryRowContext(ctx, "SELECT value FROM test").Scan(&value); err != nil || value != 1 {
		t.Fatalf("WAL reader blocked: %d %v", value, err)
	}
	// Force four separate connections: PRAGMAs must apply to every one.
	var conns []*sql.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for i := 0; i < 4; i++ {
		c, err := reader.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		var readonly int
		if err := c.QueryRowContext(ctx, "PRAGMA query_only").Scan(&readonly); err != nil || readonly != 1 {
			t.Fatal("report connection is writable", err)
		}
		if _, err := c.ExecContext(ctx, "DELETE FROM test"); err == nil {
			t.Fatal("report process modified database")
		}
	}
}

func TestAgentAllowsOnlyOneWriter(t *testing.T) {
	dir := t.TempDir()
	first, err := lockAgent(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := lockAgent(dir); err == nil {
		second.Close()
		t.Fatal("second writer acquired lock")
	}
	first.Close()
	next, err := lockAgent(dir)
	if err != nil {
		t.Fatal("restart could not acquire released lock", err)
	}
	next.Close()
}

func TestWebRoutingAndPrivateLease(t *testing.T) {
	for _, path := range []string{"history/all", "request-history/1", "export/traffic.csv"} {
		if !localWebRequest(httptest.NewRequest("GET", "/admin/api/"+path, nil), "/admin/") {
			t.Fatal(path)
		}
		if localWebRequest(httptest.NewRequest("POST", "/admin/api/"+path, nil), "/admin/") {
			t.Fatal("write routed to read-only process")
		}
	}
	a := &App{data: t.TempDir(), secretPath: "admin"}
	h := webHandler(a)
	for path, want := range map[string]int{"/internal/lease": 404, "/admin/api/history/all": 401, "/admin/api/routes": 503} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != want {
			t.Fatalf("%s: got %d want %d", path, w.Code, want)
		}
	}
}

func TestDirectRuntimeErrorsNotAcknowledged(t *testing.T) {
	var commands []string
	command := func(s string) ([]byte, error) { commands = append(commands, s); return nil, nil }
	if err := enforceDirectBackend(command, "direct_1_token", true); err != nil || len(commands) != 2 {
		t.Fatal(commands, err)
	}
	if err := enforceDirectBackend(func(string) ([]byte, error) { return []byte("No such server"), nil }, "direct_1_token", false); err == nil {
		t.Fatal("rejected command marked successful")
	}
}

func TestStoppedDirectBackendTerminatesItsStreams(t *testing.T) {
	var commands []string
	command := func(s string) ([]byte, error) {
		commands = append(commands, s)
		switch {
		case strings.HasPrefix(s, "set server "), strings.HasPrefix(s, "shutdown sessions server "):
			return []byte("Proxy is disabled.\n"), nil
		case s == "show sess backend direct_1_token":
			return []byte("0x1234: proto=tcpv4 fe=public_direct be=direct_1_token srv=target\n0x5678: proto=tcpv4 be=direct_1_token srv=target\n"), nil
		case s == "shutdown session 0x1234":
			return nil, nil
		case s == "shutdown session 0x5678":
			return []byte("No such session (use 'show sess').\n"), nil
		default:
			t.Fatalf("unexpected command %q", s)
			return nil, nil
		}
	}
	if err := enforceDirectBackend(command, "direct_1_token", true); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(commands, []string{"set server direct_1_token/target state maint", "shutdown sessions server direct_1_token/target", "show sess backend direct_1_token", "shutdown session 0x1234", "shutdown session 0x5678"}) {
		t.Fatal(commands)
	}
	// Disabled is not an acknowledgement when trying to reopen a route.
	if err := enforceDirectBackend(command, "direct_1_token", false); err == nil {
		t.Fatal("disabled backend marked ready")
	}
	for _, raw := range []string{"Unknown command\n", "0x1234: be=other\n", "0x1234;quit: be=direct_1_token\n"} {
		if _, err := stoppedStreamIDs([]byte(raw), "direct_1_token"); err == nil {
			t.Fatalf("accepted invalid stream list %q", raw)
		}
	}
}
