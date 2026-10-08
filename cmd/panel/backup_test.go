package main

import (
	"bytes"
	"database/sql"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBackupRestoreRoundTrip(t *testing.T) {
	for _, passthrough := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "passthrough"}[passthrough], func(t *testing.T) { testBackupRestoreRoundTrip(t, passthrough) })
	}
}
func testBackupRestoreRoundTrip(t *testing.T, passthrough bool) {
	source := t.TempDir()
	if e := os.Mkdir(filepath.Join(source, "certs"), 0700); e != nil {
		t.Fatal(e)
	}
	db, e := sql.Open("sqlite", filepath.Join(source, "panel.db"))
	if e != nil {
		t.Fatal(e)
	}
	db.SetMaxOpenConns(1)
	_, e = db.Exec(`CREATE TABLE routes(id INTEGER PRIMARY KEY,name TEXT,sni TEXT,ip TEXT,port INTEGER,tls INTEGER,verify INTEGER,verify_name TEXT,paused INTEGER,daily_limit INTEGER,monthly_limit INTEGER,count_mode TEXT,down_bps INTEGER,up_bps INTEGER,threshold INTEGER,created_at INTEGER,up_total INTEGER,down_total INTEGER,monitor INTEGER);CREATE TABLE periods(route_id INTEGER,kind TEXT,key TEXT,used INTEGER,extra INTEGER,threshold_sent INTEGER,exhausted_sent INTEGER);CREATE TABLE samples(route_id INTEGER,ts INTEGER,up INTEGER,down INTEGER);CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);INSERT INTO routes VALUES(1,'Test','test.example.com','127.0.0.1',8080,0,0,'',0,0,0,'both',0,0,80,1,0,0,0);`)
	if e != nil {
		t.Fatal(e)
	}
	a := &App{db: db, data: source, domain: "example.com", location: time.UTC, master: []byte("original master key with enough length"), routes: map[int64]*RouteState{}, tg: TelegramSettings{BotToken: "telegram-secret"}}
	if passthrough {
		if e = migrateRoutePassthrough(db); e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec("UPDATE routes SET tls=1,tls_passthrough=1"); e != nil {
			t.Fatal(e)
		}
	}
	if e = a.initFinance(); e != nil {
		t.Fatal(e)
	}
	if e = a.initRequestStats(); e != nil {
		t.Fatal(e)
	}
	if e = a.initDirectMeter(); e != nil {
		t.Fatal(e)
	}
	if e = a.setSetting("proxy_mode", "direct"); e != nil {
		t.Fatal(e)
	}
	if e = a.setSetting("direct_limits", "true"); e != nil {
		t.Fatal(e)
	}
	routeIdentity := Route{ID: 1}
	if e = a.ensureMeterID(&routeIdentity); e != nil {
		t.Fatal(e)
	}
	if e = a.ensureCert("fallback", a.domain); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("INSERT INTO rentals(route_id,client,contact,paid_until,remind,last_reminder) VALUES(1,'Alice','@alice','2026-10-01',1,'')"); e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	a.backupAPI(w, httptest.NewRequest("GET", "/admin/api/backup", nil))
	if w.Code != 200 {
		t.Fatalf("backup: %d %s", w.Code, w.Body.String())
	}
	if w.Body.Len() < 1000 {
		t.Fatal("backup too small")
	}
	dest := t.TempDir()
	other := &App{data: dest, master: []byte("different master key with enough length")}
	name, e := other.stageRestore(bytes.NewReader(w.Body.Bytes()))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dest, "restore.pending"), []byte(name), 0600); e != nil {
		t.Fatal(e)
	}
	if e = applyPendingRestore(dest); e != nil {
		t.Fatal(e)
	}
	restored, e := sql.Open("sqlite", filepath.Join(dest, "panel.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	other.db = restored
	var flag int
	if e = restored.QueryRow("SELECT tls_passthrough FROM routes WHERE id=1").Scan(&flag); e != nil || flag != boolInt(passthrough) {
		t.Fatal("restored transport", flag, e)
	}
	if got := other.getSetting("direct_limits", ""); got != "true" {
		t.Fatalf("direct limits lost: %q", got)
	}
	if got := other.getSetting("proxy_mode", ""); got != "direct" {
		t.Fatalf("proxy mode lost: %q", got)
	}
	restoredIdentity := Route{ID: 1}
	if e = other.ensureMeterID(&restoredIdentity); e != nil || restoredIdentity.MeterID != routeIdentity.MeterID {
		t.Fatal("route identity lost", e)
	}
	if got := other.getSetting("domain", ""); got != "example.com" {
		t.Fatalf("domain: %s", got)
	}
	if got := other.decrypt(other.getSetting("tg_token", "")); got != "telegram-secret" {
		t.Fatalf("telegram token: %q", got)
	}
	if got := other.rental(1); got.Client != "Alice" || got.PaidUntil != "2026-10-01" {
		t.Fatalf("rental: %+v", got)
	}
	if _, e = os.Stat(filepath.Join(dest, "certs", "fallback.pem")); e != nil {
		t.Fatal(e)
	}
	db.Close()
}
func TestRestoreRejectsInvalidArchive(t *testing.T) {
	a := &App{data: t.TempDir(), master: []byte("different master key with enough length")}
	if _, e := a.stageRestore(bytes.NewReader([]byte("not a zip"))); e == nil {
		t.Fatal("invalid archive accepted")
	}
	entries, e := os.ReadDir(a.data)
	if e != nil {
		t.Fatal(e)
	}
	if len(entries) != 0 {
		t.Fatalf("staging left behind: %+v", entries)
	}
}
