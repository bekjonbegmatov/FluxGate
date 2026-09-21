package main

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEditMainDomain(t *testing.T) {
	db, e := sql.Open("sqlite", ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, e = db.Exec("CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT NOT NULL)"); e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	if e = os.MkdirAll(filepath.Join(dir, "certs"), 0700); e != nil {
		t.Fatal(e)
	}
	a := &App{db: db, data: dir, domain: "old.example.com", routes: map[int64]*RouteState{}, location: time.UTC, master: []byte("test master key with enough characters"), tg: TelegramSettings{APIURL: "https://api.telegram.org"}}
	if e = a.ensureCert("fallback", a.domain); e != nil {
		t.Fatal(e)
	}
	body := `{"domain":"new.example.com","fallback_html":"<h1>ok</h1>","tg_api":"https://api.telegram.org","tg_chat":"","tg_token":""}`
	w := httptest.NewRecorder()
	a.settingsAPI(w, httptest.NewRequest("PUT", "/admin/api/settings", strings.NewReader(body)))
	if w.Code != 200 {
		t.Fatalf("settings: %d %s", w.Code, w.Body.String())
	}
	if a.domain != "new.example.com" || a.getSetting("domain", "") != "new.example.com" {
		t.Fatalf("domain not saved: %s", a.domain)
	}
	certBytes, e := os.ReadFile(filepath.Join(dir, "certs", "fallback.pem"))
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(certBytes)
	if block == nil {
		t.Fatal("no certificate")
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "new.example.com" {
		t.Fatalf("certificate: %+v", cert.DNSNames)
	}
}
