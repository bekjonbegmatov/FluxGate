package main

import (
	"database/sql"
	"encoding/csv"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCSVExportsAndFormulaEscaping(t *testing.T) {
	db, e := sql.Open("sqlite", ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	_, e = db.Exec(`CREATE TABLE routes(id INTEGER PRIMARY KEY,name TEXT,sni TEXT);CREATE TABLE rentals(route_id INTEGER PRIMARY KEY,client TEXT,contact TEXT);CREATE TABLE payments(id INTEGER PRIMARY KEY,route_id INTEGER,amount_cents INTEGER,note TEXT,created_at INTEGER,paid_until TEXT);CREATE TABLE samples(route_id INTEGER,ts INTEGER,up INTEGER,down INTEGER);`)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC).Unix()
	_, e = db.Exec("INSERT INTO routes VALUES(1,'=unsafe','a.example.com');INSERT INTO rentals VALUES(1,'Alice','@alice');INSERT INTO payments VALUES(1,1,1000,'+formula',?, '2026-10-01');INSERT INTO samples VALUES(1,?,123,456)", now, now)
	if e != nil {
		t.Fatal(e)
	}
	a := &App{db: db, location: time.UTC}
	w := httptest.NewRecorder()
	a.exportPaymentsAPI(w, httptest.NewRequest("GET", "/api/export/payments.csv?from=2026-09-21&to=2026-09-21", nil))
	if w.Code != 200 {
		t.Fatalf("payments: %d %s", w.Code, w.Body.String())
	}
	records, e := csv.NewReader(strings.NewReader(strings.TrimPrefix(w.Body.String(), "\ufeff"))).ReadAll()
	if e != nil {
		t.Fatal(e)
	}
	if len(records) != 2 || records[1][2] != "'=unsafe" || records[1][8] != "'+formula" || records[1][6] != "10.00" {
		t.Fatalf("payment csv: %+v", records)
	}
	w = httptest.NewRecorder()
	a.exportTrafficAPI(w, httptest.NewRequest("GET", "/api/export/traffic.csv?from=2026-09-21&to=2026-09-21&period=hour", nil))
	if w.Code != 200 {
		t.Fatalf("traffic: %d %s", w.Code, w.Body.String())
	}
	records, e = csv.NewReader(strings.NewReader(strings.TrimPrefix(w.Body.String(), "\ufeff"))).ReadAll()
	if e != nil {
		t.Fatal(e)
	}
	if len(records) != 2 || records[1][4] != "123" || records[1][5] != "456" || records[1][6] != "579" {
		t.Fatalf("traffic csv: %+v", records)
	}
}
