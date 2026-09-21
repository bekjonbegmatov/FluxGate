package main

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRentalExtensionAndPayment(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	a := &App{db: db, secretPath: "admin", routes: map[int64]*RouteState{1: {Route: Route{ID: 1, Name: "Test", SNI: "test.example.com"}}}, location: time.UTC}
	if err := a.initFinance(); err != nil {
		t.Fatal(err)
	}
	call := func(method, path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		a.financeAPI(w, httptest.NewRequest(method, path, strings.NewReader(body)))
		return w
	}
	w := call("PUT", "/admin/api/finance/1", `{"client":"Alice","contact":"@alice","paid_until":"2026-10-10","remind":true,"last_reminder":""}`)
	if w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	w = call("POST", "/admin/api/finance/1/payments", `{"amount_cents":1000,"note":"10 days","paid_until":"2026-10-10"}`)
	if w.Code != 200 {
		t.Fatalf("payment: %d %s", w.Code, w.Body.String())
	}
	w = call("POST", "/admin/api/finance/1/payments", `{"amount_cents":700,"note":"7 days","paid_until":"2026-10-17"}`)
	if w.Code != 200 {
		t.Fatalf("extension: %d %s", w.Code, w.Body.String())
	}
	var rental Rental
	if err := json.Unmarshal(w.Body.Bytes(), &rental); err != nil {
		t.Fatal(err)
	}
	if rental.TotalPaidCents != 1700 || rental.PaidUntil != "2026-10-17" {
		t.Fatalf("rental: %+v", rental)
	}
	w = call("GET", "/admin/api/finance/1/payments", "")
	var payments []Payment
	if err := json.Unmarshal(w.Body.Bytes(), &payments); err != nil {
		t.Fatal(err)
	}
	if len(payments) != 2 || payments[0].AmountCents != 700 || payments[0].PaidUntil != "2026-10-17" {
		t.Fatalf("payments: %+v", payments)
	}
	if w = call("POST", "/admin/api/finance/1/payments", `{"amount_cents":100,"paid_until":""}`); w.Code != 400 {
		t.Fatalf("date required: %d", w.Code)
	}
}
func TestLegacyFinanceMigration(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE rentals(route_id INTEGER PRIMARY KEY, client TEXT NOT NULL, contact TEXT NOT NULL, debt_cents INTEGER NOT NULL, paid_until TEXT NOT NULL, remind INTEGER NOT NULL, last_reminder TEXT NOT NULL);
 CREATE TABLE payments(id INTEGER PRIMARY KEY, route_id INTEGER NOT NULL, amount_cents INTEGER NOT NULL, note TEXT NOT NULL, created_at INTEGER NOT NULL, debt_before INTEGER NOT NULL, debt_after INTEGER NOT NULL, paid_until TEXT NOT NULL);
 INSERT INTO rentals VALUES(1,'Alice','@alice',500,'2026-10-10',1,'');
 INSERT INTO payments VALUES(1,1,1000,'first',1,500,0,'2026-10-10');`)
	if err != nil {
		t.Fatal(err)
	}
	a := &App{db: db}
	if err := a.initFinance(); err != nil {
		t.Fatal(err)
	}
	r := a.rental(1)
	if r.Client != "Alice" || r.TotalPaidCents != 1000 || r.PaidUntil != "2026-10-10" {
		t.Fatalf("migration: %+v", r)
	}
	var removed int
	rows, err := db.Query("PRAGMA table_info(rentals)")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var cid, nn, pk int
		var name, typ string
		var def sql.NullString
		_ = rows.Scan(&cid, &name, &typ, &nn, &def, &pk)
		if name == "debt_cents" {
			removed++
		}
	}
	rows.Close()
	if removed != 0 {
		t.Fatal("legacy debt column remains")
	}
}
