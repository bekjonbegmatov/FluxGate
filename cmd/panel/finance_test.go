package main

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestManualRentalAndPayment(t *testing.T) {
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
	w := call("PUT", "/admin/api/finance/1", `{"client":"Alice","contact":"@alice","debt_cents":3000,"paid_until":"2026-10-10","remind":true,"last_reminder":""}`)
	if w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	w = call("POST", "/admin/api/finance/1/payments", `{"amount_cents":1000,"note":"test","paid_until":"2026-11-10"}`)
	if w.Code != 200 {
		t.Fatalf("payment: %d %s", w.Code, w.Body.String())
	}
	var rental Rental
	if err := json.Unmarshal(w.Body.Bytes(), &rental); err != nil {
		t.Fatal(err)
	}
	if rental.DebtCents != 2000 || rental.PaidUntil != "2026-11-10" {
		t.Fatalf("rental: %+v", rental)
	}
	w = call("GET", "/admin/api/finance/1/payments", "")
	var payments []Payment
	if err := json.Unmarshal(w.Body.Bytes(), &payments); err != nil {
		t.Fatal(err)
	}
	if len(payments) != 1 || payments[0].DebtBefore != 3000 || payments[0].DebtAfter != 2000 {
		t.Fatalf("payments: %+v", payments)
	}
}
