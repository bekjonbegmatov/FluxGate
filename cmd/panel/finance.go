package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Rental struct {
	RouteID      int64  `json:"route_id"`
	Client       string `json:"client"`
	Contact      string `json:"contact"`
	DebtCents    int64  `json:"debt_cents"`
	PaidUntil    string `json:"paid_until"`
	Remind       bool   `json:"remind"`
	LastReminder string `json:"last_reminder"`
}
type Payment struct {
	ID          int64  `json:"id"`
	RouteID     int64  `json:"route_id"`
	AmountCents int64  `json:"amount_cents"`
	Note        string `json:"note"`
	CreatedAt   int64  `json:"created_at"`
	DebtBefore  int64  `json:"debt_before"`
	DebtAfter   int64  `json:"debt_after"`
	PaidUntil   string `json:"paid_until"`
}

func (a *App) initFinance() error {
	_, err := a.db.Exec(`CREATE TABLE IF NOT EXISTS rentals(route_id INTEGER PRIMARY KEY, client TEXT NOT NULL DEFAULT '', contact TEXT NOT NULL DEFAULT '', debt_cents INTEGER NOT NULL DEFAULT 0, paid_until TEXT NOT NULL DEFAULT '', remind INTEGER NOT NULL DEFAULT 0, last_reminder TEXT NOT NULL DEFAULT '');
 CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY, route_id INTEGER NOT NULL, amount_cents INTEGER NOT NULL, note TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, debt_before INTEGER NOT NULL, debt_after INTEGER NOT NULL, paid_until TEXT NOT NULL DEFAULT '');`)
	return err
}
func validDate(v string) bool {
	if v == "" {
		return true
	}
	t, e := time.Parse("2006-01-02", v)
	return e == nil && t.Format("2006-01-02") == v
}
func (a *App) rental(id int64) Rental {
	v := Rental{RouteID: id}
	var remind int
	_ = a.db.QueryRow("SELECT client,contact,debt_cents,paid_until,remind,last_reminder FROM rentals WHERE route_id=?", id).Scan(&v.Client, &v.Contact, &v.DebtCents, &v.PaidUntil, &remind, &v.LastReminder)
	v.Remind = remind != 0
	return v
}
func (a *App) financeAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/"+a.secretPath+"/api/finance"), "/")
	if path == "" {
		if r.Method != "GET" {
			fail(w, 405, "method")
			return
		}
		rows, e := a.db.Query("SELECT route_id FROM rentals ORDER BY route_id")
		if e != nil {
			fail(w, 500, e.Error())
			return
		}
		ids := []int64{}
		for rows.Next() {
			var id int64
			if rows.Scan(&id) == nil {
				ids = append(ids, id)
			}
		}
		rows.Close()
		out := []Rental{}
		for _, id := range ids {
			out = append(out, a.rental(id))
		}
		writeJSON(w, 200, out)
		return
	}
	parts := strings.Split(path, "/")
	id, e := strconv.ParseInt(parts[0], 10, 64)
	if e != nil {
		fail(w, 400, "id")
		return
	}
	a.mu.RLock()
	s := a.routes[id]
	a.mu.RUnlock()
	if s == nil {
		fail(w, 404, "server not found")
		return
	}
	if len(parts) == 2 && parts[1] == "payments" {
		if r.Method == "GET" {
			rows, e := a.db.Query("SELECT id,route_id,amount_cents,note,created_at,debt_before,debt_after,paid_until FROM payments WHERE route_id=? ORDER BY id DESC LIMIT 500", id)
			if e != nil {
				fail(w, 500, e.Error())
				return
			}
			defer rows.Close()
			out := []Payment{}
			for rows.Next() {
				var p Payment
				if rows.Scan(&p.ID, &p.RouteID, &p.AmountCents, &p.Note, &p.CreatedAt, &p.DebtBefore, &p.DebtAfter, &p.PaidUntil) == nil {
					out = append(out, p)
				}
			}
			writeJSON(w, 200, out)
			return
		}
		if r.Method != "POST" {
			fail(w, 405, "method")
			return
		}
		var req struct {
			AmountCents int64  `json:"amount_cents"`
			Note        string `json:"note"`
			PaidUntil   string `json:"paid_until"`
			DebtAfter   *int64 `json:"debt_after"`
		}
		if readJSON(r, &req) != nil || req.AmountCents <= 0 || req.AmountCents > 1000000000 || len(req.Note) > 300 || !validDate(req.PaidUntil) || (req.DebtAfter != nil && (*req.DebtAfter < 0 || *req.DebtAfter > 1000000000)) {
			fail(w, 400, "invalid payment")
			return
		}
		a.financeMu.Lock()
		defer a.financeMu.Unlock()
		before := a.rental(id)
		after := before.DebtCents - req.AmountCents
		if after < 0 {
			after = 0
		}
		if req.DebtAfter != nil {
			after = *req.DebtAfter
		}
		date := before.PaidUntil
		if req.PaidUntil != "" {
			date = req.PaidUntil
		}
		tx, e := a.db.Begin()
		if e != nil {
			fail(w, 500, e.Error())
			return
		}
		_, e = tx.Exec("INSERT INTO rentals(route_id,client,contact,debt_cents,paid_until,remind,last_reminder) VALUES(?,?,?,?,?,?,?) ON CONFLICT(route_id) DO UPDATE SET debt_cents=excluded.debt_cents,paid_until=excluded.paid_until", id, before.Client, before.Contact, after, date, boolInt(before.Remind), before.LastReminder)
		if e == nil {
			_, e = tx.Exec("INSERT INTO payments(route_id,amount_cents,note,created_at,debt_before,debt_after,paid_until) VALUES(?,?,?,?,?,?,?)", id, req.AmountCents, req.Note, time.Now().Unix(), before.DebtCents, after, date)
		}
		if e != nil {
			tx.Rollback()
			fail(w, 500, e.Error())
			return
		}
		if e = tx.Commit(); e != nil {
			fail(w, 500, e.Error())
			return
		}
		writeJSON(w, 200, a.rental(id))
		return
	}
	if len(parts) > 1 {
		fail(w, 404, "not found")
		return
	}
	if r.Method == "GET" {
		writeJSON(w, 200, a.rental(id))
		return
	}
	if r.Method != "PUT" {
		fail(w, 405, "method")
		return
	}
	var v Rental
	if readJSON(r, &v) != nil || len(v.Client) > 120 || len(v.Contact) > 500 || v.DebtCents < 0 || v.DebtCents > 1000000000 || !validDate(v.PaidUntil) {
		fail(w, 400, "invalid rental")
		return
	}
	v.RouteID = id
	a.financeMu.Lock()
	defer a.financeMu.Unlock()
	before := a.rental(id)
	_, e = a.db.Exec("INSERT INTO rentals(route_id,client,contact,debt_cents,paid_until,remind,last_reminder) VALUES(?,?,?,?,?,?,?) ON CONFLICT(route_id) DO UPDATE SET client=excluded.client,contact=excluded.contact,debt_cents=excluded.debt_cents,paid_until=excluded.paid_until,remind=excluded.remind,last_reminder=excluded.last_reminder", id, strings.TrimSpace(v.Client), strings.TrimSpace(v.Contact), v.DebtCents, v.PaidUntil, boolInt(v.Remind), before.LastReminder)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	writeJSON(w, 200, a.rental(id))
}
func (a *App) checkRentals(now time.Time) {
	local := now.In(a.location)
	today := local.Format("2006-01-02")
	if local.Hour() < 9 {
		return
	}
	rows, e := a.db.Query("SELECT route_id FROM rentals WHERE remind=1 AND debt_cents>0 AND paid_until=? AND last_reminder<>?", today, today)
	if e != nil {
		return
	}
	ids := []int64{}
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		v := a.rental(id)
		res, e := a.db.Exec("UPDATE rentals SET last_reminder=? WHERE route_id=? AND last_reminder<>?", today, id, today)
		if e != nil {
			continue
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			continue
		}
		a.mu.RLock()
		s := a.routes[id]
		a.mu.RUnlock()
		if s == nil {
			continue
		}
		s.mu.Lock()
		route := s.Route
		s.mu.Unlock()
		name := v.Client
		if name == "" {
			name = "Клиент не указан"
		}
		go a.notify(route, fmt.Sprintf("Напоминание об аренде: %s, контакт: %s. Оплачено до %s. Текущий долг: $%.2f.", name, v.Contact, v.PaidUntil, float64(v.DebtCents)/100))
	}
}
