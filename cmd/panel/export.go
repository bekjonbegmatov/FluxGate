package main

import (
	"context"
	"database/sql"
	"encoding/csv"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func csvSafe(s string) string {
	trimmed := strings.TrimLeft(s, " \t\r\n")
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + s
	}
	return s
}
func (a *App) exportRange(r *http.Request) (time.Time, time.Time, error) {
	now := time.Now().In(a.location)
	from := now.AddDate(0, 0, -29).Format("2006-01-02")
	to := now.Format("2006-01-02")
	if x := r.URL.Query().Get("from"); x != "" {
		from = x
	}
	if x := r.URL.Query().Get("to"); x != "" {
		to = x
	}
	if !validDate(from) || !validDate(to) {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid date")
	}
	start, e1 := time.ParseInLocation("2006-01-02", from, a.location)
	end, e2 := time.ParseInLocation("2006-01-02", to, a.location)
	if e1 != nil || e2 != nil || end.Before(start) || end.Sub(start) > 366*24*time.Hour {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid date range")
	}
	return start, end.AddDate(0, 0, 1), nil
}
func exportRouteID(r *http.Request) (int64, error) {
	if r.URL.Query().Get("route_id") == "" {
		return 0, nil
	}
	id, e := strconv.ParseInt(r.URL.Query().Get("route_id"), 10, 64)
	if e != nil || id <= 0 {
		return 0, fmt.Errorf("invalid route id")
	}
	return id, nil
}

// Materialize on disk before sending any bytes to the client. Otherwise a slow
// recipient keeps rows open and monopolizes the single SQLite connection.
func (a *App) exportCSV(w http.ResponseWriter, r *http.Request, name, query string, args []any, header []string, record func(*sql.Rows) ([]string, error)) {
	if !a.exportBusy.CompareAndSwap(false, true) {
		w.Header().Set("Retry-After", "5")
		fail(w, 503, "another export is in progress")
		return
	}
	defer a.exportBusy.Store(false)
	f, err := os.CreateTemp(a.data, "export-*.csv")
	if err != nil {
		fail(w, 500, "cannot create export")
		return
	}
	defer os.Remove(f.Name())
	defer f.Close()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	err = func() error {
		rows, err := a.db.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		if _, err := f.Write([]byte{0xef, 0xbb, 0xbf}); err != nil {
			return err
		}
		csvw := csv.NewWriter(f)
		if err := csvw.Write(header); err != nil {
			return err
		}
		for rows.Next() {
			line, err := record(rows)
			if err != nil {
				return err
			}
			if err := csvw.Write(line); err != nil {
				return err
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		csvw.Flush()
		return csvw.Error()
	}()
	if err != nil {
		fail(w, 500, "export could not be completed")
		return
	}
	if _, err = f.Seek(0, 0); err != nil {
		fail(w, 500, "cannot read export")
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	w.Header().Set("Cache-Control", "no-store")
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(2 * time.Minute))
	http.ServeContent(w, r, name, time.Time{}, f)
}
func (a *App) exportPaymentsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		fail(w, 405, "method")
		return
	}
	start, end, e := a.exportRange(r)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	id, e := exportRouteID(r)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	query := `SELECT p.created_at,p.route_id,COALESCE(rt.name,''),COALESCE(rt.sni,''),COALESCE(ren.client,''),COALESCE(ren.contact,''),p.amount_cents,p.paid_until,p.note FROM payments p LEFT JOIN routes rt ON rt.id=p.route_id LEFT JOIN rentals ren ON ren.route_id=p.route_id WHERE p.created_at>=? AND p.created_at<?`
	args := []any{start.Unix(), end.Unix()}
	if id > 0 {
		query += " AND p.route_id=?"
		args = append(args, id)
	}
	query += " ORDER BY p.created_at,p.id"
	a.exportCSV(w, r, "fluxgate-payments.csv", query, args, []string{"Дата оплаты", "ID сервера", "Сервер", "SNI", "Арендатор", "Контакт", "Получено USD", "Оплачено до", "Примечание"}, func(rows *sql.Rows) ([]string, error) {
		var ts, routeID, amount int64
		var name, sni, client, contact, paidUntil, note string
		if err := rows.Scan(&ts, &routeID, &name, &sni, &client, &contact, &amount, &paidUntil, &note); err != nil {
			return nil, err
		}
		return []string{time.Unix(ts, 0).In(a.location).Format("2006-01-02 15:04:05"), strconv.FormatInt(routeID, 10), csvSafe(name), csvSafe(sni), csvSafe(client), csvSafe(contact), fmt.Sprintf("%.2f", float64(amount)/100), paidUntil, csvSafe(note)}, nil
	})
}
func (a *App) exportTrafficAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		fail(w, 405, "method")
		return
	}
	start, end, e := a.exportRange(r)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	id, e := exportRouteID(r)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "day"
	}
	if period != "day" && period != "hour" {
		fail(w, 400, "invalid period")
		return
	}
	// Samples are stored in UTC minute buckets; grouping uses UTC to keep the export unambiguous.
	divisor := int64(86400)
	if period == "hour" {
		divisor = 3600
	}
	query := `SELECT (s.ts/?)*?,s.route_id,COALESCE(rt.name,''),COALESCE(rt.sni,''),SUM(s.up),SUM(s.down) FROM samples s LEFT JOIN routes rt ON rt.id=s.route_id WHERE s.ts>=? AND s.ts<?`
	args := []any{divisor, divisor, start.Unix(), end.Unix()}
	if id > 0 {
		query += " AND s.route_id=?"
		args = append(args, id)
	}
	query += " GROUP BY 1,s.route_id ORDER BY 1,s.route_id"
	a.exportCSV(w, r, "fluxgate-traffic.csv", query, args, []string{"Период UTC", "ID сервера", "Сервер", "SNI", "Приём байт", "Отдача байт", "Всего байт"}, func(rows *sql.Rows) ([]string, error) {
		var ts, routeID, up, down int64
		var name, sni string
		if err := rows.Scan(&ts, &routeID, &name, &sni, &up, &down); err != nil {
			return nil, err
		}
		stamp := time.Unix(ts, 0).UTC().Format("2006-01-02")
		if period == "hour" {
			stamp = time.Unix(ts, 0).UTC().Format("2006-01-02 15:00")
		}
		return []string{stamp, strconv.FormatInt(routeID, 10), csvSafe(name), csvSafe(sni), strconv.FormatInt(up, 10), strconv.FormatInt(down, 10), strconv.FormatInt(up+down, 10)}, nil
	})
}
