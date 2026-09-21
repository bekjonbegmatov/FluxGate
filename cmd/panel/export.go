package main

import (
	"encoding/csv"
	"fmt"
	"net/http"
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
func startCSV(w http.ResponseWriter, name string) *csv.Writer {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte{0xef, 0xbb, 0xbf})
	return csv.NewWriter(w)
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
	rows, e := a.db.Query(query, args...)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	defer rows.Close()
	csvw := startCSV(w, "fluxgate-payments.csv")
	_ = csvw.Write([]string{"Дата оплаты", "ID сервера", "Сервер", "SNI", "Арендатор", "Контакт", "Получено USD", "Оплачено до", "Примечание"})
	for rows.Next() {
		var ts, routeID, amount int64
		var name, sni, client, contact, paidUntil, note string
		if rows.Scan(&ts, &routeID, &name, &sni, &client, &contact, &amount, &paidUntil, &note) != nil {
			continue
		}
		_ = csvw.Write([]string{time.Unix(ts, 0).In(a.location).Format("2006-01-02 15:04:05"), strconv.FormatInt(routeID, 10), csvSafe(name), csvSafe(sni), csvSafe(client), csvSafe(contact), fmt.Sprintf("%.2f", float64(amount)/100), paidUntil, csvSafe(note)})
	}
	csvw.Flush()
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
	rows, e := a.db.Query(query, args...)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	defer rows.Close()
	csvw := startCSV(w, "fluxgate-traffic.csv")
	_ = csvw.Write([]string{"Период UTC", "ID сервера", "Сервер", "SNI", "Приём байт", "Отдача байт", "Всего байт"})
	for rows.Next() {
		var ts, routeID, up, down int64
		var name, sni string
		if rows.Scan(&ts, &routeID, &name, &sni, &up, &down) != nil {
			continue
		}
		stamp := time.Unix(ts, 0).UTC().Format("2006-01-02")
		if period == "hour" {
			stamp = time.Unix(ts, 0).UTC().Format("2006-01-02 15:00")
		}
		_ = csvw.Write([]string{stamp, strconv.FormatInt(routeID, 10), csvSafe(name), csvSafe(sni), strconv.FormatInt(up, 10), strconv.FormatInt(down, 10), strconv.FormatInt(up+down, 10)})
	}
	csvw.Flush()
}
