package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type RequestStats struct {
	RouteID      int64   `json:"route_id"`
	Requests     int64   `json:"requests"`
	Responses2xx int64   `json:"responses_2xx"`
	Responses3xx int64   `json:"responses_3xx"`
	Responses4xx int64   `json:"responses_4xx"`
	Responses5xx int64   `json:"responses_5xx"`
	Active       int64   `json:"active"`
	Rate         float64 `json:"rate"`
	ResponseMS   int64   `json:"response_ms"`
	UpdatedAt    int64   `json:"updated_at"`
}
type requestCounter struct{ requests, r2, r3, r4, r5, active, responseMS int64 }

func (a *App) initRequestStats() error {
	_, err := a.db.Exec(`CREATE TABLE IF NOT EXISTS request_totals(route_id INTEGER PRIMARY KEY,requests INTEGER NOT NULL DEFAULT 0,r2 INTEGER NOT NULL DEFAULT 0,r3 INTEGER NOT NULL DEFAULT 0,r4 INTEGER NOT NULL DEFAULT 0,r5 INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS request_samples(route_id INTEGER NOT NULL,ts INTEGER NOT NULL,requests INTEGER NOT NULL DEFAULT 0,r2 INTEGER NOT NULL DEFAULT 0,r3 INTEGER NOT NULL DEFAULT 0,r4 INTEGER NOT NULL DEFAULT 0,r5 INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(route_id,ts));`)
	return err
}
func parseCounter(s string) int64 { v, _ := strconv.ParseInt(s, 10, 64); return v }
func deltaCounter(current, previous int64) int64 {
	if current >= previous {
		return current - previous
	}
	return current
}
func readHAProxyStats(path string) (map[int64]requestCounter, error) {
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = io.WriteString(c, "show stat\n"); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(c, 8<<20))
	if err != nil {
		return nil, err
	}
	reader := csv.NewReader(strings.NewReader(string(data)))
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) < 1 {
		return nil, fmt.Errorf("empty HAProxy stats")
	}
	header := records[0]
	index := map[string]int{}
	for i, k := range header {
		index[strings.TrimSpace(strings.TrimPrefix(k, "# "))] = i
	}
	field := func(row []string, key string) string {
		i, ok := index[key]
		if !ok || i >= len(row) {
			return ""
		}
		return row[i]
	}
	out := map[int64]requestCounter{}
	for _, row := range records[1:] {
		if field(row, "svname") != "BACKEND" {
			continue
		}
		name := field(row, "pxname")
		if !strings.HasPrefix(name, "target_") {
			continue
		}
		id, e := strconv.ParseInt(strings.TrimPrefix(name, "target_"), 10, 64)
		if e != nil || id <= 0 {
			continue
		}
		out[id] = requestCounter{parseCounter(field(row, "req_tot")), parseCounter(field(row, "hrsp_2xx")), parseCounter(field(row, "hrsp_3xx")), parseCounter(field(row, "hrsp_4xx")), parseCounter(field(row, "hrsp_5xx")), parseCounter(field(row, "scur")), parseCounter(field(row, "rtime"))}
	}
	return out, nil
}
func (a *App) collectRequestStats(now time.Time) {
	a.statsMu.Lock()
	defer a.statsMu.Unlock()
	observed, err := readHAProxyStats(filepath.Join(a.data, "haproxy.sock"))
	if err != nil {
		log.Printf("haproxy stats: %v", err)
		return
	}
	if a.lastStats == nil {
		a.lastStats = observed
		a.lastStatsAt = now
		return
	}
	elapsed := now.Sub(a.lastStatsAt).Seconds()
	if elapsed < 1 {
		elapsed = 1
	}
	for id, current := range observed {
		previous, known := a.lastStats[id]
		if !known {
			a.lastStats[id] = current
			continue
		}
		d := requestCounter{requests: deltaCounter(current.requests, previous.requests), r2: deltaCounter(current.r2, previous.r2), r3: deltaCounter(current.r3, previous.r3), r4: deltaCounter(current.r4, previous.r4), r5: deltaCounter(current.r5, previous.r5)}
		a.liveStats[id] = RequestStats{RouteID: id, Active: current.active, Rate: float64(d.requests) / elapsed, ResponseMS: current.responseMS, UpdatedAt: now.Unix()}
		if d.requests+d.r2+d.r3+d.r4+d.r5 == 0 {
			continue
		}
		tx, e := a.db.Begin()
		if e != nil {
			log.Printf("request stats db: %v", e)
			continue
		}
		_, e = tx.Exec("INSERT INTO request_totals(route_id,requests,r2,r3,r4,r5) VALUES(?,?,?,?,?,?) ON CONFLICT(route_id) DO UPDATE SET requests=requests+excluded.requests,r2=r2+excluded.r2,r3=r3+excluded.r3,r4=r4+excluded.r4,r5=r5+excluded.r5", id, d.requests, d.r2, d.r3, d.r4, d.r5)
		if e == nil {
			minute := now.Unix() / 60 * 60
			_, e = tx.Exec("INSERT INTO request_samples(route_id,ts,requests,r2,r3,r4,r5) VALUES(?,?,?,?,?,?,?) ON CONFLICT(route_id,ts) DO UPDATE SET requests=requests+excluded.requests,r2=r2+excluded.r2,r3=r3+excluded.r3,r4=r4+excluded.r4,r5=r5+excluded.r5", id, minute, d.requests, d.r2, d.r3, d.r4, d.r5)
		}
		if e != nil {
			tx.Rollback()
			log.Printf("request stats db: %v", e)
		} else if e = tx.Commit(); e != nil {
			log.Printf("request stats commit: %v", e)
		}
	}
	a.lastStats = observed
	a.lastStatsAt = now
}
func (a *App) requestStatsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		fail(w, 405, "method")
		return
	}
	rows, e := a.db.Query("SELECT route_id,requests,r2,r3,r4,r5 FROM request_totals")
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	defer rows.Close()
	out := map[int64]RequestStats{}
	for rows.Next() {
		var v RequestStats
		if rows.Scan(&v.RouteID, &v.Requests, &v.Responses2xx, &v.Responses3xx, &v.Responses4xx, &v.Responses5xx) == nil {
			out[v.RouteID] = v
		}
	}
	a.statsMu.RLock()
	for id, v := range a.liveStats {
		item := out[id]
		item.RouteID = id
		item.Active = v.Active
		item.Rate = v.Rate
		item.ResponseMS = v.ResponseMS
		item.UpdatedAt = v.UpdatedAt
		out[id] = item
	}
	a.statsMu.RUnlock()
	list := []RequestStats{}
	a.mu.RLock()
	for id := range a.routes {
		v := out[id]
		v.RouteID = id
		list = append(list, v)
	}
	a.mu.RUnlock()
	writeJSON(w, 200, list)
}
func (a *App) requestHistoryAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		fail(w, 405, "method")
		return
	}
	part := strings.TrimPrefix(r.URL.Path, "/"+a.secretPath+"/api/request-history/")
	id, e := strconv.ParseInt(part, 10, 64)
	if e != nil && part != "all" {
		fail(w, 400, "id")
		return
	}
	hours := 24
	if n, e := strconv.Atoi(r.URL.Query().Get("hours")); e == nil && n >= 1 && n <= 2160 {
		hours = n
	}
	bucket := int64(hours * 3600 / 60)
	if bucket < 60 {
		bucket = 60
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	query := "SELECT (ts/?)*?,SUM(requests),SUM(r2),SUM(r3),SUM(r4),SUM(r5) FROM request_samples WHERE route_id=? AND ts>=? GROUP BY 1 ORDER BY 1"
	args := []any{bucket, bucket, id, since}
	if part == "all" {
		query = "SELECT (ts/?)*?,SUM(requests),SUM(r2),SUM(r3),SUM(r4),SUM(r5) FROM request_samples WHERE ts>=? GROUP BY 1 ORDER BY 1"
		args = []any{bucket, bucket, since}
	}
	rows, e := a.db.Query(query, args...)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	defer rows.Close()
	out := [][6]int64{}
	for rows.Next() {
		var item [6]int64
		if rows.Scan(&item[0], &item[1], &item[2], &item[3], &item[4], &item[5]) == nil {
			out = append(out, item)
		}
	}
	writeJSON(w, 200, out)
}
