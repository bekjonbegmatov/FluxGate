package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
func readJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	return d.Decode(v)
}
func (a *App) sessionValid(r *http.Request) bool {
	c, err := r.Cookie("panel_session")
	if err != nil {
		return false
	}
	p := strings.Split(c.Value, ".")
	if len(p) != 2 {
		return false
	}
	raw, e := base64.RawURLEncoding.DecodeString(p[0])
	if e != nil {
		return false
	}
	mac, e := base64.RawURLEncoding.DecodeString(p[1])
	if e != nil {
		return false
	}
	h := hmac.New(sha256.New, a.master)
	h.Write(raw)
	if !hmac.Equal(mac, h.Sum(nil)) {
		return false
	}
	v := strings.Split(string(raw), ":")
	if len(v) != 2 {
		return false
	}
	exp, e := strconv.ParseInt(v[0], 10, 64)
	return e == nil && time.Now().Unix() < exp
}
func (a *App) newSession() string {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	raw := []byte(fmt.Sprintf("%d:%x", time.Now().Add(24*time.Hour).Unix(), nonce))
	h := hmac.New(sha256.New, a.master)
	h.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
func (a *App) adminServer() *http.Server {
	mux := http.NewServeMux()
	base := "/" + a.secretPath + "/"
	mux.HandleFunc("/healthz", a.healthAPI)
	mux.HandleFunc(base+"api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			fail(w, 405, "method")
			return
		}
		var v struct {
			Token string `json:"token"`
		}
		if readJSON(r, &v) != nil {
			fail(w, 400, "invalid JSON")
			return
		}
		h := sha256.Sum256([]byte(v.Token))
		if subtle.ConstantTimeCompare(h[:], a.tokenHash[:]) != 1 {
			time.Sleep(200 * time.Millisecond)
			fail(w, 401, "invalid token")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "panel_session", Value: a.newSession(), Path: base, HttpOnly: true, Secure: false, SameSite: http.SameSiteStrictMode, MaxAge: 86400})
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc(base+"api/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "panel_session", Value: "", Path: base, HttpOnly: true, Secure: false, SameSite: http.SameSiteStrictMode, MaxAge: -1})
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc(base+"api/me", a.auth(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]bool{"ok": true}) }))
	mux.HandleFunc(base+"api/routes", a.auth(a.routesAPI))
	mux.HandleFunc(base+"api/routes/", a.auth(a.routeAPI))
	mux.HandleFunc(base+"api/settings", a.auth(a.settingsAPI))
	mux.HandleFunc(base+"api/backup", a.auth(a.backupAPI))
	mux.HandleFunc(base+"api/restore", a.auth(a.restoreAPI))
	mux.HandleFunc(base+"api/history/", a.auth(a.historyAPI))
	mux.HandleFunc(base+"api/finance", a.auth(a.financeAPI))
	mux.HandleFunc(base+"api/finance/", a.auth(a.financeAPI))
	mux.HandleFunc(base+"api/system", a.auth(a.systemAPI))
	mux.HandleFunc(base+"api/request-stats", a.auth(a.requestStatsAPI))
	mux.HandleFunc(base+"api/request-history/", a.auth(a.requestHistoryAPI))
	mux.HandleFunc(base+"api/export/payments.csv", a.auth(a.exportPaymentsAPI))
	mux.HandleFunc(base+"api/export/traffic.csv", a.auth(a.exportTrafficAPI))
	mux.HandleFunc(base, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		p := strings.TrimPrefix(r.URL.Path, base)
		if p == "" {
			p = "index.html"
		}
		full := filepath.Join(a.web, filepath.Clean("/"+p))
		if !strings.HasPrefix(full, filepath.Clean(a.web)+string(os.PathSeparator)) {
			http.NotFound(w, r)
			return
		}
		if _, e := os.Stat(full); e != nil {
			full = filepath.Join(a.web, "index.html")
		}
		w.Header().Set("Cache-Control", "no-store")
		http.ServeFile(w, r, full)
	})
	listen := env("PANEL_LISTEN", "0.0.0.0:9389")
	server := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("panel listening on http://%s/%s/", listen, a.secretPath)
	return server
}
func (a *App) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.sessionValid(r) {
			fail(w, 401, "unauthorized")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			origin := r.Header.Get("Origin")
			if origin != "" {
				u, e := url.Parse(origin)
				if e != nil || u.Host != r.Host {
					fail(w, 403, "origin")
					return
				}
			}
		}
		next(w, r)
	}
}
func (a *App) routesAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		a.mu.RLock()
		list := make([]Route, 0, len(a.routes))
		for _, s := range a.routes {
			s.mu.Lock()
			v := s.Route
			v.DailyUsed = s.Daily.Used
			v.DailyExtra = s.Daily.Extra
			v.MonthlyUsed = s.Monthly.Used
			v.MonthlyExtra = s.Monthly.Extra
			v.UpRate = s.lastUp
			v.DownRate = s.lastDown
			switch {
			case v.Paused:
				v.Status = "paused"
			case s.blocked():
				v.Status = "quota"
			case !s.healthy:
				v.Status = "down"
			default:
				v.Status = "online"
			}
			s.mu.Unlock()
			list = append(list, v)
		}
		a.mu.RUnlock()
		sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
		writeJSON(w, 200, list)
	case "POST":
		a.stateMu.Lock()
		defer a.stateMu.Unlock()
		var v Route
		if readJSON(r, &v) != nil {
			fail(w, 400, "invalid JSON")
			return
		}
		a.createRoute(w, v)
	default:
		fail(w, 405, "method")
	}
}
func validateRoute(v *Route) error {
	v.SNI = strings.ToLower(strings.TrimSpace(v.SNI))
	v.VerifyName = strings.ToLower(strings.TrimSpace(v.VerifyName))
	v.Name = strings.TrimSpace(v.Name)
	if len(v.Name) < 1 || len(v.Name) > 80 {
		return fmt.Errorf("name must be 1–80 characters")
	}
	if !validSNI(v.SNI) {
		return fmt.Errorf("invalid SNI")
	}
	if net.ParseIP(v.IP) == nil {
		return fmt.Errorf("IP must be IPv4 or IPv6")
	}
	if v.Port < 1 || v.Port > 65535 {
		return fmt.Errorf("invalid port")
	}
	if v.Verify && (!v.TLS || !validDomain(v.VerifyName)) {
		return fmt.Errorf("verified HTTPS requires a certificate name")
	}
	if v.DailyLimit < 0 || v.MonthlyLimit < 0 || v.DownBPS < 0 || v.UpBPS < 0 {
		return fmt.Errorf("limits cannot be negative")
	}
	if v.CountMode != "up" && v.CountMode != "down" && v.CountMode != "both" {
		return fmt.Errorf("count mode must be up, down, or both")
	}
	if v.Threshold < 1 || v.Threshold > 100 {
		return fmt.Errorf("threshold must be 1–100")
	}
	return nil
}
func (a *App) createRoute(w http.ResponseWriter, v Route) {
	if e := validateRoute(&v); e != nil {
		fail(w, 400, e.Error())
		return
	}
	if v.SNI == a.domain {
		fail(w, 400, "main domain is reserved for fallback")
		return
	}
	// Read-only counters in a POST are never accepted as initial usage.
	v.UpTotal, v.DownTotal = 0, 0
	v.CreatedAt = time.Now().Unix()
	result, e := a.db.Exec("INSERT INTO routes(name,sni,ip,port,tls,verify,verify_name,paused,daily_limit,monthly_limit,count_mode,down_bps,up_bps,threshold,created_at,monitor) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", v.Name, v.SNI, v.IP, v.Port, boolInt(v.TLS), boolInt(v.Verify), v.VerifyName, boolInt(v.Paused), v.DailyLimit, v.MonthlyLimit, v.CountMode, v.DownBPS, v.UpBPS, v.Threshold, v.CreatedAt, boolInt(v.Monitor))
	if e != nil {
		fail(w, 409, e.Error())
		return
	}
	v.ID, _ = result.LastInsertId()
	if v.ID > 55535 {
		_, _ = a.db.Exec("DELETE FROM routes WHERE id=?", v.ID)
		fail(w, 400, "too many routes")
		return
	}
	s := &RouteState{Route: v, conns: map[net.Conn]struct{}{}}
	if e = a.refreshPeriods(s, time.Now()); e != nil {
		_, _ = a.db.Exec("DELETE FROM routes WHERE id=?", v.ID)
		fail(w, 500, e.Error())
		return
	}
	a.mu.Lock()
	a.routes[v.ID] = s
	a.mu.Unlock()
	if e = a.ensureCert(routeCert(v), v.SNI); e == nil {
		e = a.listenRoute(s)
	}
	if e == nil {
		e = a.writeConfig()
	}
	if e != nil {
		a.mu.Lock()
		delete(a.routes, v.ID)
		a.mu.Unlock()
		if s.Listener != nil {
			_ = s.Listener.Close()
		}
		_, _ = a.db.Exec("DELETE FROM routes WHERE id=?", v.ID)
		fail(w, 500, e.Error())
		return
	}
	a.historyEpoch.Add(1)
	writeJSON(w, 201, v)
}
func (a *App) routeAPI(w http.ResponseWriter, r *http.Request) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	part := strings.TrimPrefix(r.URL.Path, "/"+a.secretPath+"/api/routes/")
	items := strings.Split(strings.Trim(part, "/"), "/")
	id, e := strconv.ParseInt(items[0], 10, 64)
	if e != nil {
		fail(w, 400, "invalid id")
		return
	}
	a.mu.RLock()
	s := a.routes[id]
	a.mu.RUnlock()
	if s == nil {
		fail(w, 404, "not found")
		return
	}
	if len(items) == 2 && items[1] == "topup" {
		a.topup(w, r, s)
		return
	}
	switch r.Method {
	case "PUT":
		var v Route
		if readJSON(r, &v) != nil {
			fail(w, 400, "invalid JSON")
			return
		}
		v.ID = id
		s.mu.Lock()
		old := s.Route
		v.CreatedAt = old.CreatedAt
		v.UpTotal = old.UpTotal
		v.DownTotal = old.DownTotal
		s.mu.Unlock()
		if e := validateRoute(&v); e != nil {
			fail(w, 400, e.Error())
			return
		}
		if v.SNI == a.domain {
			fail(w, 400, "main domain is reserved for fallback")
			return
		}
		var conflict int64
		if a.db.QueryRow("SELECT id FROM routes WHERE sni=? AND id<>?", v.SNI, id).Scan(&conflict) == nil {
			fail(w, 409, "SNI is already assigned")
			return
		}
		s.mu.Lock()
		oldDaily, oldMonthly := s.Daily, s.Monthly
		v.UpTotal, v.DownTotal = s.Route.UpTotal, s.Route.DownTotal
		s.Route = v
		rearmQuota(&s.Daily, v.DailyLimit+s.Daily.Extra, v.Threshold)
		rearmQuota(&s.Monthly, v.MonthlyLimit+s.Monthly.Extra, v.Threshold)
		s.mu.Unlock()
		if e = a.ensureCert(routeCert(v), v.SNI); e == nil {
			e = a.writeConfig()
		}
		if e != nil {
			s.mu.Lock()
			s.restoreRoute(old, oldDaily, oldMonthly)
			s.mu.Unlock()
			fail(w, 400, e.Error())
			return
		}
		_, e = a.db.Exec("UPDATE routes SET name=?,sni=?,ip=?,port=?,tls=?,verify=?,verify_name=?,paused=?,daily_limit=?,monthly_limit=?,count_mode=?,down_bps=?,up_bps=?,threshold=?,monitor=? WHERE id=?", v.Name, v.SNI, v.IP, v.Port, boolInt(v.TLS), boolInt(v.Verify), v.VerifyName, boolInt(v.Paused), v.DailyLimit, v.MonthlyLimit, v.CountMode, v.DownBPS, v.UpBPS, v.Threshold, boolInt(v.Monitor), id)
		if e != nil {
			s.mu.Lock()
			s.restoreRoute(old, oldDaily, oldMonthly)
			s.mu.Unlock()
			_ = a.writeConfig()
			fail(w, 500, e.Error())
			return
		}
		if v.Paused {
			a.closeRouteConns(s)
		}
		s.mu.Lock()
		daily, monthly := s.Daily, s.Monthly
		blocked := s.blocked()
		s.mu.Unlock()
		_, _ = a.db.Exec("UPDATE periods SET threshold_sent=?,exhausted_sent=? WHERE route_id=? AND kind='daily' AND key=?", boolInt(daily.ThresholdSent), boolInt(daily.ExhaustedSent), id, daily.Key)
		_, _ = a.db.Exec("UPDATE periods SET threshold_sent=?,exhausted_sent=? WHERE route_id=? AND kind='monthly' AND key=?", boolInt(monthly.ThresholdSent), boolInt(monthly.ExhaustedSent), id, monthly.Key)
		if blocked {
			a.exhaust(s)
		}
		writeJSON(w, 200, v)
	case "DELETE":
		a.mu.Lock()
		delete(a.routes, id)
		a.mu.Unlock()
		if e = a.writeConfig(); e != nil {
			a.mu.Lock()
			a.routes[id] = s
			a.mu.Unlock()
			fail(w, 500, e.Error())
			return
		}
		tx, err := a.db.Begin()
		if err == nil {
			for _, table := range []string{"routes", "periods", "samples", "request_totals", "request_samples", "rentals", "payments"} {
				column := "route_id"
				if table == "routes" {
					column = "id"
				}
				if _, err = tx.Exec("DELETE FROM "+table+" WHERE "+column+"=?", id); err != nil {
					break
				}
			}
			if err == nil {
				err = tx.Commit()
			} else {
				_ = tx.Rollback()
			}
		}
		if err != nil {
			a.mu.Lock()
			a.routes[id] = s
			a.mu.Unlock()
			_ = a.writeConfig()
			fail(w, 500, err.Error())
			return
		}
		s.mu.Lock()
		s.deleted = true
		if s.Listener != nil {
			_ = s.Listener.Close()
		}
		s.mu.Unlock()
		a.closeRouteConns(s)
		a.historyEpoch.Add(1)
		delete(a.lastStats, id)
		a.statsMu.Lock()
		delete(a.liveStats, id)
		a.statsMu.Unlock()
		files, _ := filepath.Glob(filepath.Join(a.data, "certs", fmt.Sprintf("route_%d_*.pem", id)))
		for _, f := range files {
			_ = os.Remove(f)
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	default:
		fail(w, 405, "method")
	}
}
func (a *App) closeRouteConns(s *RouteState) {
	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		if pair, ok := c.(*relayConn); ok {
			pair.abort()
		} else {
			_ = c.Close()
		}
	}
}

// Roll back configuration without discarding traffic recorded during validation.
func (s *RouteState) restoreRoute(old Route, daily, monthly Period) {
	old.UpTotal, old.DownTotal = s.Route.UpTotal, s.Route.DownTotal
	s.Route = old
	s.Daily.ThresholdSent, s.Daily.ExhaustedSent = daily.ThresholdSent, daily.ExhaustedSent
	s.Monthly.ThresholdSent, s.Monthly.ExhaustedSent = monthly.ThresholdSent, monthly.ExhaustedSent
}
func (a *App) topup(w http.ResponseWriter, r *http.Request, s *RouteState) {
	if r.Method != "POST" {
		fail(w, 405, "method")
		return
	}
	var req struct {
		Kind  string `json:"kind"`
		Bytes int64  `json:"bytes"`
	}
	if readJSON(r, &req) != nil || req.Bytes <= 0 || req.Bytes > 1<<60 || (req.Kind != "daily" && req.Kind != "monthly") {
		fail(w, 400, "invalid topup")
		return
	}
	s.mu.Lock()
	p := &s.Daily
	baseLimit := s.Route.DailyLimit
	if req.Kind == "monthly" {
		p = &s.Monthly
		baseLimit = s.Route.MonthlyLimit
	}
	if baseLimit <= 0 {
		s.mu.Unlock()
		fail(w, 400, "quota is not configured")
		return
	}
	oldLimit := baseLimit + p.Extra
	if req.Bytes > int64(^uint64(0)>>1)-oldLimit {
		s.mu.Unlock()
		fail(w, 400, "topup is too large")
		return
	}
	period := *p
	period.Extra += req.Bytes
	newLimit := baseLimit + period.Extra
	rearmQuota(&period, newLimit, s.Route.Threshold)
	rte := s.Route
	s.mu.Unlock()
	_, err := a.db.Exec("INSERT INTO periods(route_id,kind,key,used,extra,threshold_sent,exhausted_sent) VALUES(?,?,?,?,?,?,?) ON CONFLICT(route_id,kind,key) DO UPDATE SET extra=excluded.extra,threshold_sent=excluded.threshold_sent,exhausted_sent=excluded.exhausted_sent", rte.ID, req.Kind, period.Key, period.Used, period.Extra, boolInt(period.ThresholdSent), boolInt(period.ExhaustedSent))
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	s.mu.Lock()
	p.Extra = period.Extra
	rearmQuota(p, newLimit, s.Route.Threshold)
	s.mu.Unlock()
	a.notify(rte, quotaTopupMessage(req.Kind, req.Bytes, oldLimit, newLimit, period.Used))
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (a *App) settingsAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		a.mu.RLock()
		v := map[string]any{"domain": a.domain, "timezone": a.location.String(), "fallback_html": a.fallback, "tg_api": a.tg.APIURL, "tg_chat": a.tg.ChatID, "tg_token_set": a.tg.BotToken != ""}
		a.mu.RUnlock()
		writeJSON(w, 200, v)
	case "PUT":
		a.stateMu.Lock()
		defer a.stateMu.Unlock()
		var v struct {
			Domain       string `json:"domain"`
			FallbackHTML string `json:"fallback_html"`
			TGAPI        string `json:"tg_api"`
			TGChat       string `json:"tg_chat"`
			TGToken      string `json:"tg_token"`
		}
		if readJSON(r, &v) != nil {
			fail(w, 400, "invalid JSON")
			return
		}
		if len(v.FallbackHTML) > 1<<20 {
			fail(w, 400, "HTML too large")
			return
		}
		v.Domain = strings.ToLower(strings.TrimSpace(v.Domain))
		if v.Domain != "" && !validDomain(v.Domain) {
			fail(w, 400, "invalid domain")
			return
		}
		u, e := url.Parse(v.TGAPI)
		if e != nil || u.Scheme != "https" || u.Host == "" {
			fail(w, 400, "Bot API URL must use HTTPS")
			return
		}
		a.mu.RLock()
		oldDomain := a.domain
		a.mu.RUnlock()
		if v.Domain == "" {
			v.Domain = oldDomain
		}
		if v.Domain != oldDomain {
			a.mu.RLock()
			conflict := false
			for _, route := range a.routes {
				route.mu.Lock()
				sni := route.Route.SNI
				route.mu.Unlock()
				if sni == v.Domain || (strings.HasPrefix(sni, "*.") && strings.HasSuffix(v.Domain, sni[1:])) {
					conflict = true
					break
				}
			}
			a.mu.RUnlock()
			if conflict {
				fail(w, 409, "domain is already used by a server route")
				return
			}
			certPath := filepath.Join(a.data, "certs", "fallback.pem")
			oldCert, err := os.ReadFile(certPath)
			if err != nil {
				fail(w, 500, err.Error())
				return
			}
			if err = a.ensureCert("fallback", v.Domain); err != nil {
				fail(w, 500, err.Error())
				return
			}
			a.mu.Lock()
			a.domain = v.Domain
			a.mu.Unlock()
			if err = a.writeConfig(); err == nil {
				err = a.setSetting("domain", v.Domain)
			}
			if err != nil {
				a.mu.Lock()
				a.domain = oldDomain
				a.mu.Unlock()
				_ = os.WriteFile(certPath, oldCert, 0600)
				_ = a.writeConfig()
				fail(w, 500, err.Error())
				return
			}
		}
		a.mu.Lock()
		a.fallback = v.FallbackHTML
		a.tg.APIURL = strings.TrimRight(v.TGAPI, "/")
		a.tg.ChatID = v.TGChat
		if v.TGToken != "" {
			a.tg.BotToken = v.TGToken
		}
		tg := a.tg
		a.mu.Unlock()
		_ = a.setSetting("fallback_html", v.FallbackHTML)
		_ = a.setSetting("tg_api", tg.APIURL)
		_ = a.setSetting("tg_chat", tg.ChatID)
		if v.TGToken != "" {
			_ = a.setSetting("tg_token", a.encrypt(tg.BotToken))
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	default:
		fail(w, 405, "method")
	}
}
func (a *App) historyAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		fail(w, 405, "method")
		return
	}
	part := strings.TrimPrefix(r.URL.Path, "/"+a.secretPath+"/api/history/")
	id, e := strconv.ParseInt(part, 10, 64)
	if e != nil && part != "all" {
		fail(w, 400, "id")
		return
	}
	hours := 24
	since := time.Now().Truncate(time.Minute).Add(-24 * time.Hour).Unix()
	if n, e := strconv.Atoi(r.URL.Query().Get("hours")); e == nil && n >= 1 && n <= 2160 {
		hours = n
		since = time.Now().Truncate(time.Minute).Add(-time.Duration(n) * time.Hour).Unix()
	}
	bucket := int64(hours * 3600 / 60)
	if bucket < 60 {
		bucket = 60
	}
	query := "SELECT (ts / ?) * ?, SUM(up), SUM(down) FROM samples WHERE route_id=? AND ts>=? GROUP BY 1 ORDER BY 1"
	args := []any{bucket, bucket, id, since}
	if part == "all" {
		query = "SELECT (ts / ?) * ?, SUM(up), SUM(down) FROM samples WHERE ts>=? GROUP BY 1 ORDER BY 1"
		args = []any{bucket, bucket, since}
	}
	out, e := a.historyRows(r.Context(), fmt.Sprintf("traffic/%s/%d/%d", part, hours, since), query, args, 3)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	writeJSON(w, 200, out)
}
