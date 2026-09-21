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
func (a *App) serveAdmin() {
	mux := http.NewServeMux()
	base := "/" + a.secretPath + "/"
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
	mux.HandleFunc(base+"api/history/", a.auth(a.historyAPI))
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
	listen := env("PANEL_LISTEN", "127.0.0.1:9389")
	server := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("panel listening on http://%s/%s/", listen, a.secretPath)
	log.Fatal(server.ListenAndServe())
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
		writeJSON(w, 200, list)
	case "POST":
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
	v.CreatedAt = time.Now().Unix()
	a.mu.Lock()
	result, e := a.db.Exec("INSERT INTO routes(name,sni,ip,port,tls,verify,verify_name,paused,daily_limit,monthly_limit,count_mode,down_bps,up_bps,threshold,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", v.Name, v.SNI, v.IP, v.Port, boolInt(v.TLS), boolInt(v.Verify), v.VerifyName, boolInt(v.Paused), v.DailyLimit, v.MonthlyLimit, v.CountMode, v.DownBPS, v.UpBPS, v.Threshold, v.CreatedAt)
	if e != nil {
		a.mu.Unlock()
		fail(w, 409, e.Error())
		return
	}
	v.ID, _ = result.LastInsertId()
	if v.ID > 55535 {
		_, _ = a.db.Exec("DELETE FROM routes WHERE id=?", v.ID)
		a.mu.Unlock()
		fail(w, 400, "too many routes")
		return
	}
	s := &RouteState{Route: v, conns: map[net.Conn]struct{}{}}
	a.refreshPeriods(s, time.Now())
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
	writeJSON(w, 201, v)
}
func (a *App) routeAPI(w http.ResponseWriter, r *http.Request) {
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
		s.Route = v
		s.mu.Unlock()
		if e = a.ensureCert(routeCert(v), v.SNI); e == nil {
			e = a.writeConfig()
		}
		if e != nil {
			s.mu.Lock()
			s.Route = old
			s.mu.Unlock()
			fail(w, 400, e.Error())
			return
		}
		_, e = a.db.Exec("UPDATE routes SET name=?,sni=?,ip=?,port=?,tls=?,verify=?,verify_name=?,paused=?,daily_limit=?,monthly_limit=?,count_mode=?,down_bps=?,up_bps=?,threshold=? WHERE id=?", v.Name, v.SNI, v.IP, v.Port, boolInt(v.TLS), boolInt(v.Verify), v.VerifyName, boolInt(v.Paused), v.DailyLimit, v.MonthlyLimit, v.CountMode, v.DownBPS, v.UpBPS, v.Threshold, id)
		if e != nil {
			s.mu.Lock()
			s.Route = old
			s.mu.Unlock()
			_ = a.writeConfig()
			fail(w, 500, e.Error())
			return
		}
		if v.Paused {
			a.closeRouteConns(s)
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
		a.closeRouteConns(s)
		s.mu.Lock()
		if s.Listener != nil {
			_ = s.Listener.Close()
		}
		s.mu.Unlock()
		_, _ = a.db.Exec("DELETE FROM routes WHERE id=?", id)
		_, _ = a.db.Exec("DELETE FROM periods WHERE route_id=?", id)
		_, _ = a.db.Exec("DELETE FROM samples WHERE route_id=?", id)
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
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
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
	if req.Kind == "monthly" {
		p = &s.Monthly
	}
	wasBlocked := s.blocked()
	p.Extra += req.Bytes
	period := *p
	nowBlocked := s.blocked()
	rte := s.Route
	s.mu.Unlock()
	_, err := a.db.Exec("INSERT INTO periods(route_id,kind,key,used,extra,threshold_sent,exhausted_sent) VALUES(?,?,?,?,?,?,?) ON CONFLICT(route_id,kind,key) DO UPDATE SET extra=excluded.extra", rte.ID, req.Kind, period.Key, period.Used, period.Extra, boolInt(period.ThresholdSent), boolInt(period.ExhaustedSent))
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	if wasBlocked != nowBlocked {
		_ = a.writeConfig()
	}
	a.notify(rte, fmt.Sprintf("Пополнение %s: +%d байт", req.Kind, req.Bytes))
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
		var v struct {
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
		u, e := url.Parse(v.TGAPI)
		if e != nil || u.Scheme != "https" || u.Host == "" {
			fail(w, 400, "Bot API URL must use HTTPS")
			return
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
	id, e := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/"+a.secretPath+"/api/history/"), 10, 64)
	if e != nil {
		fail(w, 400, "id")
		return
	}
	hours := 24
	since := time.Now().Add(-24 * time.Hour).Unix()
	if n, e := strconv.Atoi(r.URL.Query().Get("hours")); e == nil && n >= 1 && n <= 2160 {
		hours = n
		since = time.Now().Add(-time.Duration(n) * time.Hour).Unix()
	}
	bucket := int64(hours * 3600 / 60)
	if bucket < 60 {
		bucket = 60
	}
	rows, e := a.db.Query("SELECT (ts / ?) * ?, SUM(up), SUM(down) FROM samples WHERE route_id=? AND ts>=? GROUP BY 1 ORDER BY 1", bucket, bucket, id, since)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	defer rows.Close()
	out := [][3]int64{}
	for rows.Next() {
		var t, u, d int64
		if rows.Scan(&t, &u, &d) == nil {
			out = append(out, [3]int64{t, u, d})
		}
	}
	writeJSON(w, 200, out)
}
