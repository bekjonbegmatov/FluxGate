package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Route struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	SNI          string `json:"sni"`
	IP           string `json:"ip"`
	Port         int    `json:"port"`
	TLS          bool   `json:"tls"`
	Verify       bool   `json:"verify"`
	VerifyName   string `json:"verify_name"`
	Paused       bool   `json:"paused"`
	DailyLimit   int64  `json:"daily_limit"`
	MonthlyLimit int64  `json:"monthly_limit"`
	CountMode    string `json:"count_mode"`
	DownBPS      int64  `json:"down_bps"`
	UpBPS        int64  `json:"up_bps"`
	Threshold    int    `json:"threshold"`
	CreatedAt    int64  `json:"created_at"`
	Status       string `json:"status"`
	UpTotal      int64  `json:"up_total"`
	DownTotal    int64  `json:"down_total"`
	DailyUsed    int64  `json:"daily_used"`
	DailyExtra   int64  `json:"daily_extra"`
	MonthlyUsed  int64  `json:"monthly_used"`
	MonthlyExtra int64  `json:"monthly_extra"`
	UpRate       int64  `json:"up_rate"`
	DownRate     int64  `json:"down_rate"`
}

type Period struct {
	Key                          string
	Used, Extra                  int64
	ThresholdSent, ExhaustedSent bool
}
type RouteState struct {
	Route                  Route
	Daily, Monthly         Period
	mu                     sync.Mutex
	Listener               net.Listener
	conns                  map[net.Conn]struct{}
	upBucket, downBucket   bucket
	pendingUp, pendingDown int64
	lastUp, lastDown       int64
	healthy                bool
}
type bucket struct {
	tokens float64
	last   time.Time
}
type App struct {
	db                            *sql.DB
	data, web, secretPath, domain string
	tokenHash                     [32]byte
	master                        []byte
	location                      *time.Location
	routes                        map[int64]*RouteState
	mu                            sync.RWMutex
	fallback                      string
	tg                            TelegramSettings
	configMu                      sync.Mutex
	start                         time.Time
}
type TelegramSettings struct{ APIURL, BotToken, ChatID string }

func env(key, def string) string {
	if s := os.Getenv(key); s != "" {
		return s
	}
	return def
}
func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
func main() {
	data := env("PANEL_DATA", "./data")
	fatal(os.MkdirAll(filepath.Join(data, "certs"), 0700))
	db, err := sql.Open("sqlite", filepath.Join(data, "panel.db"))
	fatal(err)
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
 CREATE TABLE IF NOT EXISTS routes(id INTEGER PRIMARY KEY, name TEXT NOT NULL, sni TEXT NOT NULL UNIQUE, ip TEXT NOT NULL, port INTEGER NOT NULL, tls INTEGER NOT NULL, verify INTEGER NOT NULL, verify_name TEXT NOT NULL, paused INTEGER NOT NULL, daily_limit INTEGER NOT NULL, monthly_limit INTEGER NOT NULL, count_mode TEXT NOT NULL, down_bps INTEGER NOT NULL, up_bps INTEGER NOT NULL, threshold INTEGER NOT NULL, created_at INTEGER NOT NULL, up_total INTEGER NOT NULL DEFAULT 0, down_total INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS periods(route_id INTEGER NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0, extra INTEGER NOT NULL DEFAULT 0, threshold_sent INTEGER NOT NULL DEFAULT 0, exhausted_sent INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(route_id,kind,key));
 CREATE TABLE IF NOT EXISTS samples(route_id INTEGER NOT NULL, ts INTEGER NOT NULL, up INTEGER NOT NULL, down INTEGER NOT NULL, PRIMARY KEY(route_id,ts));
 CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);`)
	fatal(err)
	token := os.Getenv("PANEL_TOKEN")
	master := os.Getenv("PANEL_MASTER_KEY")
	if len(token) < 24 || len(master) < 24 {
		log.Fatal("PANEL_TOKEN and PANEL_MASTER_KEY must each have at least 24 characters")
	}
	loc, err := time.LoadLocation(env("PANEL_TIMEZONE", "UTC"))
	fatal(err)
	a := &App{db: db, data: data, web: env("PANEL_WEB", "./web/dist"), secretPath: strings.Trim(env("PANEL_SECRET_PATH", "secretpath"), "/"), domain: strings.ToLower(env("PANEL_DOMAIN", "site.example.com")), tokenHash: sha256.Sum256([]byte(token)), master: []byte(master), location: loc, routes: map[int64]*RouteState{}, start: time.Now()}
	if !validDomain(a.domain) {
		log.Fatal("invalid PANEL_DOMAIN")
	}
	a.fallback = a.getSetting("fallback_html", `<!doctype html><html><head><meta charset="utf-8"><title>Welcome</title></head><body><h1>Welcome</h1></body></html>`)
	a.tg = TelegramSettings{APIURL: a.getSetting("tg_api", "https://api.telegram.org"), BotToken: a.decrypt(a.getSetting("tg_token", "")), ChatID: a.getSetting("tg_chat", "")}
	fatal(a.ensureCert("fallback", a.domain))
	fatal(a.loadRoutes())
	fatal(a.writeConfig())
	fatal(a.startListeners())
	go a.tick()
	go a.serveFallback()
	a.serveAdmin()
}

func (a *App) getSetting(k, d string) string {
	var v string
	if a.db.QueryRow("SELECT value FROM settings WHERE key=?", k).Scan(&v) != nil {
		return d
	}
	return v
}
func (a *App) setSetting(k, v string) error {
	_, err := a.db.Exec("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", k, v)
	return err
}
func (a *App) encrypt(s string) string {
	if s == "" {
		return ""
	}
	key := sha256.Sum256(a.master)
	c, _ := aes.NewCipher(key[:])
	g, _ := cipher.NewGCM(c)
	n := make([]byte, g.NonceSize())
	_, _ = rand.Read(n)
	return base64.StdEncoding.EncodeToString(g.Seal(n, n, []byte(s), nil))
}
func (a *App) decrypt(s string) string {
	if s == "" {
		return ""
	}
	b, e := base64.StdEncoding.DecodeString(s)
	if e != nil {
		return ""
	}
	key := sha256.Sum256(a.master)
	c, _ := aes.NewCipher(key[:])
	g, _ := cipher.NewGCM(c)
	if len(b) < g.NonceSize() {
		return ""
	}
	p, e := g.Open(nil, b[:g.NonceSize()], b[g.NonceSize():], nil)
	if e != nil {
		return ""
	}
	return string(p)
}
func validDomain(s string) bool {
	return regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+$`).MatchString(s) && len(s) <= 253
}
func validSNI(s string) bool {
	if strings.HasPrefix(s, "*.") {
		return validDomain(s[2:])
	}
	return validDomain(s)
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func (a *App) loadRoutes() error {
	rows, err := a.db.Query("SELECT id,name,sni,ip,port,tls,verify,verify_name,paused,daily_limit,monthly_limit,count_mode,down_bps,up_bps,threshold,created_at,up_total,down_total FROM routes")
	if err != nil {
		return err
	}
	loaded := []*RouteState{}
	for rows.Next() {
		var r Route
		var t, v, p int
		err = rows.Scan(&r.ID, &r.Name, &r.SNI, &r.IP, &r.Port, &t, &v, &r.VerifyName, &p, &r.DailyLimit, &r.MonthlyLimit, &r.CountMode, &r.DownBPS, &r.UpBPS, &r.Threshold, &r.CreatedAt, &r.UpTotal, &r.DownTotal)
		if err != nil {
			_ = rows.Close()
			return err
		}
		r.TLS = t != 0
		r.Verify = v != 0
		r.Paused = p != 0
		s := &RouteState{Route: r, conns: map[net.Conn]struct{}{}}
		loaded = append(loaded, s)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	for _, s := range loaded {
		a.refreshPeriods(s, time.Now())
		a.routes[s.Route.ID] = s
	}
	return nil
}
func (a *App) periodKey(r Route, kind string, now time.Time) string {
	t := now.In(a.location)
	if kind == "daily" {
		return t.Format("2006-01-02")
	}
	created := time.Unix(r.CreatedAt, 0).In(a.location)
	anchor := created.Day()
	y, m, _ := t.Date()
	candidate := monthAnchor(y, m, anchor, a.location)
	if t.Before(candidate) {
		candidate = monthAnchor(y, m-1, anchor, a.location)
	}
	return candidate.Format("2006-01-02")
}
func monthAnchor(y int, m time.Month, d int, l *time.Location) time.Time {
	first := time.Date(y, m, 1, 0, 0, 0, 0, l)
	last := time.Date(y, m+1, 0, 0, 0, 0, 0, l).Day()
	if d > last {
		d = last
	}
	return time.Date(first.Year(), first.Month(), d, 0, 0, 0, 0, l)
}
func (a *App) loadPeriod(id int64, kind, key string) Period {
	p := Period{Key: key}
	var t, e int
	_ = a.db.QueryRow("SELECT used,extra,threshold_sent,exhausted_sent FROM periods WHERE route_id=? AND kind=? AND key=?", id, kind, key).Scan(&p.Used, &p.Extra, &t, &e)
	p.ThresholdSent = t != 0
	p.ExhaustedSent = e != 0
	return p
}
func (a *App) refreshPeriods(s *RouteState, now time.Time) bool {
	dk := a.periodKey(s.Route, "daily", now)
	mk := a.periodKey(s.Route, "monthly", now)
	changed := false
	if s.Daily.Key != dk {
		old := s.Daily.Key
		s.Daily = a.loadPeriod(s.Route.ID, "daily", dk)
		changed = true
		if old != "" {
			a.notify(s.Route, "Дневная квота сброшена")
		}
	}
	if s.Monthly.Key != mk {
		old := s.Monthly.Key
		s.Monthly = a.loadPeriod(s.Route.ID, "monthly", mk)
		changed = true
		if old != "" {
			a.notify(s.Route, "Месячная квота сброшена")
		}
	}
	return changed
}
func (s *RouteState) blocked() bool {
	r := s.Route
	return (r.DailyLimit > 0 && s.Daily.Used >= r.DailyLimit+s.Daily.Extra) || (r.MonthlyLimit > 0 && s.Monthly.Used >= r.MonthlyLimit+s.Monthly.Extra)
}
func (s *RouteState) counted(up bool) bool {
	return s.Route.CountMode == "both" || (up && s.Route.CountMode == "up") || (!up && s.Route.CountMode == "down")
}
func (a *App) ensureCert(name, domain string) error {
	path := filepath.Join(a.data, "certs", name+".pem")
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(2, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	if ip := net.ParseIP(domain); ip != nil {
		template.IPAddresses = []net.IP{ip}
		template.DNSNames = nil
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	out := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})...)
	return os.WriteFile(path, out, 0600)
}

func (a *App) serveFallback() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		a.mu.RLock()
		page := a.fallback
		a.mu.RUnlock()
		_, _ = io.WriteString(w, page)
	})
	log.Printf("fallback listening on 127.0.0.1:8181")
	log.Print(http.ListenAndServe("127.0.0.1:8181", mux))
}

func (a *App) notify(r Route, msg string) {
	a.mu.RLock()
	tg := a.tg
	a.mu.RUnlock()
	if tg.BotToken == "" || tg.ChatID == "" {
		return
	}
	go func() {
		body := url.Values{"chat_id": {tg.ChatID}, "text": {fmt.Sprintf("%s (%s): %s", r.Name, r.SNI, msg)}}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(tg.APIURL, "/")+"/bot"+tg.BotToken+"/sendMessage", strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("telegram: %v", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			log.Printf("telegram: %s", resp.Status)
		}
	}()
}

var _ = errors.New
var _ = html.EscapeString
var _ = sort.Slice
var _ = strconv.Itoa
var _ = sync.Mutex{}
