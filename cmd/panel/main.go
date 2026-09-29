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
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

type Route struct {
	MeterID      string `json:"-"`
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
	Monitor      bool   `json:"monitor"`
}

type Period struct {
	Key                          string
	Used, Extra                  int64
	ThresholdSent, ExhaustedSent bool
}
type retiredPeriod struct {
	Period
	reserved int64
}
type RouteState struct {
	Route                          Route
	Daily, Monthly                 Period
	mu                             sync.Mutex
	Listener                       net.Listener
	conns                          map[net.Conn]struct{}
	upBucket, downBucket           bucket
	pendingUp, pendingDown         int64
	lastUp, lastDown               int64
	healthy                        bool
	unhealthySince                 time.Time
	alertSent                      bool
	reservedDaily, reservedMonthly int64
	savedDaily, savedMonthly       Period
	savedUp, savedDown             int64
	rateUp, rateDown               int64
	rateAt                         time.Time
	rateHistory                    []trafficRateSample
	deleted                        bool
	retired                        map[string]retiredPeriod
}
type bucket struct {
	tokens float64
	last   time.Time
	rate   int64
}
type App struct {
	db                            *sql.DB
	data, web, secretPath, domain string
	tokenHash                     [32]byte
	master                        []byte
	location                      *time.Location
	routes                        map[int64]*RouteState
	deleting                      map[int64]*RouteState // accounting during transactional route deletion
	mu                            sync.RWMutex
	fallback                      string
	tg                            TelegramSettings
	configMu                      sync.Mutex
	statsMu                       sync.RWMutex
	lastStats                     map[int64]requestCounter
	liveStats                     map[int64]RequestStats
	lastStatsAt                   time.Time
	financeMu                     sync.Mutex
	restoreMu                     sync.Mutex
	start                         time.Time
	flushInterval                 time.Duration
	maxConnections                int
	relayAdmitted                 atomic.Int64
	relayRejected                 atomic.Uint64
	relayIngress                  internalTLSIngress
	proxyMode                     string // protected by mu; empty means relay (old installs)
	directLimits                  bool   // explicit opt-in, protected by mu
	direct                        directMeter
	restartRequested              atomic.Bool
	restartService                func()
	directLastOK                  atomic.Int64
	directErrors                  atomic.Uint64
	publicProbe                   publicProbeState
	publicConnections, publicPeak atomic.Int64
	// stateMu serializes control-plane changes and persistence, never relay I/O.
	stateMu              sync.Mutex
	collectMu            sync.Mutex
	closing              atomic.Bool
	listenersWG, relayWG sync.WaitGroup
	fallbackListener     net.Listener
	fallbackConns        sync.Map
	exportBusy           atomic.Bool
	history              historyCache
	historyEpoch         atomic.Uint64
	flushLastOK          atomic.Int64
	flushLastNS          atomic.Int64
	flushErrors          atomic.Uint64
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
	if len(os.Args) == 2 && os.Args[1] == "--watchdog" {
		log.SetPrefix("quota watchdog: ")
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		directWatchdog(ctx, env("PANEL_DATA", "/data"))
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--diagnose" {
		if err := printDiagnostics(os.Stdout); err != nil {
			log.Print(err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--healthcheck" {
		if err := checkPanelHealth(); err != nil {
			log.Print(err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 1 {
		fatal(supervise())
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--web" {
		fatal(runWeb())
		return
	}
	if len(os.Args) != 2 || os.Args[1] != "--agent" {
		log.Fatal("supported options: --healthcheck, --diagnose, --web, --agent")
	}
	log.SetPrefix("agent: ")
	data, err := filepath.Abs(env("PANEL_DATA", "./data"))
	fatal(err)
	fatal(os.MkdirAll(data, 0700))
	lock, err := lockAgent(data)
	fatal(err)
	defer lock.Close()
	fatal(applyPendingRestore(data))
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
	fatal(migrateRouteMonitor(db))
	token := os.Getenv("PANEL_TOKEN")
	master := os.Getenv("PANEL_MASTER_KEY")
	if len(token) < 24 || len(master) < 24 {
		log.Fatal("PANEL_TOKEN and PANEL_MASTER_KEY must each have at least 24 characters")
	}
	var timezone string
	if db.QueryRow("SELECT value FROM settings WHERE key='timezone'").Scan(&timezone) != nil {
		timezone = env("PANEL_TIMEZONE", "UTC")
	}
	loc, err := time.LoadLocation(timezone)
	fatal(err)
	a := &App{db: db, data: data, web: env("PANEL_WEB", "./web/dist"), secretPath: strings.Trim(env("PANEL_SECRET_PATH", "admin"), "/"), domain: strings.ToLower(env("PANEL_DOMAIN", "proxy.local.invalid")), tokenHash: sha256.Sum256([]byte(token)), master: []byte(master), location: loc, routes: map[int64]*RouteState{}, start: time.Now()}
	a.domain = a.getSetting("domain", a.domain)
	a.proxyMode = a.getSetting("proxy_mode", "relay")
	limitSetting := a.getSetting("direct_limits", "false")
	if limitSetting != "false" && limitSetting != "true" {
		log.Fatal("invalid direct_limits setting")
	}
	a.directLimits = limitSetting == "true"
	if !validProxyMode(a.proxyMode) {
		log.Fatal("invalid proxy_mode setting")
	}
	a.flushInterval, err = time.ParseDuration(env("PANEL_FLUSH_INTERVAL", "5s"))
	fatal(err)
	if a.flushInterval < time.Second || a.flushInterval > time.Minute {
		log.Fatal("PANEL_FLUSH_INTERVAL must be between 1s and 1m")
	}
	a.maxConnections, err = parseMaxConnections(env("PANEL_MAX_CONNECTIONS", strconv.Itoa(defaultMaxConnections)))
	fatal(err)
	if !validDomain(a.domain) {
		log.Fatal("invalid PANEL_DOMAIN")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{3,64}$`).MatchString(a.secretPath) {
		log.Fatal("PANEL_SECRET_PATH must be 3–64 letters, digits, underscore, or dash")
	}
	a.fallback = a.getSetting("fallback_html", `<!doctype html><html><head><meta charset="utf-8"><title>Welcome</title></head><body><h1>Welcome</h1></body></html>`)
	a.tg = TelegramSettings{APIURL: a.getSetting("tg_api", "https://api.telegram.org"), BotToken: a.decrypt(a.getSetting("tg_token", "")), ChatID: a.getSetting("tg_chat", "")}
	fatal(a.initFinance())
	fatal(a.initRequestStats())
	fatal(a.initDirectMeter())
	fatal(a.initHistoryIndexes())
	a.liveStats = map[int64]RequestStats{}
	fatal(a.ensureCert("fallback", a.domain))
	fatal(a.loadRoutes())
	fatal(a.writeConfig())
	fatal(a.startListeners())
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	a.restartService = stop
	tickDone := make(chan struct{})
	go func() { defer close(tickDone); a.tick(ctx) }()
	go a.serveFallback()
	server := a.adminServer()
	listener, err := listenAgent(data)
	fatal(err)
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("panel: %v", err)
			stop()
		}
	}()
	<-ctx.Done()
	a.closing.Store(true)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
	}
	a.stopRelays()
	<-tickDone
	if a.restartRequested.Load() {
		a.quiesceHAProxy()
	}
	a.collectDirectTraffic(time.Now())
	if err := a.flushTraffic(time.Now()); err != nil {
		log.Printf("final traffic flush: %v", err)
	}
	a.closeDirectMeter()
	if a.restartRequested.Load() {
		// Only the HAProxy supervisor reads this marker. No Docker socket or
		// privileged shell is exposed to the HTTP panel.
		fatal(os.WriteFile(filepath.Join(a.data, "haproxy.restart-request"), []byte("restart\n"), 0600))
	}
	fatal(db.Close())
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
func migrateRouteMonitor(db *sql.DB) error {
	rows, err := db.Query("PRAGMA table_info(routes)")
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid, notnull, pk int
		var name, kind string
		var def sql.NullString
		if rows.Scan(&cid, &name, &kind, &notnull, &def, &pk) == nil && name == "monitor" {
			found = true
		}
	}
	rows.Close()
	if found {
		return nil
	}
	_, err = db.Exec("ALTER TABLE routes ADD COLUMN monitor INTEGER NOT NULL DEFAULT 0")
	return err
}
func (a *App) loadRoutes() error {
	rows, err := a.db.Query("SELECT id,name,sni,ip,port,tls,verify,verify_name,paused,daily_limit,monthly_limit,count_mode,down_bps,up_bps,threshold,created_at,up_total,down_total,monitor FROM routes")
	if err != nil {
		return err
	}
	loaded := []*RouteState{}
	for rows.Next() {
		var r Route
		var t, v, p, monitor int
		err = rows.Scan(&r.ID, &r.Name, &r.SNI, &r.IP, &r.Port, &t, &v, &r.VerifyName, &p, &r.DailyLimit, &r.MonthlyLimit, &r.CountMode, &r.DownBPS, &r.UpBPS, &r.Threshold, &r.CreatedAt, &r.UpTotal, &r.DownTotal, &monitor)
		if err != nil {
			_ = rows.Close()
			return err
		}
		r.TLS = t != 0
		r.Verify = v != 0
		r.Paused = p != 0
		r.Monitor = monitor != 0
		s := &RouteState{Route: r, conns: map[net.Conn]struct{}{}}
		loaded = append(loaded, s)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	for _, s := range loaded {
		if err := a.ensureMeterID(&s.Route); err != nil {
			return err
		}
		if err := a.refreshPeriods(s, time.Now()); err != nil {
			return err
		}
		s.savedUp, s.savedDown = s.Route.UpTotal, s.Route.DownTotal
		s.savedDaily, s.savedMonthly = s.Daily, s.Monthly
		s.rateUp, s.rateDown, s.rateAt = s.Route.UpTotal, s.Route.DownTotal, time.Now()
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
func (a *App) loadPeriod(id int64, kind, key string) (Period, error) {
	p := Period{Key: key}
	var t, e int
	err := a.db.QueryRow("SELECT used,extra,threshold_sent,exhausted_sent FROM periods WHERE route_id=? AND kind=? AND key=?", id, kind, key).Scan(&p.Used, &p.Extra, &t, &e)
	if err != nil && err != sql.ErrNoRows {
		return Period{}, err
	}
	p.ThresholdSent = t != 0
	p.ExhaustedSent = e != 0
	return p, nil
}

// Only used before a route is published; live rollovers use rollPeriods.
func (a *App) refreshPeriods(s *RouteState, now time.Time) error {
	dk := a.periodKey(s.Route, "daily", now)
	mk := a.periodKey(s.Route, "monthly", now)
	var err error
	if s.Daily.Key != dk {
		old := s.Daily.Key
		s.Daily, err = a.loadPeriod(s.Route.ID, "daily", dk)
		if err != nil {
			return err
		}
		if old != "" && s.Route.DailyLimit > 0 {
			go a.notify(s.Route, quotaResetMessage("daily", s.Route.DailyLimit+s.Daily.Extra))
		}
	}
	if s.Monthly.Key != mk {
		old := s.Monthly.Key
		s.Monthly, err = a.loadPeriod(s.Route.ID, "monthly", mk)
		if err != nil {
			return err
		}
		if old != "" && s.Route.MonthlyLimit > 0 {
			go a.notify(s.Route, quotaResetMessage("monthly", s.Route.MonthlyLimit+s.Monthly.Extra))
		}
	}
	return nil
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
	if existing, err := os.ReadFile(path); err == nil {
		if block, _ := pem.Decode(existing); block != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil && time.Now().Before(cert.NotAfter) {
				for _, san := range cert.DNSNames {
					if san == domain {
						return nil
					}
				}
			}
		}
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
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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
		for attempt := 0; attempt < 3; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			req, _ := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(tg.APIURL, "/")+"/bot"+tg.BotToken+"/sendMessage", strings.NewReader(body.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := http.DefaultClient.Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			cancel()
			if err == nil && resp.StatusCode < 300 {
				return
			}
			if err != nil {
				// net/http errors can contain the complete URL and bot token.
				log.Printf("telegram request failed (%T)", err)
			} else {
				log.Printf("telegram: %s", resp.Status)
			}
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
	}()
}
