package main

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

func validProxyMode(mode string) bool { return mode == "relay" || mode == "direct" }
func (a *App) directMode() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.proxyMode == "direct"
}
func routeBackend(r Route, direct bool) string {
	if direct {
		return fmt.Sprintf("direct_%d_%s", r.ID, r.MeterID)
	}
	return fmt.Sprintf("target_%d", r.ID)
}

// Independent identities prevent a draining worker's counters from being
// attributed to a new route when SQLite reuses a deleted integer route ID.
func (a *App) ensureMeterID(r *Route) error {
	if _, err := a.db.Exec(`CREATE TABLE IF NOT EXISTS route_meter_ids(route_id INTEGER PRIMARY KEY, token TEXT NOT NULL)`); err != nil {
		return err
	}
	if _, err := a.db.Exec(`INSERT INTO route_meter_ids(route_id,token) VALUES(?,lower(hex(randomblob(16)))) ON CONFLICT(route_id) DO NOTHING`, r.ID); err != nil {
		return err
	}
	if err := a.db.QueryRow("SELECT token FROM route_meter_ids WHERE route_id=?", r.ID).Scan(&r.MeterID); err != nil {
		return err
	}
	decoded, err := hex.DecodeString(r.MeterID)
	if err != nil || len(decoded) != 16 {
		return fmt.Errorf("invalid route meter identity")
	}
	return nil
}

type directKey struct{ worker, backend string }
type directCounter struct{ up, down, seen int64 }
type directMeter struct {
	mu            sync.Mutex // socket operations only; never held by relay traffic
	workers       map[string]*meterWorker
	lastErrorLog  time.Time
	lastReloadAck string
	recoverOld    bool
	// These maps are protected by stateMu. Checkpoints are committed in the
	// SAME transaction as totals/samples, so a panel restart cannot double bill.
	last    map[directKey]directCounter
	pending map[directKey]directCounter
}
type meterWorker struct {
	conn        net.Conn
	reader      *bufio.Reader
	key         string
	stopping    bool
	connections int64
	activated   bool
}

func (a *App) initDirectMeter() error {
	_, err := a.db.Exec(`CREATE TABLE IF NOT EXISTS direct_checkpoints(worker TEXT NOT NULL,backend TEXT NOT NULL,up INTEGER NOT NULL,down INTEGER NOT NULL,seen INTEGER NOT NULL,PRIMARY KEY(worker,backend));
CREATE INDEX IF NOT EXISTS direct_checkpoints_seen ON direct_checkpoints(seen);
CREATE TABLE IF NOT EXISTS route_meter_ids(route_id INTEGER PRIMARY KEY,token TEXT NOT NULL);`)
	if err != nil {
		return err
	}
	rows, err := a.db.Query("SELECT worker,backend,up,down,seen FROM direct_checkpoints")
	if err != nil {
		return err
	}
	defer rows.Close()
	a.direct.last = map[directKey]directCounter{}
	a.direct.pending = map[directKey]directCounter{}
	for rows.Next() {
		var k directKey
		var v directCounter
		if err := rows.Scan(&k.worker, &k.backend, &v.up, &v.down, &v.seen); err != nil {
			return err
		}
		a.direct.last[k] = v
	}
	a.direct.recoverOld = len(a.direct.last) > 0
	return rows.Err()
}

// An interactive Runtime API connection keeps a softly stopped worker alive.
// Keep it until its last client has drained AND its final counters are saved.
// A crash/hard-stop can still lose the unobserved tail; this is not a billing WAL.
func openMeterWorker(path string) (*meterWorker, error) {
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return nil, err
	}
	w := &meterWorker{conn: c, reader: bufio.NewReader(c)}
	if _, err = w.command("prompt"); err == nil {
		err = w.info()
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	return w, nil
}
func (w *meterWorker) command(command string) ([]byte, error) {
	_ = w.conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(w.conn, command+"\n"); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	for out.Len() < 8<<20 {
		b, err := w.reader.ReadByte()
		if err != nil {
			return nil, err
		}
		out.WriteByte(b)
		if bytes.HasSuffix(out.Bytes(), []byte("\n> ")) {
			return bytes.TrimSuffix(out.Bytes(), []byte("\n> ")), nil
		}
	}
	return nil, fmt.Errorf("HAProxy runtime response exceeds limit")
}
func (w *meterWorker) info() error {
	raw, err := w.command("show info")
	if err != nil {
		return err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok {
			values[k] = strings.TrimSpace(v)
		}
	}
	pid, e1 := strconv.ParseInt(values["Pid"], 10, 64)
	start, e2 := strconv.ParseInt(values["Start_time_sec"], 10, 64)
	if e1 != nil || e2 != nil || pid <= 0 || start <= 0 {
		return fmt.Errorf("HAProxy lacks worker identity (requires 3.2)")
	}
	w.key = fmt.Sprintf("%s/%d/%d", values["node"], start, pid)
	w.stopping = values["Stopping"] == "1"
	w.connections = parseCounter(values["CurrConns"])
	return nil
}

func parseDirectStats(raw []byte) (map[string]directCounter, error) {
	r := csv.NewReader(bytes.NewReader(raw))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("empty HAProxy stats")
	}
	index := map[string]int{}
	for i, k := range rows[0] {
		index[strings.TrimSpace(strings.TrimPrefix(k, "# "))] = i
	}
	for _, k := range []string{"pxname", "svname", "bin", "bout"} {
		if _, ok := index[k]; !ok {
			return nil, fmt.Errorf("missing HAProxy field %s", k)
		}
	}
	field := func(row []string, k string) string {
		i := index[k]
		if i >= len(row) {
			return ""
		}
		return row[i]
	}
	out := map[string]directCounter{}
	for _, row := range rows[1:] {
		name := field(row, "pxname")
		if field(row, "svname") != "BACKEND" || !strings.HasPrefix(name, "direct_") {
			continue
		}
		parts := strings.Split(name, "_")
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid direct backend identity")
		}
		id, e := strconv.ParseInt(parts[1], 10, 64)
		token, te := hex.DecodeString(parts[2])
		if e != nil || id <= 0 || id > 55535 || te != nil || len(token) != 16 {
			return nil, fmt.Errorf("invalid direct backend identity")
		}
		up, e1 := strconv.ParseInt(field(row, "bin"), 10, 64)
		down, e2 := strconv.ParseInt(field(row, "bout"), 10, 64)
		if e1 != nil || e2 != nil || up < 0 || down < 0 {
			return nil, fmt.Errorf("invalid HAProxy byte counter")
		}
		out[name] = directCounter{up: up, down: down}
	}
	return out, nil
}

func (a *App) observeDirect(worker string, observed map[string]directCounter, now time.Time) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if a.direct.last == nil {
		a.direct.last = map[directKey]directCounter{}
		a.direct.pending = map[directKey]directCounter{}
	}
	routes := map[string]*RouteState{}
	for _, s := range a.routeStates() {
		s.mu.Lock()
		routes[routeBackend(s.Route, true)] = s
		s.mu.Unlock()
	}
	for backend, current := range observed {
		k := directKey{worker, backend}
		previous := a.direct.last[k]
		if current.up == previous.up && current.down == previous.down && now.Unix()-previous.seen < 60 {
			continue
		}
		up, down := deltaCounter(current.up, previous.up), deltaCounter(current.down, previous.down)
		if s := routes[backend]; s != nil {
			s.mu.Lock()
			s.Route.UpTotal += up
			s.Route.DownTotal += down
			s.pendingUp += up
			s.pendingDown += down
			var counted int64
			if s.counted(true) {
				counted += up
			}
			if s.counted(false) {
				counted += down
			}
			s.Daily.Used += counted
			s.Monthly.Used += counted
			s.mu.Unlock()
		}
		current.seen = now.Unix()
		a.direct.last[k] = current
		a.direct.pending[k] = current
	}
}

func (a *App) allowedDirectBackends() map[string]bool {
	allowed := map[string]bool{}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.proxyMode == "direct" {
		for _, s := range a.routes {
			s.mu.Lock()
			allowed[routeBackend(s.Route, true)] = !s.Route.Paused
			s.mu.Unlock()
		}
	}
	return allowed
}

func (a *App) collectDirectTraffic(now time.Time) {
	a.direct.mu.Lock()
	defer a.direct.mu.Unlock()
	if a.direct.workers == nil {
		a.direct.workers = map[string]*meterWorker{}
	}
	report := func(err error) {
		a.directErrors.Add(1)
		if now.Sub(a.direct.lastErrorLog) >= time.Minute {
			log.Printf("direct traffic collection: %v", err)
			a.direct.lastErrorLog = now
		}
	}
	requestPath := filepath.Join(a.data, "haproxy.reload-request")
	reloadRequest, _ := os.ReadFile(requestPath)
	// Connect before inspecting the old worker: this pins every observed
	// generation, even if its last client closes during a config reload.
	current, err := openMeterWorker(filepath.Join(a.data, "haproxy.sock"))
	currentKey := ""
	if err == nil {
		currentKey = current.key
	}
	if err != nil {
		if a.directMode() {
			report(err)
		}
	} else if _, ok := a.direct.workers[current.key]; ok {
		current.conn.Close()
	} else {
		a.direct.workers[current.key] = current
	}
	for key, w := range a.direct.workers {
		if err = w.info(); err != nil {
			w.conn.Close()
			delete(a.direct.workers, key)
			report(err)
			continue
		}
		raw, e := w.command("show stat")
		var observed map[string]directCounter
		if e == nil {
			observed, e = parseDirectStats(raw)
		}
		if e != nil {
			w.conn.Close()
			delete(a.direct.workers, key)
			report(e)
			continue
		}
		if key == currentKey {
			a.directLastOK.Store(now.Unix())
		}
		a.observeDirect(key, observed, now)
		if !w.activated && !w.stopping && bytes.Contains(raw, []byte("public_direct,FRONTEND,")) && a.directMode() {
			for _, s := range a.routeStates() {
				a.closeRouteConns(s)
			}
			w.activated = true
		}
		// Pause/delete and returning to relay also terminate old direct tunnels.
		// No quota enforcement is attempted in direct mode.
		allowed := a.allowedDirectBackends()
		for backend := range observed {
			if !allowed[backend] {
				_, _ = w.command("set server " + backend + "/target state maint")
				_, _ = w.command("shutdown sessions server " + backend + "/target")
			}
		}
		if w.stopping && w.connections == 0 {
			if e = a.flushTraffic(now); e != nil {
				report(e)
				continue
			}
			w.conn.Close()
			delete(a.direct.workers, key)
		}
	}
	if a.direct.recoverOld {
		a.recoverDirectWorkers(now, report)
	}
	_, pinned := a.direct.workers[currentKey]
	if !pinned && !a.directMode() {
		// Keep legacy relay-only/native installations reloadable. Only direct
		// mode requires Start_time_sec; never use this fallback for direct data.
		if raw, e := haproxyCommand(filepath.Join(a.data, "haproxy.sock"), "show stat"); e == nil && bytes.Contains(raw, []byte("public_sni,FRONTEND,")) && !bytes.Contains(raw, []byte("direct_")) {
			pinned = true
		}
	}
	if pinned && len(reloadRequest) > 0 && string(reloadRequest) != a.direct.lastReloadAck {
		ack := filepath.Join(a.data, "haproxy.reload-ready")
		if err := os.WriteFile(ack+".tmp", reloadRequest, 0600); err == nil {
			if os.Rename(ack+".tmp", ack) == nil {
				a.direct.lastReloadAck = string(reloadRequest)
			}
		}
	}
}

// After a PANEL-only restart, old workers can outlive the panel's guard
// connections. Recover their remaining counters through the master CLI. The
// normal reload handshake pins workers; recovery polling has a bounded tail
// loss if an old worker exits between polls while the panel was restarting.
func (a *App) recoverDirectWorkers(now time.Time, report func(error)) {
	path := filepath.Join(a.data, "haproxy-master.sock")
	if a.data == "/var/lib/fluxgate" {
		path = "/run/fluxgate/haproxy-master.sock"
	}
	path = env("PANEL_HAPROXY_MASTER_SOCKET", path)
	raw, err := haproxyCommand(path, "show proc")
	if err != nil {
		report(err)
		return
	}
	old, remaining := false, false
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "# old workers") {
			old = true
			continue
		}
		if !old || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 || f[1] != "worker" {
			continue
		}
		pid, e := strconv.Atoi(f[0])
		if e != nil || pid <= 0 {
			continue
		}
		known := false
		for key := range a.direct.workers {
			if strings.HasSuffix(key, "/"+f[0]) {
				known = true
				break
			}
		}
		if known {
			continue
		}
		remaining = true
		prefix := "@!" + f[0] + " "
		info, e := haproxyCommand(path, prefix+"show info")
		if e != nil {
			report(e)
			continue
		}
		values := map[string]string{}
		for _, l := range strings.Split(string(info), "\n") {
			k, v, ok := strings.Cut(l, ":")
			if ok {
				values[k] = strings.TrimSpace(v)
			}
		}
		start, e := strconv.ParseInt(values["Start_time_sec"], 10, 64)
		if e != nil {
			continue
		}
		stats, e := haproxyCommand(path, prefix+"show stat")
		if e != nil {
			report(e)
			continue
		}
		observed, e := parseDirectStats(stats)
		if e != nil {
			continue
		}
		a.observeDirect(fmt.Sprintf("%s/%d/%d", values["node"], start, pid), observed, now)
		// Return-to-relay/pause/delete must also apply to these older workers.
		allowed := a.allowedDirectBackends()
		for backend := range observed {
			if !allowed[backend] || a.restartRequested.Load() {
				_, _ = haproxyCommand(path, prefix+"set server "+backend+"/target state maint")
				_, _ = haproxyCommand(path, prefix+"shutdown sessions server "+backend+"/target")
			}
		}
	}
	a.direct.recoverOld = remaining
}

// Caller holds stateMu. Checkpoints and route totals must never be committed
// separately, including on backup and graceful shutdown.
func (a *App) saveDirectCheckpoints(tx *sql.Tx, now time.Time) error {
	for k, v := range a.direct.pending {
		_, err := tx.Exec(`INSERT INTO direct_checkpoints(worker,backend,up,down,seen) VALUES(?,?,?,?,?) ON CONFLICT(worker,backend) DO UPDATE SET up=excluded.up,down=excluded.down,seen=excluded.seen`, k.worker, k.backend, v.up, v.down, v.seen)
		if err != nil {
			return err
		}
	}
	if len(a.direct.pending) > 0 {
		_, err := tx.Exec("DELETE FROM direct_checkpoints WHERE seen<?", now.Add(-48*time.Hour).Unix())
		return err
	}
	return nil
}
func (a *App) closeDirectMeter() {
	a.direct.mu.Lock()
	defer a.direct.mu.Unlock()
	for key, w := range a.direct.workers {
		w.conn.Close()
		delete(a.direct.workers, key)
	}
}
