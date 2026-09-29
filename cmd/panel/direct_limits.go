package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const directLeaseTimeout = 10 * time.Second

func (a *App) persistenceFresh(now time.Time) bool {
	last := time.Unix(a.flushLastOK.Load(), 0)
	if a.flushLastOK.Load() == 0 {
		last = a.start
	}
	return !last.IsZero() && now.Sub(last) <= max(30*time.Second, 3*a.flushInterval)
}

func (a *App) directPolicy() (quota, rate map[string]bool) {
	quota, rate = map[string]bool{}, map[string]bool{}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.proxyMode != "direct" || !a.directLimits {
		return
	}
	for _, s := range a.routes {
		s.mu.Lock()
		r := s.Route
		s.mu.Unlock()
		key := routeBackend(r, true)
		quota[key] = r.DailyLimit > 0 || r.MonthlyLimit > 0
		rate[key] = r.DownBPS > 0 || r.UpBPS > 0
	}
	return
}

func enforceDirectBackend(command func(string) ([]byte, error), backend string, blocked bool) error {
	state := "ready"
	if blocked {
		state = "maint"
	}
	commands := []string{"set server " + backend + "/target state " + state}
	if blocked {
		commands = append(commands, "shutdown sessions server "+backend+"/target")
	}
	var result error
	stopped := false
	for _, cmd := range commands {
		out, err := command(cmd)
		if err != nil {
			result = err
			continue
		}
		reply := strings.TrimSpace(string(out))
		if blocked && reply == "Proxy is disabled." {
			// HAProxy rejects server commands on softly stopped backends,
			// even while their established streams are still forwarding.
			stopped = true
		} else if reply != "" {
			result = fmt.Errorf("HAProxy refused quota command: %.200q", reply)
		}
	}
	if stopped {
		result = errors.Join(result, shutdownStoppedStreams(command, backend))
	}
	return result
}

// Used only when HAProxy reports a stopped backend. Its listener no longer
// accepts clients, but upgraded streams must still be terminated explicitly.
// Fetch the short, backend-filtered list; never log addresses or request data.
func shutdownStoppedStreams(command func(string) ([]byte, error), backend string) error {
	raw, err := command("show sess backend " + backend)
	if err != nil {
		return err
	}
	ids, err := stoppedStreamIDs(raw, backend)
	if err != nil {
		return err
	}
	// Keep each CLI request below the default HAProxy input buffer. At 100k
	// streams, one socket round-trip per ID would stall quota enforcement.
	for start := 0; start < len(ids); start += 64 {
		end := min(start+64, len(ids))
		commands := make([]string, 0, end-start)
		for _, id := range ids[start:end] {
			commands = append(commands, "shutdown session "+id)
		}
		out, err := command(strings.Join(commands, ";"))
		if err != nil {
			return err
		}
		// A stream can close naturally between the snapshot and command.
		for _, reply := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if reply = strings.TrimSpace(reply); reply != "" && reply != "No such session (use 'show sess')." {
				return fmt.Errorf("HAProxy refused stopped-stream shutdown")
			}
		}
	}
	return nil
}

func stoppedStreamIDs(raw []byte, backend string) ([]string, error) {
	var ids []string
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		id := strings.TrimSuffix(fields[0], ":")
		n, err := strconv.ParseUint(strings.TrimPrefix(id, "0x"), 16, 64)
		if err != nil || n == 0 || !strings.HasPrefix(id, "0x") || !strings.HasSuffix(fields[0], ":") {
			return nil, fmt.Errorf("invalid HAProxy stream identifier")
		}
		matched := false
		for _, f := range fields[1:] {
			if f == "be="+backend {
				matched = true
			}
		}
		if !matched {
			return nil, fmt.Errorf("HAProxy stream does not match requested backend")
		}
		ids = append(ids, id)
	}
	return ids, nil
}

type directLease struct {
	Stats     int64 `json:"stats"`
	Persisted bool  `json:"persisted"`
}

func (a *App) directLeaseAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	writeJSON(w, 200, directLease{a.directLastOK.Load(), a.persistenceFresh(time.Now())})
}

// The independent watchdog never opens SQLite. When the agent stops making
// progress, shut down quota-bearing direct routes through HAProxy's Runtime API.
// This is a soft-quota safety net, not a byte-accurate in-path enforcement point.
func directWatchdog(ctx context.Context, data string) {
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", agentSocket(data))
	}}}
	defer client.CloseIdleConnections()
	policies := map[string]bool{}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var lastLog time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		cfg, err := os.ReadFile(filepath.Join(data, "haproxy.cfg"))
		if err == nil {
			currentPolicy := map[string]bool{}
			for _, line := range strings.Split(string(cfg), "\n") {
				f := strings.Fields(line)
				if len(f) == 3 && f[0] == "#" && f[1] == "fluxgate-quota" {
					currentPolicy[f[2]] = true
				}
			}
			// Removing a limit is an explicit opt-out, including on old workers.
			// Do not retain stale policies indefinitely after that change.
			policies = currentPolicy
		}
		if len(policies) == 0 {
			continue
		}
		healthy := false
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://agent/internal/lease", nil)
		if res, err := client.Do(req); err == nil {
			var lease directLease
			if json.NewDecoder(io.LimitReader(res.Body, 1024)).Decode(&lease) == nil && res.StatusCode == 200 {
				healthy = lease.Persisted && lease.Stats > 0 && time.Since(time.Unix(lease.Stats, 0)) <= directLeaseTimeout
			}
			res.Body.Close()
		}
		if healthy {
			continue
		}
		if err := stopStaleDirect(data, policies); err != nil && time.Since(lastLog) > time.Minute {
			log.Printf("direct quota watchdog: %v", err)
			lastLog = time.Now()
		}
	}
}

func masterSocket(data string) string {
	path := filepath.Join(data, "haproxy-master.sock")
	if data == "/var/lib/fluxgate" {
		path = "/run/fluxgate/haproxy-master.sock"
	}
	return env("PANEL_HAPROXY_MASTER_SOCKET", path)
}

func stopStaleDirect(data string, policy map[string]bool) error {
	// Use the master CLI so draining generations are covered too.
	path := masterSocket(data)
	raw, err := haproxyCommand(path, "show proc")
	if err != nil {
		return err
	}
	var result error
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[1] != "worker" {
			continue
		}
		// IDs are parsed before they can become CLI commands.
		pid, err := strconv.Atoi(fields[0])
		if err != nil || pid <= 0 {
			continue
		}
		prefix := fmt.Sprintf("@!%d ", pid)
		stats, err := haproxyCommand(path, prefix+"show stat")
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		backends, err := parseDirectStats(stats)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		for backend := range backends {
			if !policy[backend] {
				continue
			}
			command := func(s string) ([]byte, error) { return haproxyCommand(path, workerCommands(prefix, s)) }
			if err := enforceDirectBackend(command, backend, true); err != nil {
				// One disappearing generation must not prevent protection of
				// the other workers/routes. Retry failures on the next tick.
				result = errors.Join(result, err)
			}
		}
	}
	return result
}
