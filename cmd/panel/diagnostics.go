package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Bounded, including a short stream list at the configured 20k-client maximum.
const maxRuntimeResponse = 32 << 20

func haproxyCommand(path, command string) ([]byte, error) {
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = io.WriteString(c, command+"\n"); err != nil {
		return nil, err
	}
	// The master CLI accepts multiple commands and otherwise waits for more
	// input instead of closing after its reply. Signal EOF, but keep reading.
	if unix, ok := c.(*net.UnixConn); ok {
		_ = unix.CloseWrite()
	}
	data, err := io.ReadAll(io.LimitReader(c, maxRuntimeResponse+1))
	if len(data) > maxRuntimeResponse {
		return nil, fmt.Errorf("HAProxy runtime response exceeds limit")
	}
	return data, err
}

// One-shot, explicitly selected metrics only. Never emit environment, routes,
// cookies, Telegram configuration, certificate contents, or the login token.
func printDiagnostics(dst io.Writer) error {
	host, port, err := net.SplitHostPort(env("PANEL_LISTEN", ":9389"))
	if err != nil {
		return fmt.Errorf("invalid panel listen address")
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	base := "http://" + net.JoinHostPort(host, port) + "/" + strings.Trim(env("PANEL_SECRET_PATH", "admin"), "/") + "/api"
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Timeout: 10 * time.Second, Jar: jar, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	login, _ := json.Marshal(map[string]string{"token": os.Getenv("PANEL_TOKEN")})
	response, err := client.Post(base+"/login", "application/json", bytes.NewReader(login))
	if err != nil {
		return fmt.Errorf("diagnostics: local panel login unavailable")
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("diagnostics: local panel login rejected")
	}
	response, err = client.Get(base + "/system")
	if err != nil {
		return fmt.Errorf("diagnostics: local system endpoint unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("diagnostics: system HTTP %d", response.StatusCode)
	}
	var system map[string]any
	if err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&system); err != nil {
		return fmt.Errorf("diagnostics: invalid system response")
	}
	path := filepath.Join(env("PANEL_DATA", "./data"), "haproxy.sock")
	out := haproxyDiagnostics(path)
	out["system"], out["time_utc"] = system, time.Now().UTC().Format(time.RFC3339)
	encoder := json.NewEncoder(dst)
	encoder.SetIndent("", "  ")
	return encoder.Encode(out)
}

func haproxyDiagnostics(path string) map[string]any {
	out := map[string]any{}
	info := map[string]string{}
	if raw, err := haproxyCommand(path, "show info"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			key, value, _ := strings.Cut(line, ":")
			switch key {
			case "Version", "Uptime_sec", "Nbthread", "CurrConns", "Maxconn", "Maxsock", "Ulimit-n", "Idle_pct", "Tasks", "Run_queue", "SslRate", "SslFrontendKeyRate", "ConnRate", "Hard_maxconn", "CumConns", "CumReq", "PoolAlloc_MB", "PoolUsed_MB", "FailedResolutions":
				info[key] = strings.TrimSpace(value)
			}
		}
	} else {
		info["error"] = "runtime socket unavailable"
	}
	out["haproxy"] = info
	frontends := map[string]map[string]string{}
	backends := map[string]map[string]string{}
	if raw, err := haproxyCommand(path, "show stat"); err == nil {
		reader := csv.NewReader(bytes.NewReader(raw))
		reader.FieldsPerRecord = -1
		if rows, err := reader.ReadAll(); err == nil && len(rows) > 0 {
			for _, row := range rows[1:] {
				if len(row) < 2 {
					continue
				}
				frontend := row[1] == "FRONTEND" && (row[0] == "public_sni" || row[0] == "internal_tls" || row[0] == "public_direct")
				backend := row[1] == "BACKEND" && (strings.HasPrefix(row[0], "target_") || strings.HasPrefix(row[0], "direct_") || strings.HasPrefix(row[0], "relay_") || row[0] == "fallback_page")
				if !frontend && !backend {
					continue
				}
				v := map[string]string{}
				for i, name := range rows[0] {
					if i >= len(row) {
						break
					}
					switch strings.TrimSpace(name) {
					case "scur", "smax", "slim", "stot", "bin", "bout", "dreq", "ereq", "rate", "status", "qcur", "qmax", "econ", "eresp", "wretr", "wredis", "cli_abrt", "srv_abrt", "qtime", "ctime", "rtime", "ttime":
						v[strings.TrimSpace(name)] = row[i]
					}
				}
				if frontend {
					frontends[row[0]] = v
				} else {
					name := row[0]
					if strings.HasPrefix(name, "direct_") {
						name = strings.Join(strings.Split(name, "_")[:2], "_")
					}
					backends[name] = v
				}
			}
		}
	}
	out["frontends"] = frontends
	out["backends"] = backends
	if raw, err := os.ReadFile("/proc/net/sockstat"); err == nil {
		out["socket_counts"] = strings.TrimSpace(string(raw))
	}
	return out
}

func (a *App) observeCapacity(raw []byte) {
	r := csv.NewReader(bytes.NewReader(raw))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil || len(rows) == 0 {
		return
	}
	indices := map[string]int{}
	for i, k := range rows[0] {
		indices[strings.TrimSpace(strings.TrimPrefix(k, "# "))] = i
	}
	cur, ok1 := indices["scur"]
	peak, ok2 := indices["smax"]
	if !ok1 || !ok2 {
		return
	}
	for _, row := range rows[1:] {
		if len(row) > max(peak, cur) && row[1] == "FRONTEND" && (row[0] == "public_sni" || row[0] == "public_direct") {
			a.publicConnections.Store(parseCounter(row[cur]))
			a.publicPeak.Store(parseCounter(row[peak]))
			return
		}
	}
}
