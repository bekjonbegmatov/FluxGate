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
	return io.ReadAll(io.LimitReader(c, 8<<20))
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
	out := map[string]any{"system": system, "time_utc": time.Now().UTC().Format(time.RFC3339)}
	path := filepath.Join(env("PANEL_DATA", "./data"), "haproxy.sock")
	info := map[string]string{}
	if raw, err := haproxyCommand(path, "show info"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			key, value, _ := strings.Cut(line, ":")
			switch key {
			case "Version", "Uptime_sec", "Nbthread", "CurrConns", "Maxconn", "Idle_pct", "Tasks", "Run_queue", "SslRate", "SslFrontendKeyRate", "ConnRate", "Hard_maxconn":
				info[key] = strings.TrimSpace(value)
			}
		}
	} else {
		info["error"] = "runtime socket unavailable"
	}
	out["haproxy"] = info
	frontends := map[string]map[string]string{}
	if raw, err := haproxyCommand(path, "show stat"); err == nil {
		reader := csv.NewReader(bytes.NewReader(raw))
		reader.FieldsPerRecord = -1
		if rows, err := reader.ReadAll(); err == nil && len(rows) > 0 {
			for _, row := range rows[1:] {
				if len(row) < 2 || row[1] != "FRONTEND" || (row[0] != "public_sni" && row[0] != "internal_tls") {
					continue
				}
				v := map[string]string{}
				for i, name := range rows[0] {
					if i >= len(row) {
						break
					}
					switch strings.TrimSpace(name) {
					case "scur", "smax", "slim", "stot", "bin", "bout", "dreq", "ereq", "rate", "status":
						v[strings.TrimSpace(name)] = row[i]
					}
				}
				frontends[row[0]] = v
			}
		}
	}
	out["frontends"] = frontends
	encoder := json.NewEncoder(dst)
	encoder.SetIndent("", "  ")
	return encoder.Encode(out)
}
