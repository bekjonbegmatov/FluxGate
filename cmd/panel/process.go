package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// One container/unit, three independent heaps. Only the agent owns traffic and
// writes SQLite. A crashed web process is restarted without interrupting relay.
type childProcess struct {
	cmd  *exec.Cmd
	done chan error
}

func startChild(role string) (*childProcess, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	c := exec.Command(exe, "--"+role)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	if err := c.Start(); err != nil {
		return nil, err
	}
	p := &childProcess{cmd: c, done: make(chan error, 1)}
	go func() { p.done <- c.Wait() }()
	log.Printf("started %s pid=%d", role, c.Process.Pid)
	return p, nil
}

func (p *childProcess) stop(timeout time.Duration) {
	if p == nil {
		return
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(timeout):
		_ = p.cmd.Process.Kill()
		<-p.done
	}
}

func supervise() error {
	log.SetPrefix("supervisor: ")
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	for ctx.Err() == nil {
		agent, err := startChild("agent")
		if err != nil {
			return err
		}
		// Starting web early is safe: it retries opening the migrated database.
		web, err := startChild("web")
		if err != nil {
			agent.stop(30 * time.Second)
			return err
		}
		running := true
		for running {
			select {
			case <-ctx.Done():
				web.stop(5 * time.Second)
				agent.stop(35 * time.Second)
				return nil
			case err := <-agent.done:
				log.Printf("agent exited: %v", err)
				// Close every read-only connection BEFORE the next agent can
				// replace the DB on restore. Never read an unlinked old database.
				web.stop(5 * time.Second)
				running = false
			case err := <-web.done:
				log.Printf("web exited: %v", err)
				select {
				case <-ctx.Done():
					agent.stop(35 * time.Second)
					return nil
				case <-time.After(time.Second):
				}
				web, err = startChild("web")
				if err != nil {
					agent.stop(35 * time.Second)
					return err
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}
	}
	return nil
}

func agentSocket(data string) string { return filepath.Join(data, "agent.sock") }

func listenAgent(data string) (net.Listener, error) {
	return listenPrivateSocket(agentSocket(data))
}

func lockAgent(data string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(data, "agent.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another traffic agent owns this data directory")
	}
	return f, nil
}

func listenPrivateSocket(path string) (net.Listener, error) {
	if c, err := net.DialTimeout("unix", path, 200*time.Millisecond); err == nil {
		c.Close()
		return nil, fmt.Errorf("another process is already listening on private socket")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("agent socket path is not a socket")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func openReportDB(data string) (*sql.DB, error) {
	path, err := filepath.Abs(filepath.Join(data, "panel.db"))
	if err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: path}
	q := url.Values{"mode": {"ro"}, "_pragma": {"busy_timeout(2000)", "query_only(1)"}}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func localWebRequest(r *http.Request, base string) bool {
	if !strings.HasPrefix(r.URL.Path, base+"api/") {
		return r.URL.Path != "/healthz"
	}
	path := strings.TrimPrefix(r.URL.Path, base+"api/")
	if path == "login" || path == "logout" || path == "me" {
		return true
	}
	return r.Method == http.MethodGet && (strings.HasPrefix(path, "history/") || strings.HasPrefix(path, "request-history/") || path == "export/traffic.csv" || path == "export/payments.csv")
}

func webHandler(a *App) http.Handler {
	local := a.adminServer().Handler
	proxy := &httputil.ReverseProxy{
		Director: func(r *http.Request) { r.URL.Scheme, r.URL.Host = "http", "agent" },
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", agentSocket(a.data))
		}, ResponseHeaderTimeout: 3 * time.Minute, MaxIdleConnsPerHost: 16},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) { fail(w, 503, "traffic agent unavailable") },
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/internal/") {
			http.NotFound(w, r)
			return
		}
		if localWebRequest(r, "/"+a.secretPath+"/") {
			local.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			a.historyEpoch.Add(1)
			defer a.historyEpoch.Add(1)
		}
		// Host, Origin and cookies are preserved; the private agent performs
		// the same authentication and Origin validation as the public API.
		proxy.ServeHTTP(w, r)
	})
}

func runWeb() error {
	log.SetPrefix("web: ")
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	data := env("PANEL_DATA", "./data")
	// The socket is bound only after schema migrations and route recovery.
	for {
		c, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", agentSocket(data))
		if err == nil {
			c.Close()
			break
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(100 * time.Millisecond):
		}
	}
	db, err := openReportDB(data)
	if err != nil {
		return err
	}
	defer db.Close()
	a := &App{db: db, data: data, web: env("PANEL_WEB", "./web/dist"), secretPath: strings.Trim(env("PANEL_SECRET_PATH", "admin"), "/"), tokenHash: sha256.Sum256([]byte(os.Getenv("PANEL_TOKEN"))), master: []byte(os.Getenv("PANEL_MASTER_KEY"))}
	a.location, err = time.LoadLocation(a.getSetting("timezone", env("PANEL_TIMEZONE", "UTC")))
	if err != nil {
		return err
	}
	server := a.adminServer()
	server.Handler = webHandler(a)
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	log.Printf("panel listening on http://%s/%s/ (read-only reports)", server.Addr, a.secretPath)
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		stop, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if err := server.Shutdown(stop); err != nil {
			_ = server.Close()
		}
		return nil
	}
}
