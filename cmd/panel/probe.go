package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"
)

type publicProbeState struct {
	lastOK, lastNS atomic.Int64
	failures       atomic.Uint64
	// Only the fixed probe worker writes these fields.
	consecutive int
	lastCapture time.Time
}

func probeHTTPS(ctx context.Context, address, domain string) error {
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{ServerName: domain, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, // local self-signed endpoint, not upstream trust
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		},
	}
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+domain+"/", nil)
	if err != nil {
		return err
	}
	res, err := (&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		return fmt.Errorf("TLS/HTTP handshake or response failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("fallback returned HTTP %d", res.StatusCode)
	}
	_, err = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("fallback body failed")
	}
	return nil
}

func (a *App) probePublic(now time.Time) {
	a.mu.RLock()
	domain := a.domain
	a.mu.RUnlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	err := probeHTTPS(ctx, "127.0.0.1:443", domain)
	a.publicProbe.lastNS.Store(time.Since(started).Nanoseconds())
	if err == nil {
		a.publicProbe.lastOK.Store(time.Now().Unix())
		if a.publicProbe.consecutive >= 3 {
			log.Print("public HTTPS probe recovered")
		}
		a.publicProbe.consecutive = 0
		return
	}
	a.publicProbe.failures.Add(1)
	a.publicProbe.consecutive++
	if a.publicProbe.consecutive < 3 || now.Sub(a.publicProbe.lastCapture) < 10*time.Minute {
		return
	}
	a.publicProbe.lastCapture = now
	log.Printf("public HTTPS probe failed repeatedly: %v; capturing incident (no automatic restart)", err)
	// Bounded local files, not a per-request log. Stack traces contain function
	// frames, not request payloads; treat the files as private diagnostics.
	stack := make([]byte, 2<<20)
	stack = stack[:runtime.Stack(stack, true)]
	if err := atomicPrivateFile(filepath.Join(a.data, "incident-goroutines.txt"), stack); err != nil {
		log.Printf("incident stack: %v", err)
	}
	out := haproxyDiagnostics(filepath.Join(a.data, "haproxy.sock"))
	out["time_utc"] = time.Now().UTC().Format(time.RFC3339)
	out["public_https_failures"] = a.publicProbe.failures.Load()
	out["agent_pid"] = os.Getpid()
	out["goroutines"] = runtime.NumGoroutine()
	out["traffic_flush_errors"] = a.flushErrors.Load()
	out["traffic_flush_last_ok_unix"] = a.flushLastOK.Load()
	if data, e := json.MarshalIndent(out, "", "  "); e == nil {
		if e = atomicPrivateFile(filepath.Join(a.data, "incident-latest.json"), data); e != nil {
			log.Printf("incident snapshot: %v", e)
		}
	}
}

func atomicPrivateFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".incident-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
