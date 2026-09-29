package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestConnectionLimitBounds(t *testing.T) {
	for _, value := range []string{"1", "20000", "40000", "80000", "100000"} {
		if _, err := parseMaxConnections(value); err != nil {
			t.Fatal(value, err)
		}
	}
	for _, value := range []string{"0", "-1", "100001", "500000", "", "abc"} {
		if _, err := parseMaxConnections(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}

func TestRelayAdmissionAcrossRoutesAndGenerations(t *testing.T) {
	a := &App{maxConnections: 100}
	var wg sync.WaitGroup
	var admitted atomic.Int64
	// Only test the algorithm: no sockets, buffers or 100k goroutines allocated.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if a.acquireRelay() {
					admitted.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if admitted.Load() != 100 || a.relayAdmitted.Load() != 100 || a.relayRejected.Load() != 300 {
		t.Fatal(admitted.Load(), a.relayAdmitted.Load(), a.relayRejected.Load())
	}
	a.relayAdmitted.Add(-1)
	if !a.acquireRelay() || a.acquireRelay() {
		t.Fatal("released slot was not reused exactly once")
	}
}

func TestHundredThousandConfigAndLocalTransports(t *testing.T) {
	a, s := trafficApp(t)
	a.data, a.domain, a.maxConnections = t.TempDir(), "fallback.example.test", 100000
	s.Route.SNI, s.Route.IP, s.Route.Port = "route.example.test", "127.0.0.1", 8080
	if err := os.Mkdir(filepath.Join(a.data, "certs"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := a.ensureCert("fallback", a.domain); err != nil {
		t.Fatal(err)
	}
	if err := a.ensureCert(routeCert(s.Route), s.Route.SNI); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"relay", "direct"} {
		a.proxyMode = mode
		if err := a.writeConfig(); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(a.data, "haproxy.cfg"))
		if err != nil {
			t.Fatal(err)
		}
		cfg := string(raw)
		if !strings.Contains(cfg, "  maxconn 100000\n") {
			t.Fatal("missing public cap")
		}
		if mode == "relay" {
			for _, want := range []string{"global\n  maxconn 200256\n", "  maxconn 100256\n", "bind 127.0.0.1:8443-8458 ssl", "server relay " + relaySocket(a.data, s.Route.ID)} {
				if !strings.Contains(cfg, want) {
					t.Fatalf("missing %q", want)
				}
			}
			for _, old := range []string{"bind 127.0.0.1:8443 ssl", "127.0.0.1:9999", "127.0.0.1:10001"} {
				if strings.Contains(cfg, old) {
					t.Fatalf("TCP port bottleneck remains: %s", old)
				}
			}
		} else if !strings.Contains(cfg, "global\n  maxconn 100256\n") || strings.Contains(cfg, "frontend internal_tls") {
			t.Fatal("wrong direct capacity/transport")
		}
	}
}

func TestInternalTLSIngressLeastActiveAndRelease(t *testing.T) {
	var pool internalTLSIngress
	counts := map[string]int{}
	releases := make([]func(), 0, 160)
	for i := 0; i < 160; i++ {
		addr, release := pool.acquire()
		counts[addr]++
		releases = append(releases, release)
	}
	if len(counts) != internalTLSShards {
		t.Fatal(counts)
	}
	for _, n := range counts {
		if n != 10 {
			t.Fatal(counts)
		}
	}
	// All sockets on the first shard close while other shards remain busy.
	for i := 0; i < 160; i += 16 {
		releases[i]()
		releases[i] = nil
	}
	for i := 0; i < 10; i++ {
		addr, release := pool.acquire()
		if addr != "127.0.0.1:8443" {
			t.Fatal("not least-active", addr)
		}
		releases = append(releases, release)
	}
	for _, release := range releases {
		if release != nil {
			release()
		}
	}
	for _, n := range pool.active {
		if n != 0 {
			t.Fatal("inner slot leaked")
		}
	}
}

func TestRelayUnixListenerLifecycle(t *testing.T) {
	// Keep Unix paths below the OS sun_path limit (macOS temp roots are long).
	dir, err := os.MkdirTemp("", "fg-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	a := &App{data: dir, routes: map[int64]*RouteState{}}
	if err := a.startListeners(); err != nil {
		t.Fatal(err)
	}
	p := relaySocket(dir, 0)
	info, err := os.Stat(p)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal(info, err)
	}
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	a.stopRelays()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("listener left socket behind", err)
	}
	if a.relayAdmitted.Load() != 0 {
		t.Fatal("admission slot leaked during shutdown")
	}
}

func TestInternalTLSIngressConcurrentRelease(t *testing.T) {
	var pool internalTLSIngress
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, release := pool.acquire()
				release()
			}
		}()
	}
	wg.Wait()
	for _, count := range pool.active {
		if count != 0 {
			t.Fatal("concurrent release lost", pool.active)
		}
	}
}
