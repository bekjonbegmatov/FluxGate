package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

type memoryConn struct {
	io.Reader
	write func([]byte) (int, error)
}

func (c *memoryConn) Write(p []byte) (int, error) {
	if c.write != nil {
		return c.write(p)
	}
	return len(p), nil
}
func (*memoryConn) Close() error                     { return nil }
func (*memoryConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*memoryConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*memoryConn) SetDeadline(time.Time) error      { return nil }
func (*memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*memoryConn) SetWriteDeadline(time.Time) error { return nil }

func trafficApp(t *testing.T) (*App, *RouteState) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(`CREATE TABLE routes(id INTEGER PRIMARY KEY,up_total INTEGER,down_total INTEGER);
CREATE TABLE periods(route_id INTEGER,kind TEXT,key TEXT,used INTEGER,extra INTEGER,threshold_sent INTEGER,exhausted_sent INTEGER,PRIMARY KEY(route_id,kind,key));
CREATE TABLE samples(route_id INTEGER,ts INTEGER,up INTEGER,down INTEGER,PRIMARY KEY(route_id,ts));
INSERT INTO routes VALUES(1,0,0);`)
	if err != nil {
		t.Fatal(err)
	}
	s := &RouteState{Route: Route{ID: 1, CountMode: "both", Threshold: 80, CreatedAt: time.Now().Unix()}, conns: map[net.Conn]struct{}{}}
	a := &App{db: db, routes: map[int64]*RouteState{1: s}, location: time.UTC}
	if err := a.refreshPeriods(s, time.Now()); err != nil {
		t.Fatal(err)
	}
	return a, s
}

func TestMeterCountsOnlyWrittenBytes(t *testing.T) {
	a, s := trafficApp(t)
	s.Route.DailyLimit = 100
	dst := &memoryConn{write: func([]byte) (int, error) { return 7, io.ErrClosedPipe }}
	err := a.copyMetered(s, dst, &memoryConn{Reader: bytes.NewReader(make([]byte, 64))}, true, make(chan struct{}))
	if !errors.Is(err, io.ErrClosedPipe) || s.Route.UpTotal != 7 || s.Daily.Used != 7 || s.reservedDaily != 0 {
		t.Fatalf("err=%v total=%d period=%+v reserved=%d", err, s.Route.UpTotal, s.Daily, s.reservedDaily)
	}
}

func TestConcurrentQuotaCannotBeExceeded(t *testing.T) {
	a, s := trafficApp(t)
	s.Route.DailyLimit = 100003
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(up bool) {
			defer wg.Done()
			_ = a.copyMetered(s, &memoryConn{}, &memoryConn{Reader: bytes.NewReader(make([]byte, 128<<10))}, up, make(chan struct{}))
		}(i%2 == 0)
	}
	wg.Wait()
	if got := s.Route.UpTotal + s.Route.DownTotal; got != s.Route.DailyLimit || s.Daily.Used != got || s.Monthly.Used != got {
		t.Fatalf("quota=%d actual=%d daily=%d monthly=%d", s.Route.DailyLimit, got, s.Daily.Used, s.Monthly.Used)
	}
}

func TestSharedBucketAndRateChange(t *testing.T) {
	b := bucket{}
	now := time.Now()
	if n, _ := b.take(1000, 1000, now); n != 1000 {
		t.Fatal(n)
	}
	if n, d := b.take(1000, 1000, now); n != 0 || d <= 0 {
		t.Fatalf("new connection got its own budget: %d %s", n, d)
	}
	if n, _ := b.take(1000, 1000, now.Add(100*time.Millisecond)); n != 100 {
		t.Fatal(n)
	}
	if n, _ := b.take(1000, 10, now.Add(time.Second)); n != 10 {
		t.Fatalf("lower rate retained old burst: %d", n)
	}
	if n, _ := b.take(65536, 0, now); n != 65536 {
		t.Fatal(n)
	}
}

func TestRateLimitWaitCanBeCancelled(t *testing.T) {
	a, s := trafficApp(t)
	s.Route.UpBPS = 1
	s.upBucket = bucket{last: time.Now(), rate: 1}
	done := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- a.copyMetered(s, &memoryConn{}, &memoryConn{Reader: bytes.NewReader([]byte("x"))}, true, done)
	}()
	close(done)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("expected cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("limiter did not stop")
	}
}

func TestFlushRetriesWithoutLosingOrDuplicatingSamples(t *testing.T) {
	a, s := trafficApp(t)
	s.Route.UpTotal, s.pendingUp, s.Daily.Used, s.Monthly.Used = 77, 77, 77, 77
	_, err := a.db.Exec("CREATE TRIGGER fail_sample BEFORE INSERT ON samples BEGIN SELECT RAISE(FAIL,'injected storage failure'); END")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.flushTraffic(time.Now()); err == nil {
		t.Fatal("expected DB failure")
	}
	if s.pendingUp != 77 {
		t.Fatal("pending traffic lost")
	}
	if _, err = a.db.Exec("DROP TRIGGER fail_sample"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err = a.flushTraffic(time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	var total, sample int64
	_ = a.db.QueryRow("SELECT up_total FROM routes WHERE id=1").Scan(&total)
	_ = a.db.QueryRow("SELECT SUM(up) FROM samples WHERE route_id=1").Scan(&sample)
	if total != 77 || sample != 77 || s.pendingUp != 0 {
		t.Fatalf("total=%d sample=%d pending=%d", total, sample, s.pendingUp)
	}
}

func TestSlowDatabaseDoesNotBlockRelay(t *testing.T) {
	a, s := trafficApp(t)
	s.Route.UpTotal, s.pendingUp = 1, 1
	conn, err := a.db.Conn(context.Background()) // Occupy the only DB connection.
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	flushed := make(chan error, 1)
	go func() { flushed <- a.flushTraffic(time.Now()) }()
	deadline := time.Now().Add(time.Second)
	for a.db.Stats().WaitCount == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if a.db.Stats().WaitCount == 0 {
		t.Fatal("flush did not wait for DB")
	}
	copied := make(chan error, 1)
	go func() {
		copied <- a.copyMetered(s, &memoryConn{}, &memoryConn{Reader: bytes.NewReader(make([]byte, 1<<20))}, true, make(chan struct{}))
	}()
	select {
	case err := <-copied:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("SQLite wait blocked the data path")
	}
	conn.Close()
	if err := <-flushed; err != nil {
		t.Fatal(err)
	}
	if err := a.flushTraffic(time.Now()); err != nil {
		t.Fatal(err)
	}
	var total int64
	_ = a.db.QueryRow("SELECT SUM(up) FROM samples").Scan(&total)
	if total != 1+(1<<20) {
		t.Fatalf("traffic during flush lost: %d", total)
	}
}

func TestPeriodRolloverAccountsInflightWrite(t *testing.T) {
	a, s := trafficApp(t)
	now := time.Now().UTC()
	oldKey := s.Daily.Key
	entered, release := make(chan struct{}), make(chan struct{})
	dst := &memoryConn{write: func(p []byte) (int, error) { close(entered); <-release; return len(p), nil }}
	done := make(chan error, 1)
	go func() {
		done <- a.copyMetered(s, dst, &memoryConn{Reader: bytes.NewReader(make([]byte, 99))}, true, make(chan struct{}))
	}()
	<-entered
	if err := a.rollPeriods(now.AddDate(0, 0, 1)); err != nil {
		t.Fatal(err)
	}
	if err := a.flushTraffic(now); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := a.flushTraffic(now.AddDate(0, 0, 1)); err != nil {
		t.Fatal(err)
	}
	var oldUsage int64
	_ = a.db.QueryRow("SELECT used FROM periods WHERE kind='daily' AND key=?", oldKey).Scan(&oldUsage)
	if oldUsage != 99 || s.Daily.Used != 0 {
		t.Fatalf("old=%d new=%d", oldUsage, s.Daily.Used)
	}
}

func TestRoutesHaveStableOrder(t *testing.T) {
	a := &App{routes: map[int64]*RouteState{}}
	for _, id := range []int64{9, 3, 15, 1, 7} {
		a.routes[id] = &RouteState{Route: Route{ID: id}}
	}
	for i := 0; i < 50; i++ {
		w := httptest.NewRecorder()
		a.routesAPI(w, httptest.NewRequest("GET", "/admin/api/routes", nil))
		var list []Route
		if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
			t.Fatal(err)
		}
		for j := 1; j < len(list); j++ {
			if list[j-1].ID >= list[j].ID {
				t.Fatalf("unstable order: %v", list)
			}
		}
	}
}

func TestConfigRollbackKeepsLiveTraffic(t *testing.T) {
	s := &RouteState{Route: Route{Name: "new", UpTotal: 120}, Daily: Period{Used: 120}, Monthly: Period{Used: 120}}
	s.restoreRoute(Route{Name: "old", UpTotal: 10}, Period{Used: 10}, Period{Used: 10})
	if s.Route.Name != "old" || s.Route.UpTotal != 120 || s.Daily.Used != 120 || s.Monthly.Used != 120 {
		t.Fatal("rollback discarded live counters")
	}
}

func tcpPair(t testing.TB) (net.Conn, net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	one, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	two, err := l.Accept()
	if err != nil {
		one.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { one.Close(); two.Close() })
	return one, two
}

func TestRelayPreservesHalfClose(t *testing.T) {
	client, relayClient := tcpPair(t)
	origin, relayOrigin := tcpPair(t)
	pair := &relayConn{Conn: relayClient, upstream: relayOrigin, done: make(chan struct{})}
	defer pair.Close()
	done := make(chan struct{})
	go func() { (&App{}).relayDuplex(nil, pair); close(done) }()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = origin.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = client.Write([]byte("request"))
	_ = client.(*net.TCPConn).CloseWrite()
	request, err := io.ReadAll(origin)
	if err != nil || string(request) != "request" {
		t.Fatalf("request=%q err=%v", request, err)
	}
	response := bytes.Repeat([]byte("response"), 10000)
	go func() { _, _ = origin.Write(response); _ = origin.(*net.TCPConn).CloseWrite() }()
	got, err := io.ReadAll(client)
	if err != nil || !bytes.Equal(got, response) {
		t.Fatalf("response truncated: %d err=%v", len(got), err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay failed to drain")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func TestRelayReadErrorStopsOppositePump(t *testing.T) {
	origin, upstream := net.Pipe()
	defer origin.Close()
	pair := &relayConn{Conn: &memoryConn{Reader: errorReader{}}, upstream: upstream, done: make(chan struct{})}
	defer pair.Close()
	done := make(chan struct{})
	go func() { (&App{}).relayDuplex(nil, pair); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("opposite copy goroutine leaked")
	}
}

func TestConfigStableDuringConcurrentTraffic(t *testing.T) {
	a, s := trafficApp(t)
	a.data = t.TempDir()
	a.domain = "fallback.example.test"
	s.Route.SNI = "route.example.test"
	s.Route.IP = "127.0.0.1"
	s.Route.Port = 8080
	if err := os.Mkdir(filepath.Join(a.data, "certs"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := a.ensureCert("fallback", a.domain); err != nil {
		t.Fatal(err)
	}
	if err := a.ensureCert(routeCert(s.Route), s.Route.SNI); err != nil {
		t.Fatal(err)
	}
	if err := a.writeConfig(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(a.data, "haproxy.cfg")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 10000; i++ {
			s.mu.Lock()
			s.Route.UpTotal++
			s.mu.Unlock()
		}
	}()
	for i := 0; i < 20; i++ {
		if err := a.writeConfig(); err != nil {
			t.Fatal(err)
		}
	}
	<-done
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("identical config was replaced")
	}
}

func TestHistoryIndexesMigrateIdempotently(t *testing.T) {
	a, _ := trafficApp(t)
	if err := a.initRequestStats(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := a.initHistoryIndexes(); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := a.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN ('samples_ts','request_samples_ts')").Scan(&n); err != nil || n != 2 {
		t.Fatalf("indexes=%d err=%v", n, err)
	}
}

func TestPeriodReadFailureCannotResetQuota(t *testing.T) {
	a, s := trafficApp(t)
	if _, err := a.db.Exec("DROP TABLE periods"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.loadPeriod(s.Route.ID, "daily", s.Daily.Key); err == nil {
		t.Fatal("storage error treated as an unused quota")
	}
}

// Real TCP on BOTH sides, with metering shared by the stated number of streams.
func BenchmarkRelayTCP(b *testing.B) {
	for _, streams := range []int{1, 8} {
		b.Run(strconv.Itoa(streams)+"-streams", func(b *testing.B) {
			s := &RouteState{Route: Route{CountMode: "both"}}
			a := &App{}
			payload := make([]byte, 1<<20)
			type stream struct {
				writer, reader  net.Conn
				copied, drained chan error
			}
			pipes := make([]stream, streams)
			for i := range pipes {
				src, in := tcpPair(b)
				out, dst := tcpPair(b)
				p := stream{writer: src, reader: dst, copied: make(chan error, 1), drained: make(chan error, 1)}
				pipes[i] = p
				go func() {
					p.copied <- a.copyMetered(s, out, in, true, make(chan struct{}))
					out.(*net.TCPConn).CloseWrite()
				}()
				go func() { _, err := io.Copy(io.Discard, dst); p.drained <- err }()
			}
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			var wg sync.WaitGroup
			for i, p := range pipes {
				wg.Add(1)
				go func(i int, p stream) {
					defer wg.Done()
					for n := i; n < b.N; n += streams {
						if _, err := p.writer.Write(payload); err != nil {
							b.Error(err)
							return
						}
					}
					p.writer.(*net.TCPConn).CloseWrite()
					if err := <-p.copied; err != nil {
						b.Error(err)
					}
					if err := <-p.drained; err != nil {
						b.Error(err)
					}
				}(i, p)
			}
			wg.Wait()
			b.StopTimer()
		})
	}
}
