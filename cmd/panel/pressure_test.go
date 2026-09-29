package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestCancelledHistoryReleasesDatabaseWait(t *testing.T) {
	for _, requests := range []bool{false, true} {
		a, _ := trafficApp(t)
		if err := a.initRequestStats(); err != nil {
			t.Fatal(err)
		}
		conn, err := a.db.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		path := "/api/history/all"
		handler := a.historyAPI
		if requests {
			path, handler = "/api/request-history/all", a.requestHistoryAPI
		}
		// Empty secretPath still contributes a slash in the handler prefix.
		a.secretPath = "admin"
		r := httptest.NewRequest("GET", "/admin"+path, nil).WithContext(ctx)
		done := make(chan struct{})
		go func() { handler(httptest.NewRecorder(), r); close(done) }()
		select {
		case <-done:
		case <-time.After(300 * time.Millisecond):
			t.Errorf("requests=%v: cancelled HTTP request still occupies the DB wait queue", requests)
		}
		conn.Close()
		<-done
	}
}

func TestCreateRouteDatabaseWaitDoesNotLockFallback(t *testing.T) {
	a, _ := trafficApp(t)
	conn, err := a.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan struct{})
	go func() {
		a.createRoute(httptest.NewRecorder(), Route{Name: "Test", SNI: "test.example.test", IP: "127.0.0.1", Port: 8080, CountMode: "both", Threshold: 80})
		close(done)
	}()
	deadline := time.Now().Add(time.Second)
	for a.db.Stats().WaitCount == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if a.db.Stats().WaitCount == 0 {
		t.Error("create did not wait on DB")
	}
	readable := make(chan struct{})
	go func() { a.mu.RLock(); a.mu.RUnlock(); close(readable) }()
	select {
	case <-readable:
	case <-time.After(300 * time.Millisecond):
		t.Error("DB wait locked fallback/settings/system readers")
	}
	conn.Close()
	<-done
	<-readable
}

func TestHistoryCancelsRunningSQLiteQuery(t *testing.T) {
	a, _ := trafficApp(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := a.historyRows(ctx, "expensive", `WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100000000) SELECT SUM(x),0,0 FROM n`, nil, 3)
	if err == nil || ctx.Err() == nil || time.Since(started) > time.Second {
		t.Fatalf("query did not stop promptly: %v, %s", err, time.Since(started))
	}
	if err := a.db.PingContext(context.Background()); err != nil {
		t.Fatal("connection unusable after cancellation", err)
	}
}

type stalledResponse struct {
	*httptest.ResponseRecorder
	entered, release chan struct{}
	once             sync.Once
}

func (w *stalledResponse) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered); <-w.release })
	return w.ResponseRecorder.Write(p)
}

func TestSlowCSVClientDoesNotHoldDatabase(t *testing.T) {
	a, _ := trafficApp(t)
	if _, err := a.db.Exec(`ALTER TABLE routes ADD COLUMN name TEXT DEFAULT 'test';
ALTER TABLE routes ADD COLUMN sni TEXT DEFAULT 'example.test';
INSERT INTO samples VALUES(1,1789992000,123,456);`); err != nil {
		t.Fatal(err)
	}
	w := &stalledResponse{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		a.exportTrafficAPI(w, httptest.NewRequest(http.MethodGet, "/api/export/traffic.csv?from=2026-09-21&to=2026-09-21", nil))
		close(done)
	}()
	<-w.entered
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err := a.db.PingContext(ctx)
	close(w.release)
	<-done
	if err != nil {
		t.Fatalf("slow CSV recipient monopolized SQLite: %v", err)
	}
}

type idleReader struct {
	size    chan int
	release <-chan struct{}
}

func (r idleReader) Read(p []byte) (int, error) { r.size <- cap(p); <-r.release; return 0, io.EOF }

func TestIdleRelayBufferBudget(t *testing.T) {
	const directions = 512
	sizes, release := make(chan int, directions), make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < directions; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = (&App{}).copyMetered(nil, &memoryConn{}, &memoryConn{Reader: idleReader{sizes, release}}, true, make(chan struct{}))
		}()
	}
	total := 0
	for i := 0; i < directions; i++ {
		total += <-sizes
	}
	close(release)
	wg.Wait()
	t.Logf("%d idle tunnels retain %d KiB of relay buffers (%d KiB/tunnel)", directions/2, total/1024, total/(directions/2)/1024)
	if total > directions*16*1024 {
		t.Fatal("idle connection buffers exceed 16 KiB per direction")
	}
}

func TestSlowBackupClientDoesNotStopAccounting(t *testing.T) {
	a, s := trafficApp(t)
	a.data = t.TempDir()
	a.domain = "example.test"
	if err := os.Mkdir(filepath.Join(a.data, "certs"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := a.ensureCert("fallback", a.domain); err != nil {
		t.Fatal(err)
	}
	w := &stalledResponse{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{})}
	download := make(chan struct{})
	go func() { a.backupAPI(w, httptest.NewRequest("GET", "/api/backup", nil)); close(download) }()
	<-w.entered
	s.mu.Lock()
	s.pendingUp = 9
	s.Route.UpTotal = 9
	s.mu.Unlock()
	flushed := make(chan error, 1)
	go func() { flushed <- a.flushTraffic(time.Now()) }()
	select {
	case err := <-flushed:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(time.Second):
		t.Error("backup download blocks accounting")
	}
	close(w.release)
	<-download
	files, _ := filepath.Glob(filepath.Join(a.data, "backup-*"))
	if len(files) != 0 {
		t.Fatal("backup temporary files retained", files)
	}
}

func TestHistoryCacheBoundedAndEpochInvalidated(t *testing.T) {
	a, _ := trafficApp(t)
	ctx := context.Background()
	query := "SELECT ts,up,down FROM samples"
	_, _ = a.db.Exec("INSERT INTO samples VALUES(1,60,2,3)")
	first, err := a.historyRows(ctx, "same", query, nil, 3)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = a.db.Exec("UPDATE samples SET up=99")
	cached, err := a.historyRows(ctx, "same", query, nil, 3)
	if err != nil || cached[0][1] != first[0][1] {
		t.Fatal("cache missed", cached, err)
	}
	a.historyEpoch.Add(1)
	updated, err := a.historyRows(ctx, "same", query, nil, 3)
	if err != nil || updated[0][1] != 99 {
		t.Fatal("stale data after route epoch change", updated, err)
	}
	for i := 0; i < 100; i++ {
		if _, err := a.historyRows(ctx, fmt.Sprint(i), query, nil, 3); err != nil {
			t.Fatal(err)
		}
	}
	if len(a.history.entries) > 64 {
		t.Fatal("unbounded history cache")
	}
}

func TestHistoryPruneIsBoundedAndPreservesRetention(t *testing.T) {
	a, _ := trafficApp(t)
	if err := a.initRequestStats(); err != nil {
		t.Fatal(err)
	}
	if err := a.initHistoryIndexes(); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	cutoff := now.AddDate(0, 0, -90).Unix()
	_, err := a.db.Exec(`WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<40001)
INSERT INTO samples SELECT 1,?-x,1,1 FROM n`, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.db.Exec("INSERT INTO samples VALUES(1,?,100,100); INSERT INTO request_samples VALUES(1,?,10,9,0,1,0)", cutoff, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.pruneHistory(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	var old, fresh int
	if err = a.db.QueryRow("SELECT COUNT(*) FROM samples WHERE ts<?", cutoff).Scan(&old); err != nil || old < 1 {
		t.Fatalf("cleanup exceeded one tick budget: %d %v", old, err)
	}
	if err = a.db.QueryRow("SELECT COUNT(*) FROM samples WHERE ts=?", cutoff).Scan(&fresh); err != nil || fresh != 1 {
		t.Fatalf("retained sample deleted: %d %v", fresh, err)
	}
	if err = a.db.QueryRow("SELECT COUNT(*) FROM request_samples").Scan(&fresh); err != nil || fresh != 1 {
		t.Fatalf("retained HTTP sample deleted: %d %v", fresh, err)
	}
}

// This benchmark is deliberately opt-in: it seeds two realistic 90-day tables,
// then measures uncached scans and repeated dashboard requests separately.
func BenchmarkHistoryGrowth(b *testing.B) {
	for _, days := range []int{1, 90} {
		b.Run(fmt.Sprintf("20-routes-%dd", days), func(b *testing.B) {
			db, err := sql.Open("sqlite", filepath.Join(b.TempDir(), "history.db"))
			if err != nil {
				b.Fatal(err)
			}
			defer db.Close()
			db.SetMaxOpenConns(1)
			_, err = db.Exec(`PRAGMA journal_mode=WAL;
CREATE TABLE samples(route_id INTEGER,ts INTEGER,up INTEGER,down INTEGER,PRIMARY KEY(route_id,ts));
CREATE TABLE request_samples(route_id INTEGER,ts INTEGER,requests INTEGER,r2 INTEGER,r3 INTEGER,r4 INTEGER,r5 INTEGER,PRIMARY KEY(route_id,ts));`)
			if err != nil {
				b.Fatal(err)
			}
			a := &App{db: db, secretPath: "admin"}
			if err = a.initHistoryIndexes(); err != nil {
				b.Fatal(err)
			}
			now := time.Now().Truncate(time.Minute).Unix()
			_, err = db.Exec(`WITH RECURSIVE minute(n) AS (VALUES(0) UNION ALL SELECT n+1 FROM minute WHERE n<?-1), route(id) AS (VALUES(1) UNION ALL SELECT id+1 FROM route WHERE id<20) INSERT INTO samples SELECT id,?-n*60,1000000,2000000 FROM route CROSS JOIN minute`, days*1440, now)
			if err != nil {
				b.Fatal(err)
			}
			_, err = db.Exec("INSERT INTO request_samples SELECT route_id,ts,10,9,0,1,0 FROM samples")
			if err != nil {
				b.Fatal(err)
			}
			for _, cached := range []bool{false, true} {
				b.Run(fmt.Sprintf("cached=%v", cached), func(b *testing.B) {
					r := httptest.NewRequest("GET", fmt.Sprintf("/admin/api/history/all?hours=%d", days*24), nil)
					// Warm the same graph once, never cache more than 61 aggregated points.
					w := httptest.NewRecorder()
					a.historyAPI(w, r)
					if w.Code != 200 {
						b.Fatal(w.Body.String())
					}
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if !cached {
							a.historyEpoch.Add(1)
						}
						w := httptest.NewRecorder()
						a.historyAPI(w, r)
						if w.Code != 200 {
							b.Fatal(w.Body.String())
						}
					}
				})
			}
		})
	}
}
