package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPassthroughRequestStatsRetainHistoryButHideLiveHTTP(t *testing.T) {
	a, s := trafficApp(t)
	if err := a.initRequestStats(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec("INSERT INTO request_totals(route_id,requests,r2) VALUES(1,123,123)"); err != nil {
		t.Fatal(err)
	}
	a.liveStats = map[int64]RequestStats{1: {Rate: 12, Active: 3, ResponseMS: 5, UpdatedAt: 100}}
	s.Route.TLSPassthrough = true
	w := httptest.NewRecorder()
	a.requestStatsAPI(w, httptest.NewRequest("GET", "/admin/api/request-stats", nil))
	var result []RequestStats
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].HTTPVisible || result[0].Requests != 123 || result[0].Rate != 0 || result[0].Active != 0 || result[0].UpdatedAt != 0 {
		t.Fatal("misleading opaque HTTP statistics", result)
	}
}

func TestReadHAProxyStats(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.sock")
	l, e := net.Listen("unix", path)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	go func() {
		c, e := l.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		b := make([]byte, 64)
		_, _ = c.Read(b)
		_, _ = c.Write([]byte("# pxname,svname,req_tot,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,scur,rtime,mode\ntarget_7,BACKEND,42,30,3,4,5,2,16,http\ndirect_8_abcdef,BACKEND,20,0,0,0,0,2,0,tcp\nfallback_page,BACKEND,11,1,0,0,0,0,0,http\n"))
	}()
	got, e := readHAProxyStats(path)
	if e != nil {
		t.Fatal(e)
	}
	v := got[7]
	if len(got) != 1 || v.requests != 42 || v.r4 != 4 || v.r5 != 5 || v.active != 2 || v.responseMS != 16 {
		t.Fatalf("stats: %+v", got)
	}
	if deltaCounter(5, 9) != 5 || deltaCounter(12, 9) != 3 {
		t.Fatal("counter reset handling")
	}
}

func TestRequestStatsRetriesFailedTransaction(t *testing.T) {
	a, _ := trafficApp(t)
	if err := a.initRequestStats(); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "fg-stats-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	a.data = dir
	l, err := net.Listen("unix", filepath.Join(dir, "haproxy.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			buf := make([]byte, 64)
			_, _ = c.Read(buf)
			_, _ = fmt.Fprint(c, "# pxname,svname,req_tot,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,scur,rtime\ntarget_1,BACKEND,50,50,0,0,0,2,1\n")
			c.Close()
		}
	}()
	a.lastStats = map[int64]requestCounter{1: {requests: 10, r2: 10}}
	a.lastStatsAt = time.Now().Add(-10 * time.Second)
	if _, err := a.db.Exec("CREATE TRIGGER fail_requests BEFORE INSERT ON request_samples BEGIN SELECT RAISE(FAIL,'injected failure'); END"); err != nil {
		t.Fatal(err)
	}
	a.collectRequestStats(time.Now())
	if a.lastStats[1].requests != 10 {
		t.Fatal("baseline advanced despite failed transaction")
	}
	if _, err := a.db.Exec("DROP TRIGGER fail_requests"); err != nil {
		t.Fatal(err)
	}
	a.collectRequestStats(time.Now().Add(10 * time.Second))
	a.collectRequestStats(time.Now().Add(20 * time.Second))
	var requests, samples int64
	_ = a.db.QueryRow("SELECT requests FROM request_totals WHERE route_id=1").Scan(&requests)
	_ = a.db.QueryRow("SELECT SUM(requests) FROM request_samples WHERE route_id=1").Scan(&samples)
	if requests != 40 || samples != 40 {
		t.Fatalf("requests=%d samples=%d", requests, samples)
	}
}
