package main

import (
	"net"
	"path/filepath"
	"testing"
)

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
		_, _ = c.Write([]byte("# pxname,svname,req_tot,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,scur,rtime\ntarget_7,BACKEND,42,30,3,4,5,2,16\nfallback_page,BACKEND,11,1,0,0,0,0,0\n"))
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
