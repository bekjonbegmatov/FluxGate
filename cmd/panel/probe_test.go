package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPublicProbeRequiresTLSAndHTTP(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := probeHTTPS(ctx, strings.TrimPrefix(srv.URL, "https://"), "fallback.example.test"); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		c, e := l.Accept()
		if e == nil {
			defer c.Close()
			<-done
		}
	}()
	defer close(done)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()
	if err := probeHTTPS(ctx2, l.Addr().String(), "fallback.example.test"); err == nil {
		t.Fatal("bare accepting TCP listener reported healthy")
	}
}
