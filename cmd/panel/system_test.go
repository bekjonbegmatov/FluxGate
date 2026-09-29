package main

import "testing"

func TestCPUBreakdownExcludesWaitAndGuestDoubleCount(t *testing.T) {
	before, ok := parseCPUCounters([]byte("cpu 100 0 100 700 50 0 50 0 20 0\ncpu0 0\n"))
	if !ok || before.total != 1000 {
		t.Fatalf("guest double counted: %+v", before)
	}
	after, ok := parseCPUCounters([]byte("cpu 120 0 120 710 80 0 60 10 30 0\n"))
	if !ok {
		t.Fatal("parse failed")
	}
	u := cpuDelta(after, before)
	if u.busy != 50 || u.wait != 30 || u.softirq != 10 || u.steal != 10 {
		t.Fatalf("wrong CPU breakdown: %+v", u)
	}
	if _, ok := parseCPUCounters([]byte("cpu broken data")); ok {
		t.Fatal("invalid counters accepted")
	}
}
