package main

import (
	"testing"
	"time"
)

func TestMonthlyPeriodUsesCreationDayAndLastDay(t *testing.T) {
	loc := time.FixedZone("UTC+3", 3*3600)
	a := &App{location: loc}
	created := time.Date(2026, time.January, 31, 14, 0, 0, 0, loc)
	r := Route{CreatedAt: created.Unix()}
	cases := []struct {
		now  time.Time
		want string
	}{
		{time.Date(2026, time.February, 27, 23, 59, 0, 0, loc), "2026-01-31"},
		{time.Date(2026, time.February, 28, 0, 0, 0, 0, loc), "2026-02-28"},
		{time.Date(2026, time.March, 30, 23, 59, 0, 0, loc), "2026-02-28"},
		{time.Date(2026, time.March, 31, 0, 0, 0, 0, loc), "2026-03-31"},
	}
	for _, c := range cases {
		if got := a.periodKey(r, "monthly", c.now); got != c.want {
			t.Errorf("%v: got %q, want %q", c.now, got, c.want)
		}
	}
}

func TestQuotaModesAndTopup(t *testing.T) {
	for _, mode := range []string{"up", "down", "both"} {
		s := &RouteState{Route: Route{CountMode: mode, DailyLimit: 100}, Daily: Period{Used: 100}}
		if !s.blocked() {
			t.Fatalf("%s should be blocked", mode)
		}
		s.Daily.Extra = 50
		if s.blocked() {
			t.Fatalf("%s should be open after topup", mode)
		}
		if s.counted(true) != (mode == "up" || mode == "both") || s.counted(false) != (mode == "down" || mode == "both") {
			t.Fatalf("wrong count mode: %s", mode)
		}
	}
}

func TestDomainValidation(t *testing.T) {
	for _, v := range []string{"api.example.com", "*.api.example.com"} {
		if !validSNI(v) {
			t.Fatalf("rejected %q", v)
		}
	}
	for _, v := range []string{"*.com", "api.example.com;evil", "foo bar.example.com", "*.*.example.com"} {
		if validSNI(v) {
			t.Fatalf("accepted %q", v)
		}
	}
}
