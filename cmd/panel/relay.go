package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

func (a *App) startListeners() error {
	fallback, err := net.Listen("tcp", "127.0.0.1:9999")
	if err != nil {
		return err
	}
	go func() {
		for {
			c, e := fallback.Accept()
			if e != nil {
				return
			}
			go relayFallback(c)
		}
	}()
	a.mu.RLock()
	routes := make([]*RouteState, 0, len(a.routes))
	for _, s := range a.routes {
		routes = append(routes, s)
	}
	a.mu.RUnlock()
	for _, s := range routes {
		if err := a.listenRoute(s); err != nil {
			return err
		}
	}
	return nil
}
func relayFallback(client net.Conn) {
	defer client.Close()
	up, err := net.DialTimeout("tcp", "127.0.0.1:8443", 5*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	go func() {
		_, _ = io.Copy(up, client)
		if t, ok := up.(*net.TCPConn); ok {
			_ = t.CloseWrite()
		}
	}()
	_, _ = io.Copy(client, up)
}
func (a *App) listenRoute(s *RouteState) error {
	addr := fmt.Sprintf("127.0.0.1:%d", 10000+s.Route.ID)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.Listener = l
	s.mu.Unlock()
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go a.handleConn(s, c)
		}
	}()
	go a.checkHealth(s)
	return nil
}
func (a *App) checkHealth(s *RouteState) {
	s.mu.Lock()
	addr := net.JoinHostPort(s.Route.IP, fmt.Sprint(s.Route.Port))
	s.mu.Unlock()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err == nil {
		_ = c.Close()
	}
	s.mu.Lock()
	s.healthy = err == nil
	s.mu.Unlock()
}
func (a *App) handleConn(s *RouteState, client net.Conn) {
	upstream, err := net.DialTimeout("tcp", "127.0.0.1:8443", 5*time.Second)
	if err != nil {
		_ = client.Close()
		return
	}
	s.mu.Lock()
	blockedOnEntry := s.blocked() || s.Route.Paused
	s.conns[client] = struct{}{}
	s.mu.Unlock()
	defer func() { _ = client.Close(); _ = upstream.Close(); s.mu.Lock(); delete(s.conns, client); s.mu.Unlock() }()
	if blockedOnEntry {
		go func() {
			_, _ = io.Copy(upstream, client)
			if t, ok := upstream.(*net.TCPConn); ok {
				_ = t.CloseWrite()
			}
		}()
		_, _ = io.Copy(client, upstream)
		return
	}
	var once sync.Once
	stop := func() { once.Do(func() { _ = client.Close(); _ = upstream.Close() }) }
	done := make(chan struct{})
	go func() {
		a.copyMetered(s, upstream, client, true, stop)
		if t, ok := upstream.(*net.TCPConn); ok {
			_ = t.CloseWrite()
		}
		close(done)
	}()
	a.copyMetered(s, client, upstream, false, stop)
	if t, ok := client.(*net.TCPConn); ok {
		_ = t.CloseWrite()
	}
	<-done
}
func (a *App) copyMetered(s *RouteState, dst, src net.Conn, up bool, stop func()) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			offset := 0
			for offset < n {
				s.mu.Lock()
				blocked := s.blocked()
				paused := s.Route.Paused
				if blocked || paused {
					s.mu.Unlock()
					if blocked || paused {
						stop()
						return
					}
				}
				limit := s.Route.DownBPS
				bucket := &s.downBucket
				if up {
					limit = s.Route.UpBPS
					bucket = &s.upBucket
				}
				allowed := n - offset
				if s.counted(up) {
					if s.Route.DailyLimit > 0 {
						left := s.Route.DailyLimit + s.Daily.Extra - s.Daily.Used
						if int64(allowed) > left {
							allowed = int(left)
						}
					}
					if s.Route.MonthlyLimit > 0 {
						left := s.Route.MonthlyLimit + s.Monthly.Extra - s.Monthly.Used
						if int64(allowed) > left {
							allowed = int(left)
						}
					}
				}
				if allowed <= 0 {
					s.mu.Unlock()
					a.exhaust(s)
					stop()
					return
				}
				if limit > 0 {
					now := time.Now()
					if bucket.last.IsZero() {
						bucket.last = now
						bucket.tokens = float64(limit)
					} else {
						bucket.tokens += now.Sub(bucket.last).Seconds() * float64(limit)
						if bucket.tokens > float64(limit) {
							bucket.tokens = float64(limit)
						}
						bucket.last = now
					}
					if bucket.tokens < 1 {
						s.mu.Unlock()
						time.Sleep(10 * time.Millisecond)
						continue
					}
					if float64(allowed) > bucket.tokens {
						allowed = int(bucket.tokens)
					}
					bucket.tokens -= float64(allowed)
				}
				if up {
					s.Route.UpTotal += int64(allowed)
					s.pendingUp += int64(allowed)
				} else {
					s.Route.DownTotal += int64(allowed)
					s.pendingDown += int64(allowed)
				}
				if s.counted(up) {
					s.Daily.Used += int64(allowed)
					s.Monthly.Used += int64(allowed)
				}
				newBlocked := s.blocked()
				s.mu.Unlock()
				written, e := dst.Write(buf[offset : offset+allowed])
				offset += written
				if e != nil || written != allowed {
					stop()
					return
				}
				if newBlocked {
					a.exhaust(s)
					stop()
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}
func (a *App) exhaust(s *RouteState) {
	s.mu.Lock()
	r := s.Route
	daily := r.DailyLimit > 0 && s.Daily.Used >= r.DailyLimit+s.Daily.Extra
	monthly := r.MonthlyLimit > 0 && s.Monthly.Used >= r.MonthlyLimit+s.Monthly.Extra
	first := (daily && !s.Daily.ExhaustedSent) || (monthly && !s.Monthly.ExhaustedSent)
	if daily && !s.Daily.ExhaustedSent {
		s.Daily.ExhaustedSent = true
		s.Daily.ThresholdSent = true
		go a.notify(r, quotaExhaustedMessage("daily", s.Daily.Used, r.DailyLimit+s.Daily.Extra))
	}
	if monthly && !s.Monthly.ExhaustedSent {
		s.Monthly.ExhaustedSent = true
		s.Monthly.ThresholdSent = true
		go a.notify(r, quotaExhaustedMessage("monthly", s.Monthly.Used, r.MonthlyLimit+s.Monthly.Extra))
	}
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	if !first {
		return
	}
	if err := a.writeConfig(); err != nil {
		log.Printf("quota config: %v", err)
	}
}
func (a *App) tick() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for now := range t.C {
		a.mu.RLock()
		routes := make([]*RouteState, 0, len(a.routes))
		for _, s := range a.routes {
			routes = append(routes, s)
		}
		a.mu.RUnlock()
		changed := false
		for _, s := range routes {
			if now.Unix()%10 == 0 {
				go a.checkHealth(s)
			}
			s.mu.Lock()
			before := s.blocked()
			if a.refreshPeriods(s, now) {
				changed = true
			}
			after := s.blocked()
			if before != after {
				changed = true
			}
			r := s.Route
			up, down := s.pendingUp, s.pendingDown
			s.lastUp, s.lastDown = up, down
			s.pendingUp = 0
			s.pendingDown = 0
			if r.DailyLimit > 0 && !s.Daily.ThresholdSent && !s.Daily.ExhaustedSent && quotaReachedThreshold(s.Daily.Used, r.DailyLimit+s.Daily.Extra, r.Threshold) {
				s.Daily.ThresholdSent = true
				go a.notify(r, quotaThresholdMessage("daily", s.Daily.Used, r.DailyLimit+s.Daily.Extra))
			}
			if r.MonthlyLimit > 0 && !s.Monthly.ThresholdSent && !s.Monthly.ExhaustedSent && quotaReachedThreshold(s.Monthly.Used, r.MonthlyLimit+s.Monthly.Extra, r.Threshold) {
				s.Monthly.ThresholdSent = true
				go a.notify(r, quotaThresholdMessage("monthly", s.Monthly.Used, r.MonthlyLimit+s.Monthly.Extra))
			}
			d, m := s.Daily, s.Monthly
			s.mu.Unlock()
			if up == 0 && down == 0 && !changed {
				continue
			}
			tx, err := a.db.Begin()
			if err != nil {
				log.Printf("db: %v", err)
				continue
			}
			_, err = tx.Exec("UPDATE routes SET up_total=?,down_total=? WHERE id=?", r.UpTotal, r.DownTotal, r.ID)
			if err == nil {
				_, err = tx.Exec("INSERT INTO periods(route_id,kind,key,used,extra,threshold_sent,exhausted_sent) VALUES(?,?,?,?,?,?,?) ON CONFLICT(route_id,kind,key) DO UPDATE SET used=excluded.used,extra=excluded.extra,threshold_sent=excluded.threshold_sent,exhausted_sent=excluded.exhausted_sent", r.ID, "daily", d.Key, d.Used, d.Extra, boolInt(d.ThresholdSent), boolInt(d.ExhaustedSent))
			}
			if err == nil {
				_, err = tx.Exec("INSERT INTO periods(route_id,kind,key,used,extra,threshold_sent,exhausted_sent) VALUES(?,?,?,?,?,?,?) ON CONFLICT(route_id,kind,key) DO UPDATE SET used=excluded.used,extra=excluded.extra,threshold_sent=excluded.threshold_sent,exhausted_sent=excluded.exhausted_sent", r.ID, "monthly", m.Key, m.Used, m.Extra, boolInt(m.ThresholdSent), boolInt(m.ExhaustedSent))
			}
			if err == nil && up+down > 0 {
				minute := now.Unix() / 60 * 60
				_, err = tx.Exec("INSERT INTO samples(route_id,ts,up,down) VALUES(?,?,?,?) ON CONFLICT(route_id,ts) DO UPDATE SET up=up+excluded.up,down=down+excluded.down", r.ID, minute, up, down)
			}
			if err != nil {
				_ = tx.Rollback()
				log.Printf("db: %v", err)
			} else if err = tx.Commit(); err != nil {
				log.Printf("db commit: %v", err)
			}
		}
		if changed {
			if err := a.writeConfig(); err != nil {
				log.Printf("period config: %v", err)
			}
		}
		if now.Minute() == 0 && now.Second() == 0 {
			_, _ = a.db.Exec("DELETE FROM samples WHERE ts<?", now.AddDate(0, 0, -90).Unix())
		}
	}
}
