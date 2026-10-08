package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"time"
)

// Each tunnel holds TWO buffers even when idle. Keep the per-connection
// footprint bounded; 10,000 tunnels used to pin 1.22 GiB in 64 KiB buffers.
const relayBufferSize = 16 * 1024
const relayIdleTimeout = time.Hour
const relayHalfCloseIdleTimeout = 30 * time.Second

var relayBuffers = sync.Pool{New: func() any { b := make([]byte, relayBufferSize); return &b }}

// Closing either side interrupts writes and rate-limit waits on the other.
type relayConn struct {
	net.Conn
	upstream  net.Conn
	done      chan struct{}
	once      sync.Once
	tlsStream bool
}

func (c *relayConn) Close() error {
	c.once.Do(func() {
		close(c.done)
		// Both pumps have drained (or setup was cancelled). An upstream FIN
		// alone can leave HAProxy's inner TLS/WebSocket stream half-open for
		// the full tunnel timeout after the outer client has disappeared.
		// Reset ONLY the inner hop; keep a normal close towards the outer
		// frontend so already forwarded response bytes are not discarded.
		if tcp, ok := c.upstream.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		_ = c.upstream.Close()
		_ = c.Conn.Close()
	})
	return nil
}

// For cancellation (pause, quota, shutdown or a transport error), a reset tells
// HAProxy that the upstream must be abandoned, even if it ignores a half-close.
// Normal EOF still uses CloseWrite and drains the response before Close.
func (c *relayConn) abort() {
	c.once.Do(func() {
		close(c.done)
		for _, conn := range []net.Conn{c.Conn, c.upstream} {
			if tcp, ok := conn.(*net.TCPConn); ok {
				_ = tcp.SetLinger(0)
			}
			_ = conn.Close()
		}
	})
}
func (a *App) routeStates() []*RouteState {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]*RouteState, 0, len(a.routes))
	for _, s := range a.routes {
		out = append(out, s)
	}
	return out
}
func (a *App) startListeners() error {
	l, err := listenPrivateSocket(relaySocket(a.data, 0))
	if err != nil {
		return err
	}
	a.fallbackListener = l
	a.acceptRelay(l, nil)
	for _, s := range a.routeStates() {
		if err := a.listenRoute(s); err != nil {
			return err
		}
	}
	return nil
}
func (a *App) listenRoute(s *RouteState) error {
	s.mu.Lock()
	id := s.Route.ID
	s.mu.Unlock()
	l, err := listenPrivateSocket(relaySocket(a.data, id))
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.Listener = l
	s.mu.Unlock()
	a.acceptRelay(l, s)
	return nil
}
func (a *App) acceptRelay(l net.Listener, s *RouteState) {
	a.listenersWG.Add(1)
	go func() {
		defer a.listenersWG.Done()
		var delay time.Duration
		for {
			c, err := l.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) || a.closing.Load() {
					return
				}
				// EMFILE must not silently abandon an open listener.
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else {
					delay *= 2
				}
				if delay > time.Second {
					delay = time.Second
				}
				log.Printf("relay accept: %v; retrying in %s", err, delay)
				time.Sleep(delay)
				continue
			}
			delay = 0
			if !a.acquireRelay() {
				_ = c.Close()
				continue
			}
			a.relayWG.Add(1)
			go func() {
				defer a.relayWG.Done()
				defer a.relayAdmitted.Add(-1)
				a.handleConn(s, c)
			}()
		}
	}()
}
func (a *App) stopRelays() {
	a.closing.Store(true)
	if a.fallbackListener != nil {
		_ = a.fallbackListener.Close()
	}
	states := a.routeStates()
	for _, s := range states {
		s.mu.Lock()
		if s.Listener != nil {
			_ = s.Listener.Close()
		}
		s.mu.Unlock()
	}
	a.listenersWG.Wait()
	for _, s := range states {
		a.closeRouteConns(s)
	}
	a.fallbackConns.Range(func(key, _ any) bool { key.(*relayConn).abort(); return true })
	a.relayWG.Wait()
}
func (a *App) handleConn(s *RouteState, client net.Conn) {
	defer client.Close()
	if a.closing.Load() {
		return
	}
	var r Route
	if s != nil {
		s.mu.Lock()
		r = s.Route
		blocked, deleted := s.blocked(), s.deleted
		s.mu.Unlock()
		if deleted {
			return
		}
		if blocked || r.Paused {
			// Never tunnel blocked traffic unmetered while HAProxy is reloading.
			a.rejectConn(client, r)
			return
		}
	}
	address := net.JoinHostPort(r.IP, fmt.Sprint(r.Port))
	if !r.TLSPassthrough {
		var releaseIngress func()
		address, releaseIngress = a.relayIngress.acquire()
		defer releaseIngress()
	}
	upstream, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return
	}
	pair := &relayConn{Conn: client, upstream: upstream, done: make(chan struct{}), tlsStream: true}
	defer pair.Close()
	if s != nil {
		s.mu.Lock()
		if a.closing.Load() || s.deleted || s.Route.Paused || s.blocked() ||
			s.Route.TLSPassthrough != r.TLSPassthrough || s.Route.IP != r.IP || s.Route.Port != r.Port {
			s.mu.Unlock()
			return
		}
		s.conns[pair] = struct{}{}
		s.mu.Unlock()
		defer func() { s.mu.Lock(); delete(s.conns, pair); s.mu.Unlock() }()
	} else {
		a.fallbackConns.Store(pair, struct{}{})
		defer a.fallbackConns.Delete(pair)
		if a.closing.Load() {
			return
		}
	}
	a.relayDuplex(s, pair)
}
func (a *App) rejectConn(client net.Conn, r Route) {
	// A passthrough endpoint must never impersonate the origin, even to return
	// a quota error. Closing TCP is the only response without terminating TLS.
	if r.TLSPassthrough {
		return
	}
	certPath := filepath.Join(a.data, "certs", routeCert(r)+".pem")
	cert, err := tls.LoadX509KeyPair(certPath, certPath)
	if err != nil {
		return
	}
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	c := tls.Server(client, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	if err := c.Handshake(); err != nil {
		return
	}
	if _, err := http.ReadRequest(bufio.NewReader(io.LimitReader(c, 32<<10))); err != nil {
		return
	}
	status := http.StatusTooManyRequests
	if r.Paused {
		status = http.StatusServiceUnavailable
	}
	body := http.StatusText(status) + "\n"
	_, _ = fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), len(body), body)
	_ = c.Close()
}
func (a *App) relayDuplex(s *RouteState, pair *relayConn) {
	done := make(chan struct{}, 2)
	drain := &relayDrain{upstream: pair.upstream, client: pair.Conn}
	pump := func(dst, src net.Conn, up bool) {
		copyDst, copySrc := dst, src
		if pair.tlsStream && !up {
			copySrc = &drainReadConn{Conn: src, drain: drain}
			copyDst = &drainWriteConn{Conn: dst, drain: drain}
		}
		err := a.copyMetered(s, copyDst, copySrc, up, pair.done)
		if err != nil {
			pair.abort()
		} else if up && pair.tlsStream {
			// TLS close_notify, if present, has already been forwarded. Do not
			// send a transport FIN into the TLS frontend: HAProxy can retain an
			// upgraded upstream after that FIN even after Go closes its socket.
			// Drain responses with a short IDLE timeout, not a total deadline;
			// active large responses still finish. Truncated TLS then gets RST.
			drain.begin()
		} else if half, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		}
		done <- struct{}{}
	}
	go pump(pair.upstream, pair.Conn, true)
	pump(pair.Conn, pair.upstream, false)
	<-done
	<-done
}

type relayDrain struct {
	mu               sync.Mutex
	active           bool
	upstream, client net.Conn
}

func (d *relayDrain) begin() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.active = true
	deadline := time.Now().Add(relayHalfCloseIdleTimeout)
	_ = d.upstream.SetReadDeadline(deadline)
	_ = d.client.SetWriteDeadline(deadline)
}
func (d *relayDrain) deadline(t time.Time) time.Time {
	if d.active {
		return minTime(t, time.Now().Add(relayHalfCloseIdleTimeout))
	}
	return t
}
func minTime(a, b time.Time) time.Time {
	if a.IsZero() || b.Before(a) {
		return b
	}
	return a
}

type drainReadConn struct {
	net.Conn
	drain *relayDrain
}

func (c *drainReadConn) SetReadDeadline(t time.Time) error {
	c.drain.mu.Lock()
	defer c.drain.mu.Unlock()
	return c.Conn.SetReadDeadline(c.drain.deadline(t))
}

type drainWriteConn struct {
	net.Conn
	drain *relayDrain
}

func (c *drainWriteConn) SetWriteDeadline(t time.Time) error {
	c.drain.mu.Lock()
	defer c.drain.mu.Unlock()
	return c.Conn.SetWriteDeadline(c.drain.deadline(t))
}

// take applies one shared bucket per route and direction, with s.mu held.
func (b *bucket) take(want int, rate int64, now time.Time) (int, time.Duration) {
	if rate <= 0 {
		b.rate = 0
		b.last = time.Time{}
		return want, 0
	}
	if b.last.IsZero() || b.rate == 0 {
		b.tokens = float64(rate)
	} else {
		b.tokens += now.Sub(b.last).Seconds() * float64(b.rate)
	}
	b.last, b.rate = now, rate
	if b.tokens > float64(rate) {
		b.tokens = float64(rate)
	}
	if b.tokens < 1 {
		target := min(float64(want), max(1, float64(rate)/100))
		return 0, max(time.Millisecond, time.Duration((target-b.tokens)/float64(rate)*float64(time.Second)))
	}
	n := min(want, int(b.tokens))
	b.tokens -= float64(n)
	return n, 0
}
func waitRelay(done <-chan struct{}, delay time.Duration) error {
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-done:
		return net.ErrClosed
	case <-t.C:
		return nil
	}
}
func (a *App) copyMetered(s *RouteState, dst, src net.Conn, up bool, done <-chan struct{}) error {
	p := relayBuffers.Get().(*[]byte)
	defer relayBuffers.Put(p)
	buf := *p
	for {
		_ = src.SetReadDeadline(time.Now().Add(relayIdleTimeout))
		n, readErr := src.Read(buf)
		for offset := 0; offset < n; {
			allowed := n - offset
			var dk, mk string
			var counted bool
			if s != nil {
				s.mu.Lock()
				if s.deleted || s.Route.Paused || s.blocked() {
					s.mu.Unlock()
					return net.ErrClosed
				}
				counted = s.counted(up)
				if counted {
					if s.Route.DailyLimit > 0 {
						allowed = min(allowed, int(max(0, s.Route.DailyLimit+s.Daily.Extra-s.Daily.Used-s.reservedDaily)))
					}
					if s.Route.MonthlyLimit > 0 {
						allowed = min(allowed, int(max(0, s.Route.MonthlyLimit+s.Monthly.Extra-s.Monthly.Used-s.reservedMonthly)))
					}
				}
				if allowed == 0 {
					s.mu.Unlock()
					if err := waitRelay(done, time.Millisecond); err != nil {
						return err
					}
					continue
				}
				limit, b := s.Route.DownBPS, &s.downBucket
				if up {
					limit, b = s.Route.UpBPS, &s.upBucket
				}
				var delay time.Duration
				allowed, delay = b.take(allowed, limit, time.Now())
				if delay > 0 {
					s.mu.Unlock()
					if err := waitRelay(done, delay); err != nil {
						return err
					}
					continue
				}
				if counted {
					dk, mk = s.Daily.Key, s.Monthly.Key
					s.reservedDaily += int64(allowed)
					s.reservedMonthly += int64(allowed)
				}
				s.mu.Unlock()
			}
			_ = dst.SetWriteDeadline(time.Now().Add(relayIdleTimeout))
			written, err := dst.Write(buf[offset : offset+allowed])
			offset += written
			if s != nil {
				s.mu.Lock()
				if up {
					s.Route.UpTotal += int64(written)
					s.pendingUp += int64(written)
				} else {
					s.Route.DownTotal += int64(written)
					s.pendingDown += int64(written)
				}
				if counted {
					if s.Daily.Key == dk {
						s.reservedDaily -= int64(allowed)
						s.Daily.Used += int64(written)
					} else if p, ok := s.retired["daily:"+dk]; ok {
						p.reserved -= int64(allowed)
						p.Used += int64(written)
						s.retired["daily:"+dk] = p
					}
					if s.Monthly.Key == mk {
						s.reservedMonthly -= int64(allowed)
						s.Monthly.Used += int64(written)
					} else if p, ok := s.retired["monthly:"+mk]; ok {
						p.reserved -= int64(allowed)
						p.Used += int64(written)
						s.retired["monthly:"+mk] = p
					}
				}
				blocked := s.blocked()
				s.mu.Unlock()
				if blocked {
					a.exhaust(s)
					return net.ErrClosed
				}
			}
			if err != nil {
				return err
			}
			if written != allowed {
				return io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}
func (a *App) exhaust(s *RouteState) {
	s.mu.Lock()
	r := s.Route
	daily := r.DailyLimit > 0 && s.Daily.Used >= r.DailyLimit+s.Daily.Extra
	monthly := r.MonthlyLimit > 0 && s.Monthly.Used >= r.MonthlyLimit+s.Monthly.Extra
	if daily && !s.Daily.ExhaustedSent {
		s.Daily.ExhaustedSent, s.Daily.ThresholdSent = true, true
		go a.notify(r, quotaExhaustedMessage("daily", s.Daily.Used, r.DailyLimit+s.Daily.Extra))
	}
	if monthly && !s.Monthly.ExhaustedSent {
		s.Monthly.ExhaustedSent, s.Monthly.ThresholdSent = true, true
		go a.notify(r, quotaExhaustedMessage("monthly", s.Monthly.Used, r.MonthlyLimit+s.Monthly.Extra))
	}
	s.mu.Unlock()
	a.closeRouteConns(s)
	// Quota changes are enforced locally and need neither disk I/O nor reload.
}
func (a *App) checkHealth(s *RouteState) {
	s.mu.Lock()
	r := s.Route
	s.mu.Unlock()
	c, err := net.DialTimeout("tcp", net.JoinHostPort(r.IP, fmt.Sprint(r.Port)), 2*time.Second)
	if err == nil {
		_ = c.Close()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleted || r.IP != s.Route.IP || r.Port != s.Route.Port {
		return
	}
	s.healthy = err == nil
	now := time.Now()
	if err == nil {
		if s.alertSent && s.Route.Monitor {
			go a.notify(r, fmt.Sprintf("Доступ к конечному серверу восстановлен: %s:%d.", r.IP, r.Port))
		}
		s.unhealthySince, s.alertSent = time.Time{}, false
	} else if s.Route.Monitor {
		if s.unhealthySince.IsZero() {
			s.unhealthySince = now
		}
		if !s.alertSent && now.Sub(s.unhealthySince) >= 5*time.Minute {
			s.alertSent = true
			go a.notify(r, fmt.Sprintf("Конечный сервер не отвечает более 5 минут. Адрес: %s:%d.", r.IP, r.Port))
		}
	} else {
		s.unhealthySince, s.alertSent = time.Time{}, false
	}
}
func (a *App) tick(ctx context.Context) {
	var workers sync.WaitGroup
	// Fixed workers cannot pile up when SQLite or a health probe is slow.
	run := func(interval time.Duration, fn func(time.Time)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			t := time.NewTicker(interval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case now := <-t.C:
					fn(now)
				}
			}
		}()
	}
	run(10*time.Second, a.collectRequestStats)
	run(time.Second, a.collectDirectTraffic)
	run(time.Second, a.sampleRates)
	run(15*time.Second, a.probePublic)
	run(time.Minute, a.checkRentals)
	run(10*time.Second, func(_ time.Time) {
		limit := make(chan struct{}, 16)
		var wg sync.WaitGroup
		for _, s := range a.routeStates() {
			select {
			case <-ctx.Done():
				wg.Wait()
				return
			case limit <- struct{}{}:
			}
			wg.Add(1)
			go func(s *RouteState) { defer wg.Done(); defer func() { <-limit }(); a.checkHealth(s) }(s)
		}
		wg.Wait()
	})
	run(time.Minute, func(now time.Time) {
		if err := a.pruneHistory(ctx, now); err != nil {
			log.Printf("history cleanup: %v", err)
		}
	})
	t := time.NewTicker(time.Second)
	defer t.Stop()
	defer workers.Wait()
	interval := a.flushInterval
	if interval == 0 {
		interval = 5 * time.Second
	}
	lastFlush := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if now.Sub(lastFlush) >= interval {
				if err := a.flushTraffic(now); err != nil {
					log.Printf("traffic persistence: %v", err)
				}
				lastFlush = now
			}
			if err := a.rollPeriods(now); err != nil {
				log.Printf("quota rollover: %v", err)
			}
		}
	}
}
