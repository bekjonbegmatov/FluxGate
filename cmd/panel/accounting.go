package main

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// Keep the existing 90-day retention, but never delete an arbitrarily large
// backlog in one write transaction (which can pin SQLite and inflate WAL).
func (a *App) pruneHistory(ctx context.Context, now time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for _, table := range []string{"samples", "request_samples"} {
		for batch := 0; batch < 8; batch++ {
			if ctx.Err() != nil {
				return nil
			} // Continue backlog at the next tick.
			result, err := a.db.ExecContext(ctx, "DELETE FROM "+table+" WHERE rowid IN (SELECT rowid FROM "+table+" WHERE ts<? ORDER BY ts LIMIT 5000)", now.AddDate(0, 0, -90).Unix())
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
			n, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if n < 5000 {
				break
			}
		}
	}
	return nil
}

func (a *App) initHistoryIndexes() error {
	_, err := a.db.Exec(`CREATE INDEX IF NOT EXISTS samples_ts ON samples(ts);
CREATE INDEX IF NOT EXISTS request_samples_ts ON request_samples(ts);`)
	return err
}

func savePeriod(tx *sql.Tx, id int64, kind string, p Period) error {
	_, err := tx.Exec(`INSERT INTO periods(route_id,kind,key,used,extra,threshold_sent,exhausted_sent) VALUES(?,?,?,?,?,?,?)
ON CONFLICT(route_id,kind,key) DO UPDATE SET used=excluded.used,extra=excluded.extra,threshold_sent=excluded.threshold_sent,exhausted_sent=excluded.exhausted_sent`, id, kind, p.Key, p.Used, p.Extra, boolInt(p.ThresholdSent), boolInt(p.ExhaustedSent))
	return err
}

// No route mutex is held while waiting for SQLite. In particular, backups and
// slow disks must not stall the network. One transaction covers the whole tick.
func (a *App) flushTraffic(now time.Time) (result error) {
	started := time.Now()
	defer func() {
		a.flushLastNS.Store(time.Since(started).Nanoseconds())
		if result != nil {
			a.flushErrors.Add(1)
		} else {
			a.flushLastOK.Store(time.Now().Unix())
		}
	}()
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	type snapshot struct {
		s        *RouteState
		r        Route
		d, m     Period
		up, down int64
		retired  map[string]retiredPeriod
	}
	var batch []snapshot
	a.direct.dataMu.Lock()
	checkpoints := make(map[directKey]directCounter, len(a.direct.pending))
	for k, v := range a.direct.pending {
		checkpoints[k] = v
	}
	direct := !a.quotasEnabled()
	for _, s := range a.routeStates() {
		s.mu.Lock()
		r := s.Route
		if !direct && r.DailyLimit > 0 && !s.Daily.ThresholdSent && !s.Daily.ExhaustedSent && quotaReachedThreshold(s.Daily.Used, r.DailyLimit+s.Daily.Extra, r.Threshold) {
			s.Daily.ThresholdSent = true
			go a.notify(r, quotaThresholdMessage("daily", s.Daily.Used, r.DailyLimit+s.Daily.Extra))
		}
		if !direct && r.MonthlyLimit > 0 && !s.Monthly.ThresholdSent && !s.Monthly.ExhaustedSent && quotaReachedThreshold(s.Monthly.Used, r.MonthlyLimit+s.Monthly.Extra, r.Threshold) {
			s.Monthly.ThresholdSent = true
			go a.notify(r, quotaThresholdMessage("monthly", s.Monthly.Used, r.MonthlyLimit+s.Monthly.Extra))
		}
		if !s.deleted && (r.UpTotal != s.savedUp || r.DownTotal != s.savedDown || s.Daily != s.savedDaily || s.Monthly != s.savedMonthly || s.pendingUp != 0 || s.pendingDown != 0 || len(s.retired) > 0) {
			retired := make(map[string]retiredPeriod, len(s.retired))
			for k, p := range s.retired {
				retired[k] = p
			}
			batch = append(batch, snapshot{s, r, s.Daily, s.Monthly, s.pendingUp, s.pendingDown, retired})
		}
		s.mu.Unlock()
	}
	a.direct.dataMu.Unlock()
	if len(batch) == 0 && len(checkpoints) == 0 {
		return nil
	}
	tx, err := a.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, v := range batch {
		for key, p := range v.retired {
			if err = savePeriod(tx, v.r.ID, strings.SplitN(key, ":", 2)[0], p.Period); err != nil {
				return err
			}
		}
		if _, err = tx.Exec("UPDATE routes SET up_total=?,down_total=? WHERE id=?", v.r.UpTotal, v.r.DownTotal, v.r.ID); err != nil {
			return err
		}
		if err = savePeriod(tx, v.r.ID, "daily", v.d); err != nil {
			return err
		}
		if err = savePeriod(tx, v.r.ID, "monthly", v.m); err != nil {
			return err
		}
		if v.up != 0 || v.down != 0 {
			_, err = tx.Exec("INSERT INTO samples(route_id,ts,up,down) VALUES(?,?,?,?) ON CONFLICT(route_id,ts) DO UPDATE SET up=up+excluded.up,down=down+excluded.down", v.r.ID, now.Unix()/60*60, v.up, v.down)
			if err != nil {
				return err
			}
		}
	}
	if err = saveDirectCheckpoints(tx, checkpoints, now); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	a.direct.dataMu.Lock()
	for key, value := range checkpoints {
		if a.direct.pending[key] == value {
			delete(a.direct.pending, key)
		}
	}
	for key, value := range a.direct.last {
		if value.seen < now.Add(-48*time.Hour).Unix() {
			delete(a.direct.last, key)
		}
	}
	a.direct.dataMu.Unlock()
	for _, v := range batch {
		v.s.mu.Lock()
		v.s.pendingUp -= v.up
		v.s.pendingDown -= v.down
		v.s.savedUp, v.s.savedDown = v.r.UpTotal, v.r.DownTotal
		v.s.savedDaily, v.s.savedMonthly = v.d, v.m
		for key, p := range v.retired {
			if p.reserved == 0 && v.s.retired[key] == p {
				delete(v.s.retired, key)
			}
		}
		v.s.mu.Unlock()
	}
	return nil
}

type trafficRateSample struct {
	at       time.Time
	up, down int64
}

func (a *App) sampleRates(now time.Time) {
	direct := a.directMode()
	for _, s := range a.routeStates() {
		s.mu.Lock()
		if direct {
			// HAProxy contstats updates long streams approximately every 5s.
			// A 10s window avoids displaying one-second spikes and false zeros.
			if len(s.rateHistory) == 0 {
				at := s.rateAt
				if at.IsZero() {
					at = now.Add(-time.Second)
				}
				s.rateHistory = append(s.rateHistory, trafficRateSample{at, s.rateUp, s.rateDown})
			}
			s.rateHistory = append(s.rateHistory, trafficRateSample{now, s.Route.UpTotal, s.Route.DownTotal})
			for len(s.rateHistory) > 2 && !s.rateHistory[1].at.After(now.Add(-10*time.Second)) {
				s.rateHistory = s.rateHistory[1:]
			}
			first := s.rateHistory[0]
			elapsed := max(1, now.Sub(first.at).Seconds())
			s.lastUp = int64(float64(s.Route.UpTotal-first.up) / elapsed)
			s.lastDown = int64(float64(s.Route.DownTotal-first.down) / elapsed)
			s.rateUp, s.rateDown, s.rateAt = s.Route.UpTotal, s.Route.DownTotal, now
			s.mu.Unlock()
			continue
		}
		s.rateHistory = nil
		elapsed := now.Sub(s.rateAt).Seconds()
		if s.rateAt.IsZero() || elapsed <= 0 {
			elapsed = 1
		}
		s.lastUp = int64(float64(s.Route.UpTotal-s.rateUp) / elapsed)
		s.lastDown = int64(float64(s.Route.DownTotal-s.rateDown) / elapsed)
		s.rateUp, s.rateDown, s.rateAt = s.Route.UpTotal, s.Route.DownTotal, now
		s.mu.Unlock()
	}
}

func (a *App) rollPeriods(now time.Time) error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	for _, s := range a.routeStates() {
		s.mu.Lock()
		r := s.Route
		dk, mk := a.periodKey(r, "daily", now), a.periodKey(r, "monthly", now)
		oldD, oldM := s.Daily.Key, s.Monthly.Key
		s.mu.Unlock()
		for _, kind := range []string{"daily", "monthly"} {
			key, old := dk, oldD
			if kind == "monthly" {
				key, old = mk, oldM
			}
			if key == old {
				continue
			}
			p, err := a.loadPeriod(r.ID, kind, key)
			if err != nil {
				return err
			}
			s.mu.Lock()
			if s.retired == nil {
				s.retired = map[string]retiredPeriod{}
			}
			previous := s.Daily
			reserved := s.reservedDaily
			limit := r.DailyLimit
			if kind == "monthly" {
				previous, limit = s.Monthly, r.MonthlyLimit
				reserved = s.reservedMonthly
				s.Monthly = p
				s.reservedMonthly = 0
			} else {
				s.Daily = p
				s.reservedDaily = 0
			}
			s.retired[kind+":"+previous.Key] = retiredPeriod{previous, reserved}
			s.mu.Unlock()
			if limit > 0 && a.quotasEnabled() {
				go a.notify(r, quotaResetMessage(kind, limit+p.Extra))
			}
		}
	}
	return nil
}
