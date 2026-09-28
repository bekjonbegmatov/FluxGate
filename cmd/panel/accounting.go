package main

import (
	"database/sql"
	"strings"
	"time"
)

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
func (a *App) flushTraffic(now time.Time) error {
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
	for _, s := range a.routeStates() {
		s.mu.Lock()
		r := s.Route
		if r.DailyLimit > 0 && !s.Daily.ThresholdSent && !s.Daily.ExhaustedSent && quotaReachedThreshold(s.Daily.Used, r.DailyLimit+s.Daily.Extra, r.Threshold) {
			s.Daily.ThresholdSent = true
			go a.notify(r, quotaThresholdMessage("daily", s.Daily.Used, r.DailyLimit+s.Daily.Extra))
		}
		if r.MonthlyLimit > 0 && !s.Monthly.ThresholdSent && !s.Monthly.ExhaustedSent && quotaReachedThreshold(s.Monthly.Used, r.MonthlyLimit+s.Monthly.Extra, r.Threshold) {
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
	if len(batch) == 0 {
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
	if err = tx.Commit(); err != nil {
		return err
	}
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

func (a *App) sampleRates(now time.Time) {
	for _, s := range a.routeStates() {
		s.mu.Lock()
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
			if limit > 0 {
				go a.notify(r, quotaResetMessage(kind, limit+p.Extra))
			}
		}
	}
	return nil
}
