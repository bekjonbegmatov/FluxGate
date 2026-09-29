package main

import (
	"bytes"
	"encoding/csv"
	"net/http"
	"strings"
	"time"
)

func (a *App) restartAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, 405, "method")
		return
	}
	var v struct {
		Confirm bool `json:"confirm"`
	}
	if readJSON(r, &v) != nil || !v.Confirm {
		fail(w, 400, "restart confirmation required")
		return
	}
	if a.restartService == nil {
		fail(w, 503, "service restart unavailable")
		return
	}
	a.collectDirectTraffic(time.Now())
	if err := a.flushTraffic(time.Now()); err != nil {
		fail(w, 503, "cannot save traffic before restart")
		return
	}
	if !a.restartRequested.CompareAndSwap(false, true) {
		fail(w, 409, "restart already scheduled")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"restarting": true})
	// Give the browser time to receive 202. main performs the graceful drain,
	// final commit and HAProxy restart marker before exiting to its supervisor.
	time.AfterFunc(500*time.Millisecond, a.restartService)
}

func (a *App) quiesceHAProxy() {
	a.collectDirectTraffic(time.Now())
	a.direct.mu.Lock()
	defer a.direct.mu.Unlock()
	for _, w := range a.direct.workers {
		for _, name := range []string{"public_sni", "public_direct", "internal_tls"} {
			_, _ = w.command("disable frontend " + name)
		}
		raw, err := w.command("show stat")
		if err != nil {
			continue
		}
		r := csv.NewReader(bytes.NewReader(raw))
		r.FieldsPerRecord = -1
		rows, err := r.ReadAll()
		if err != nil {
			continue
		}
		for _, row := range rows {
			if len(row) < 2 || row[1] != "BACKEND" || (!strings.HasPrefix(row[0], "direct_") && !strings.HasPrefix(row[0], "target_")) {
				continue
			}
			_ = enforceDirectBackend(w.command, row[0], true)
		}
	}
}
