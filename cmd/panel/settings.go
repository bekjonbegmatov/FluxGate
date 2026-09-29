package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func (a *App) updateSettings(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Domain       string  `json:"domain"`
		ProxyMode    *string `json:"proxy_mode"`
		DirectLimits *bool   `json:"direct_limits"`
		FallbackHTML string  `json:"fallback_html"`
		TGAPI        string  `json:"tg_api"`
		TGChat       string  `json:"tg_chat"`
		TGToken      string  `json:"tg_token"`
	}
	if readJSON(r, &v) != nil {
		fail(w, 400, "invalid JSON")
		return
	}
	if len(v.FallbackHTML) > 1<<20 {
		fail(w, 400, "HTML too large")
		return
	}
	v.Domain = strings.ToLower(strings.TrimSpace(v.Domain))
	if v.Domain != "" && !validDomain(v.Domain) {
		fail(w, 400, "invalid domain")
		return
	}
	if v.ProxyMode != nil && !validProxyMode(*v.ProxyMode) {
		fail(w, 400, "proxy_mode must be relay or direct")
		return
	}
	u, err := url.Parse(v.TGAPI)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		fail(w, 400, "Bot API URL must use HTTPS")
		return
	}
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	a.mu.RLock()
	oldDomain, oldMode, oldTG := a.domain, a.proxyMode, a.tg
	oldLimits := a.directLimits
	a.mu.RUnlock()
	mode := oldMode
	limits := oldLimits
	if v.DirectLimits != nil {
		limits = *v.DirectLimits
	}
	if mode == "" {
		mode = "relay"
	}
	if v.ProxyMode != nil {
		mode = *v.ProxyMode
	}
	if v.Domain == "" {
		v.Domain = oldDomain
	}
	if mode == "direct" && oldMode != "direct" {
		// Do not enable a path whose counters cannot be read on an older/native
		// installation. The default Docker image includes supported HAProxy 3.2.
		worker, e := openMeterWorker(filepath.Join(a.data, "haproxy.sock"))
		if e != nil {
			fail(w, 503, "direct mode requires a reachable HAProxy 3.2 Runtime API")
			return
		}
		worker.conn.Close()
	}
	for _, s := range a.routeStates() {
		s.mu.Lock()
		sni := s.Route.SNI
		s.mu.Unlock()
		if v.Domain != oldDomain && (sni == v.Domain || (strings.HasPrefix(sni, "*.") && strings.HasSuffix(v.Domain, sni[1:]))) {
			fail(w, 409, "domain is already used by a server route")
			return
		}
	}
	certPath := filepath.Join(a.data, "certs", "fallback.pem")
	var oldCert []byte
	if v.Domain != oldDomain {
		oldCert, err = os.ReadFile(certPath)
		if err == nil {
			err = a.ensureCert("fallback", v.Domain)
		}
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
	}
	changed := v.Domain != oldDomain || mode != oldMode || limits != oldLimits
	a.mu.Lock()
	a.domain, a.proxyMode = v.Domain, mode
	a.directLimits = limits
	a.mu.Unlock()
	rollback := func() {
		a.mu.Lock()
		a.domain, a.proxyMode = oldDomain, oldMode
		a.directLimits = oldLimits
		a.mu.Unlock()
		if oldCert != nil {
			_ = os.WriteFile(certPath, oldCert, 0600)
		}
		if changed {
			_ = a.writeConfig()
		}
	}
	if changed {
		err = a.writeConfig()
	}
	if err != nil {
		rollback()
		fail(w, 500, err.Error())
		return
	}
	tg := TelegramSettings{APIURL: strings.TrimRight(v.TGAPI, "/"), ChatID: v.TGChat, BotToken: oldTG.BotToken}
	if v.TGToken != "" {
		tg.BotToken = v.TGToken
	}
	values := map[string]string{"domain": v.Domain, "proxy_mode": mode, "fallback_html": v.FallbackHTML, "tg_api": tg.APIURL, "tg_chat": tg.ChatID}
	values["direct_limits"] = strconv.FormatBool(limits)
	if v.TGToken != "" {
		values["tg_token"] = a.encrypt(tg.BotToken)
	}
	tx, err := a.db.Begin()
	if err == nil {
		defer tx.Rollback()
		for key, value := range values {
			if _, err = tx.Exec("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value); err != nil {
				break
			}
		}
		if err == nil {
			err = tx.Commit()
		}
	}
	if err != nil {
		if tx != nil {
			_ = tx.Rollback()
		}
		rollback()
		fail(w, 500, fmt.Sprintf("settings not saved: %v", err))
		return
	}
	a.mu.Lock()
	a.fallback, a.tg = v.FallbackHTML, tg
	a.mu.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true, "proxy_mode": mode})
}
