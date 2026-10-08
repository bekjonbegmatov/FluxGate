package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type backupManifest struct {
	Version       int    `json:"version"`
	CreatedAt     string `json:"created_at"`
	Domain        string `json:"domain"`
	Timezone      string `json:"timezone"`
	TelegramToken string `json:"telegram_token"`
}

func (a *App) backupAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		fail(w, 405, "method")
		return
	}
	a.restoreMu.Lock()
	defer a.restoreMu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	archiveFile, err := os.CreateTemp(a.data, "backup-download-*.zip")
	if err != nil {
		fail(w, 500, "cannot create backup")
		return
	}
	defer os.Remove(archiveFile.Name())
	defer archiveFile.Close()
	if err = a.writeBackup(ctx, archiveFile); err != nil {
		fail(w, 500, "backup could not be completed")
		log.Printf("backup archive: %v", err)
		return
	}
	if _, err = archiveFile.Seek(0, 0); err != nil {
		fail(w, 500, "cannot read backup")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="fluxgate-backup.zip"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Minute))
	http.ServeContent(w, r, "fluxgate-backup.zip", time.Time{}, archiveFile)
}

// Snapshot and compress to a private file, then release stateMu BEFORE sending
// to the network. Slow backup downloads must not stop accounting or rollover.
func (a *App) writeBackup(ctx context.Context, dst io.Writer) error {
	a.collectDirectTraffic(time.Now())
	if err := a.flushTraffic(time.Now()); err != nil {
		return err
	}
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	temp, err := os.CreateTemp(a.data, "backup-snapshot-*.db")
	if err != nil {
		return err
	}
	snapshot := temp.Name()
	temp.Close()
	os.Remove(snapshot)
	defer os.Remove(snapshot)
	if _, err = a.db.ExecContext(ctx, "VACUUM INTO ?", snapshot); err != nil {
		return err
	}
	_ = os.Chmod(snapshot, 0600)
	a.mu.RLock()
	manifest := backupManifest{Version: 1, CreatedAt: time.Now().UTC().Format(time.RFC3339), Domain: a.domain, Timezone: a.location.String(), TelegramToken: a.tg.BotToken}
	a.mu.RUnlock()
	archive := zip.NewWriter(dst)
	write := func(name string, src io.Reader) error {
		entry, e := archive.Create(name)
		if e != nil {
			return e
		}
		_, e = io.Copy(entry, contextReader{ctx, src})
		return e
	}
	manifestJSON, _ := json.Marshal(manifest)
	if err = write("manifest.json", strings.NewReader(string(manifestJSON))); err == nil {
		var f *os.File
		f, err = os.Open(snapshot)
		if err == nil {
			err = write("panel.db", f)
			f.Close()
		}
	}
	if err == nil {
		files, _ := filepath.Glob(filepath.Join(a.data, "certs", "*.pem"))
		for _, path := range files {
			f, e := os.Open(path)
			if e != nil {
				err = e
				break
			}
			err = write("certs/"+filepath.Base(path), f)
			f.Close()
			if err != nil {
				break
			}
		}
	}
	if closeErr := archive.Close(); err == nil {
		err = closeErr
	}
	return err
}

type contextReader struct {
	ctx context.Context
	io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}
func safeCertName(name string) bool {
	return regexp.MustCompile(`^[A-Za-z0-9_-]+\.pem$`).MatchString(name)
}
func copyArchiveFile(dst string, src *zip.File, max int64) error {
	if src.UncompressedSize64 > uint64(max) {
		return fmt.Errorf("archive member too large")
	}
	in, e := src.Open()
	if e != nil {
		return e
	}
	defer in.Close()
	out, e := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer out.Close()
	n, e := io.CopyN(out, in, max+1)
	if e != nil && e != io.EOF {
		return e
	}
	if n > max {
		return fmt.Errorf("archive member too large")
	}
	return out.Sync()
}
func (a *App) stageRestore(src io.Reader) (string, error) {
	stage, e := os.MkdirTemp(a.data, "restore-stage-")
	if e != nil {
		return "", e
	}
	cleanup := true
	defer func() {
		if cleanup {
			os.RemoveAll(stage)
		}
	}()
	upload, e := os.OpenFile(filepath.Join(stage, "upload.zip"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return "", e
	}
	n, e := io.CopyN(upload, src, (512<<20)+1)
	upload.Close()
	if e != nil && e != io.EOF {
		return "", e
	}
	if n > 512<<20 {
		return "", fmt.Errorf("backup exceeds 512 MiB")
	}
	file, e := os.Open(filepath.Join(stage, "upload.zip"))
	if e != nil {
		return "", e
	}
	defer file.Close()
	archive, e := zip.NewReader(file, n)
	if e != nil {
		return "", e
	}
	if e = os.Mkdir(filepath.Join(stage, "certs"), 0700); e != nil {
		return "", e
	}
	seen := map[string]bool{}
	for _, item := range archive.File {
		name := item.Name
		if seen[name] {
			return "", fmt.Errorf("duplicate archive entry")
		}
		seen[name] = true
		switch {
		case name == "manifest.json":
			e = copyArchiveFile(filepath.Join(stage, name), item, 64<<10)
		case name == "panel.db":
			e = copyArchiveFile(filepath.Join(stage, name), item, 1<<30)
		case strings.HasPrefix(name, "certs/") && safeCertName(strings.TrimPrefix(name, "certs/")):
			e = copyArchiveFile(filepath.Join(stage, name), item, 2<<20)
		default:
			return "", fmt.Errorf("unexpected archive entry")
		}
		if e != nil {
			return "", e
		}
		if strings.HasPrefix(name, "certs/") {
			raw, e := os.ReadFile(filepath.Join(stage, name))
			if e != nil {
				return "", e
			}
			if e = validatePEM(raw); e != nil {
				return "", e
			}
		}
	}
	if !seen["manifest.json"] || !seen["panel.db"] {
		return "", fmt.Errorf("incomplete backup")
	}
	raw, e := os.ReadFile(filepath.Join(stage, "manifest.json"))
	if e != nil {
		return "", e
	}
	var manifest backupManifest
	if e = json.Unmarshal(raw, &manifest); e != nil {
		return "", e
	}
	if manifest.Version != 1 || !validDomain(manifest.Domain) {
		return "", fmt.Errorf("unsupported or invalid backup")
	}
	if _, e = time.LoadLocation(manifest.Timezone); e != nil {
		return "", fmt.Errorf("invalid backup timezone")
	}
	db, e := sql.Open("sqlite", filepath.Join(stage, "panel.db"))
	if e != nil {
		return "", e
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	var integrity string
	if e = db.QueryRow("PRAGMA integrity_check").Scan(&integrity); e != nil || integrity != "ok" {
		return "", fmt.Errorf("invalid backup database")
	}
	for _, table := range []string{"routes", "periods", "samples", "settings", "rentals", "payments", "request_totals", "request_samples"} {
		var count int
		if e = db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); e != nil {
			return "", fmt.Errorf("missing table %s", table)
		}
	}
	var mode string
	var directLimits string
	if e = db.QueryRow("SELECT value FROM settings WHERE key='direct_limits'").Scan(&directLimits); e != nil && e != sql.ErrNoRows {
		return "", e
	} else if e == nil && directLimits != "true" && directLimits != "false" {
		return "", fmt.Errorf("invalid direct_limits in backup")
	}
	if e = db.QueryRow("SELECT value FROM settings WHERE key='proxy_mode'").Scan(&mode); e != nil && e != sql.ErrNoRows {
		return "", e
	} else if e == nil && !validProxyMode(mode) {
		return "", fmt.Errorf("invalid proxy_mode in backup")
	}
	if mode == "direct" {
		if e = checkDirectHAProxyVersion(); e != nil {
			return "", e
		}
	}
	var meterTable int
	if e = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='route_meter_ids'").Scan(&meterTable); e != nil {
		return "", e
	}
	if meterTable > 0 {
		var invalid int
		if e = db.QueryRow("SELECT count(*) FROM route_meter_ids WHERE length(token)<>32 OR token GLOB '*[^0-9a-f]*'").Scan(&invalid); e != nil {
			return "", e
		}
		if invalid > 0 {
			return "", fmt.Errorf("invalid route meter identity in backup")
		}
	}
	// Only the isolated staging DB is migrated, never the uploaded/source DB.
	if e = migrateRoutePassthrough(db); e != nil {
		return "", e
	}
	rows, e := db.Query("SELECT id,name,sni,ip,port,tls,verify,verify_name,paused,daily_limit,monthly_limit,count_mode,down_bps,up_bps,threshold,tls_passthrough FROM routes")
	if e != nil {
		return "", e
	}
	for rows.Next() {
		var r Route
		var tls, verify, paused, passthrough int
		e = rows.Scan(&r.ID, &r.Name, &r.SNI, &r.IP, &r.Port, &tls, &verify, &r.VerifyName, &paused, &r.DailyLimit, &r.MonthlyLimit, &r.CountMode, &r.DownBPS, &r.UpBPS, &r.Threshold, &passthrough)
		if e != nil {
			break
		}
		r.TLS = tls != 0
		r.Verify = verify != 0
		r.Paused = paused != 0
		r.TLSPassthrough = passthrough != 0
		if passthrough != 0 && passthrough != 1 {
			e = fmt.Errorf("invalid tls_passthrough in backup")
			break
		}
		if e = validateRoute(&r); e != nil {
			break
		}
		// Match create/update validation: an overlapping wildcard is safe;
		// the primary-domain ACL always precedes route ACLs in both frontends.
		if r.SNI == manifest.Domain {
			e = fmt.Errorf("main domain conflicts with route")
			break
		}
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return "", e
	}
	encrypted := a.encrypt(manifest.TelegramToken)
	if _, e = db.Exec("INSERT INTO settings(key,value) VALUES('domain',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", manifest.Domain); e != nil {
		return "", e
	}
	if _, e = db.Exec("INSERT INTO settings(key,value) VALUES('timezone',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", manifest.Timezone); e != nil {
		return "", e
	}
	if _, e = db.Exec("INSERT INTO settings(key,value) VALUES('tg_token',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", encrypted); e != nil {
		return "", e
	}
	if _, e = db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); e != nil {
		return "", e
	}
	if _, e = db.Exec("PRAGMA journal_mode=DELETE"); e != nil {
		return "", e
	}
	db.Close()
	os.Remove(filepath.Join(stage, "upload.zip"))
	os.Remove(filepath.Join(stage, "manifest.json"))
	cleanup = false
	return filepath.Base(stage), nil
}
func (a *App) restoreAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fail(w, 405, "method")
		return
	}
	if r.Header.Get("Content-Type") != "application/zip" {
		fail(w, 415, "upload a ZIP backup")
		return
	}
	a.restoreMu.Lock()
	defer a.restoreMu.Unlock()
	if _, e := os.Stat(filepath.Join(a.data, "restore.pending")); e == nil {
		fail(w, 409, "restore already pending")
		return
	}
	name, e := a.stageRestore(r.Body)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	marker := filepath.Join(a.data, "restore.pending")
	if e = os.WriteFile(marker, []byte(name), 0600); e != nil {
		os.RemoveAll(filepath.Join(a.data, name))
		fail(w, 500, e.Error())
		return
	}
	writeJSON(w, 202, map[string]any{"ok": true, "restarting": true})
	go func() { time.Sleep(750 * time.Millisecond); os.Exit(0) }()
}
func applyPendingRestore(data string) error {
	marker := filepath.Join(data, "restore.pending")
	raw, e := os.ReadFile(marker)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	name := string(raw)
	if !regexp.MustCompile(`^restore-stage-[A-Za-z0-9]+$`).MatchString(name) {
		return fmt.Errorf("invalid restore marker")
	}
	stage := filepath.Join(data, name)
	previous, e := os.MkdirTemp(data, "before-restore-")
	if e != nil {
		return e
	}
	stagedDB := filepath.Join(stage, "panel.db")
	if _, e = os.Stat(stagedDB); e == nil {
		for _, suffix := range []string{"", "-wal", "-shm"} {
			src := filepath.Join(data, "panel.db"+suffix)
			if _, e = os.Stat(src); e == nil {
				if e = os.Rename(src, filepath.Join(previous, "panel.db"+suffix)); e != nil {
					return e
				}
			}
		}
		if e = os.Rename(stagedDB, filepath.Join(data, "panel.db")); e != nil {
			return e
		}
	} else if _, e = os.Stat(filepath.Join(data, "panel.db")); e != nil {
		return fmt.Errorf("staged database missing")
	}
	stagedCerts := filepath.Join(stage, "certs")
	if _, e = os.Stat(stagedCerts); e == nil {
		certs := filepath.Join(data, "certs")
		if _, e = os.Stat(certs); e == nil {
			if e = os.Rename(certs, filepath.Join(previous, "certs")); e != nil {
				return e
			}
		}
		if e = os.Rename(stagedCerts, certs); e != nil {
			return e
		}
	}
	if e = os.Remove(marker); e != nil {
		return e
	}
	return os.RemoveAll(stage)
}
func validatePEM(data []byte) error {
	block, rest := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("invalid PEM")
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return e
	}
	keyBlock, _ := pem.Decode(rest)
	if keyBlock == nil {
		return fmt.Errorf("missing private key")
	}
	key, e := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if e != nil {
		return e
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return fmt.Errorf("invalid private key")
	}
	pubCert, e := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if e != nil {
		return e
	}
	pubKey, e := x509.MarshalPKIXPublicKey(signer.Public())
	if e != nil {
		return e
	}
	if !bytes.Equal(pubCert, pubKey) {
		return fmt.Errorf("certificate and key mismatch")
	}
	return nil
}
