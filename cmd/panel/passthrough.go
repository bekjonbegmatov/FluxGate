package main

import "database/sql"

// Additive migration: old installations and backups keep TLS termination.
func migrateRoutePassthrough(db *sql.DB) error {
	rows, err := db.Query("PRAGMA table_info(routes)")
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid, notnull, pk int
		var name, kind string
		var def sql.NullString
		if err = rows.Scan(&cid, &name, &kind, &notnull, &def, &pk); err != nil {
			rows.Close()
			return err
		}
		found = found || name == "tls_passthrough"
	}
	err = rows.Err()
	rows.Close() // release the sole writer connection before ALTER
	if err != nil || found {
		return err
	}
	_, err = db.Exec("ALTER TABLE routes ADD COLUMN tls_passthrough INTEGER NOT NULL DEFAULT 0 CHECK(tls_passthrough IN (0,1))")
	return err
}

func (a *App) ensureRouteCert(r Route) error {
	if r.TLSPassthrough {
		return nil
	}
	return a.ensureCert(routeCert(r), r.SNI)
}

func (a *App) needsInternalTLS() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.proxyMode != "direct" {
		return true
	}
	for _, s := range a.routes {
		s.mu.Lock()
		passthrough := s.Route.TLSPassthrough
		s.mu.Unlock()
		if passthrough {
			return true
		}
	}
	return false
}
