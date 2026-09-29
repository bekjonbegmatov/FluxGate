package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiagnosticsDoesNotPrintCredentials(t *testing.T) {
	const token = "test-only-diagnostic-token-never-print"
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/api/login", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil || body["token"] != token {
			w.WriteHeader(401)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "test-cookie-do-not-print", Path: "/"})
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/admin/api/system", func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("session"); err != nil {
			w.WriteHeader(401)
			return
		}
		writeJSON(w, 200, map[string]int{"relay_connections": 42})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	t.Setenv("PANEL_LISTEN", strings.TrimPrefix(server.URL, "http://"))
	t.Setenv("PANEL_SECRET_PATH", "admin")
	t.Setenv("PANEL_TOKEN", token)
	t.Setenv("PANEL_DATA", t.TempDir())
	var out bytes.Buffer
	if err := printDiagnostics(&out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), token) || strings.Contains(out.String(), "test-cookie-do-not-print") {
		t.Fatal("diagnostic credentials disclosed")
	}
	var result map[string]any
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["system"].(map[string]any)["relay_connections"] != float64(42) {
		t.Fatal("missing live system metrics")
	}
}
