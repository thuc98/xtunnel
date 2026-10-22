package dashboard

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"xtunnel/internal/app"
	"xtunnel/internal/config"
)

//go:embed index.html
var indexHTML []byte

const (
	sessionCookie = "xtunnel_session"
	sessionTTL    = 24 * time.Hour
)

type session struct {
	expires time.Time

	password [32]byte
}

type handler struct {
	app *app.App
	mux *http.ServeMux

	mu       sync.Mutex
	sessions map[string]session
}

func New(a *app.App) http.Handler {
	h := &handler{app: a, mux: http.NewServeMux(), sessions: map[string]session{}}
	h.mux.HandleFunc("POST /api/logout", h.logout)
	h.mux.HandleFunc("GET /{$}", h.index)
	h.mux.HandleFunc("GET /api/status", h.status)
	h.mux.HandleFunc("GET /api/metrics", h.metrics)
	h.mux.HandleFunc("GET /api/config", h.getConfig)
	h.mux.HandleFunc("PUT /api/config", h.putConfig)
	h.mux.HandleFunc("PUT /api/config/yaml", h.putYAML)
	h.mux.HandleFunc("POST /api/otp/{id}", h.postOTP)
	h.mux.HandleFunc("POST /api/vpns/{name}/enabled", h.postVPNEnabled)
	return h
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	password := h.app.AdminPassword()
	if r.URL.Path == "/login" {
		h.login(w, r, password)
		return
	}
	if password != "" && !h.validSession(r, password) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeError(w, http.StatusUnauthorized, errLoginRequired)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodGet {
		if ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); ct != "application/json" {
			http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
	}
	h.mux.ServeHTTP(w, r)
}

type httpError string

func (e httpError) Error() string { return string(e) }

const errLoginRequired = httpError("login required")

func (h *handler) validSession(r *http.Request, password string) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.sessions[c.Value]
	if !ok || time.Now().After(s.expires) || s.password != sha256.Sum256([]byte(password)) {
		delete(h.sessions, c.Value)
		return false
	}
	return true
}

var loginTmpl = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>xtunnel login</title>
<style>
:root { --bg:#f5f6f8; --panel:#fff; --text:#1d2129; --muted:#667085; --line:#e3e6eb; --accent:#2463eb; --accent-text:#fff; --bad:#c62828; }
@media (prefers-color-scheme: dark) { :root { --bg:#111317; --panel:#1a1d23; --text:#e6e8eb; --muted:#98a1ae; --line:#2c3139; --accent:#5b8cff; --accent-text:#0b0d10; --bad:#f87171; } }
* { box-sizing: border-box; }
body { margin:0; min-height:100vh; display:grid; place-items:center; background:var(--bg); color:var(--text); font:14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; padding:16px; }
form { width:100%; max-width:340px; background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:24px; }
h1 { font-size:18px; margin:0 0 4px; } p { color:var(--muted); margin:0 0 16px; }
input { width:100%; font:inherit; color:var(--text); background:var(--bg); border:1px solid var(--line); border-radius:6px; padding:9px 10px; }
button { margin-top:12px; width:100%; font:inherit; font-weight:600; padding:9px; border:0; border-radius:6px; background:var(--accent); color:var(--accent-text); cursor:pointer; }
.err { color:var(--bad); margin:10px 0 0; }
</style></head>
<body><form method="post" action="/login">
<h1>xtunnel</h1><p>Enter the admin password.</p>
<input type="password" name="password" autocomplete="current-password" autofocus required>
<button type="submit">Log in</button>
{{if .}}<p class="err">{{.}}</p>{{end}}
</form></body></html>
`))

func (h *handler) login(w http.ResponseWriter, r *http.Request, password string) {
	if password == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	switch r.Method {
	case http.MethodGet:
		_ = loginTmpl.Execute(w, "")
	case http.MethodPost:
		given := sha256.Sum256([]byte(r.FormValue("password")))
		want := sha256.Sum256([]byte(password))
		if subtle.ConstantTimeCompare(given[:], want[:]) != 1 {
			time.Sleep(time.Second)
			w.WriteHeader(http.StatusUnauthorized)
			_ = loginTmpl.Execute(w, "Wrong password.")
			return
		}
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		id := hex.EncodeToString(buf)
		h.mu.Lock()
		for k, s := range h.sessions {
			if time.Now().After(s.expires) {
				delete(h.sessions, k)
			}
		}
		h.sessions[id] = session{expires: time.Now().Add(sessionTTL), password: want}
		h.mu.Unlock()
		http.SetCookie(w, &http.Cookie{
			Name: sessionCookie, Value: id, Path: "/", MaxAge: int(sessionTTL / time.Second),
			HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil,
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *handler) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		h.mu.Lock()
		delete(h.sessions, c.Value)
		h.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *handler) index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(indexHTML)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func (h *handler) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, struct {
		app.Status
		Auth bool `json:"auth"`
	}{h.app.Status(), h.app.AdminPassword() != ""})
}

func (h *handler) metrics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.app.Metrics())
}

func (h *handler) getConfig(w http.ResponseWriter, r *http.Request) {
	cfg, text, err := h.app.EditableConfig()
	resp := map[string]any{"config": cfg, "yaml": text, "secret_mask": config.SecretMask}
	if err != nil {
		resp["error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *handler) putConfig(w http.ResponseWriter, r *http.Request) {
	var cfg config.Config
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.app.SaveConfig(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *handler) putYAML(w http.ResponseWriter, r *http.Request) {
	var body struct {
		YAML string `json:"yaml"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.app.SaveYAML([]byte(body.YAML)); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *handler) postOTP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.app.ResolveOTP(r.PathValue("id"), body.Code); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *handler) postVPNEnabled(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.app.SetVPNEnabled(r.PathValue("name"), body.Enabled); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
