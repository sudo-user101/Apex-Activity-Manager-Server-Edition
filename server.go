package main

import (
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// The HTTPS server on the Server Edition's port (7443 by default): the API the
// Mac app uses, and the same pages in a browser. Everything but /api/hello and
// /api/pair needs a paired device's token (the app sends it as a Bearer token;
// the browser keeps it in a secure, HTTP-only cookie).

//go:embed web/index.html
var indexHTML []byte

type Server struct {
	collector *Collector
	auth      *Auth
}

const cookieName = "apex_session"

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/hello", s.hello)
	mux.HandleFunc("/api/pair", s.pair)
	mux.HandleFunc("/api/snapshot", s.authed(s.snapshot))
	mux.HandleFunc("/api/action", s.authed(s.action))
	mux.HandleFunc("/api/logout", s.authed(s.logout))
	mux.HandleFunc("/", s.page)
	return securityHeaders(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

func token(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	if c, err := r.Cookie(cookieName); err == nil {
		return c.Value
	}
	return ""
}

func (s *Server) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.auth.Check(token(r)) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Not paired. Pair this device with the code from `sudo apex-server pair`."})
			return
		}
		// Browser requests that change something must come from the page itself.
		if r.Method == http.MethodPost && r.Header.Get("Authorization") == "" && r.Header.Get("X-Apex") != "1" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "Refused."})
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// hello: lets the app check it's talking to Apex (nothing about the server itself).
func (s *Server) hello(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"product": "Apex Activity Manager Server Edition", "version": version, "api": 1})
}

func (s *Server) pair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Code   string `json:"code"`
		Device string `json:"device"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Bad request."})
		return
	}
	t, err := s.auth.Pair(req.Code, req.Device, clientIP(r))
	if err != nil {
		code := http.StatusUnauthorized
		if err == errTooMany {
			code = http.StatusTooManyRequests
		}
		log.Printf("pairing refused from %s: %v", clientIP(r), err)
		writeJSON(w, code, map[string]string{"error": capitalize(err.Error()) + "."})
		return
	}
	log.Printf("paired %q from %s", req.Device, clientIP(r))
	if r.URL.Query().Get("browser") == "1" {
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: t, Path: "/", HttpOnly: true, Secure: true,
			SameSite: http.SameSiteStrictMode, MaxAge: 365 * 24 * 3600})
		writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
		return
	}
	host := s.collector.Latest().Host
	writeJSON(w, http.StatusOK, map[string]string{"token": t, "host": host})
}

func (s *Server) snapshot(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.collector.Latest())
}

type actionRequest struct {
	Kind   string `json:"kind"`   // process, service, container
	Verb   string `json:"verb"`   // end, start, stop, restart
	Target string `json:"target"` // pid, service name, container id or name
	Force  bool   `json:"force"`
}

func (s *Server) action(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var a actionRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&a) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Bad request."})
		return
	}
	err := s.do(a)
	log.Printf("action %s %s %s (force %v) from %s: %v", a.Kind, a.Verb, a.Target, a.Force, clientIP(r), errText(err))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": capitalize(err.Error())})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Done."})
}

func (s *Server) do(a actionRequest) error {
	snap := s.collector.Latest()
	switch a.Kind {
	case "process":
		pids := strings.Fields(strings.ReplaceAll(a.Target, ",", " "))
		if len(pids) == 0 || len(pids) > 200 {
			return fmt.Errorf("no process given")
		}
		for _, p := range pids {
			var pid int
			if _, err := fmt.Sscan(p, &pid); err != nil {
				return fmt.Errorf("%q isn't a process id", p)
			}
			if err := endProcess(pid, a.Force); err != nil {
				return err
			}
		}
		go func() { time.Sleep(300 * time.Millisecond); s.collector.Sample() }()
		return nil
	case "service":
		err := serviceAction(a.Verb, a.Target, snap.Services)
		go s.collector.RefreshSlow()
		return err
	case "container":
		err := containerAction(a.Verb, a.Target, snap.Containers)
		go s.collector.RefreshSlow()
		return err
	}
	return fmt.Errorf("unknown action")
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.auth.Forget(token(r))
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true})
	writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
}

func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

func errText(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// Serve runs the HTTPS server until it fails.
func Serve(c *Collector, a *Auth, cfg Config, cert tls.Certificate) error {
	s := &Server{collector: c, auth: a}
	go func() { // pick up devices removed from the command line
		for range time.Tick(30 * time.Second) {
			a.Reload()
		}
	}()
	srv := &http.Server{
		Addr:              net.JoinHostPort(cfg.Bind, fmt.Sprint(cfg.Port)),
		Handler:           s.routes(),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(quietTLS{}, "", 0),
	}
	return srv.ListenAndServeTLS("", "")
}

// quietTLS drops the "TLS handshake error" lines browsers cause until the
// certificate is accepted; everything else is logged.
type quietTLS struct{}

func (quietTLS) Write(p []byte) (int, error) {
	if !strings.Contains(string(p), "TLS handshake error") {
		log.Print(string(p))
	}
	return len(p), nil
}
