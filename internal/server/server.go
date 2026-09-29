// Package server is the HTTP side of the proxy: the OAuth authorization
// server, the SSHSIG machine auth, and the authenticated reverse proxy to the
// upstream MCP server.
package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mkmik/mcp-exe-dev-proxy/internal/config"
	"github.com/mkmik/mcp-exe-dev-proxy/internal/identity"
	"github.com/mkmik/mcp-exe-dev-proxy/internal/sshauth"
	"github.com/mkmik/mcp-exe-dev-proxy/internal/store"
)

// authCodeTTL is how long an authorization code is valid.
const authCodeTTL = 60 * time.Second

// Server serves the proxy.
type Server struct {
	cfg      *config.Config
	store    *store.Store
	keys     *sshauth.Keyring
	id       identity.Provider
	log      *slog.Logger
	now      func() time.Time
	public   *url.URL
	upstream *url.URL
	limiter  *ipLimiter
	proxy    http.Handler
	mux      *http.ServeMux
}

// New builds a server. The store and keyring stay owned by the caller.
func New(cfg *config.Config, st *store.Store, keys *sshauth.Keyring, id identity.Provider, log *slog.Logger) (*Server, error) {
	public, err := url.Parse(cfg.PublicURL)
	if err != nil {
		return nil, err
	}
	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:      cfg,
		store:    st,
		keys:     keys,
		id:       id,
		log:      log,
		now:      time.Now,
		public:   public,
		upstream: upstream,
		limiter:  newIPLimiter(cfg.RateLimit, cfg.RateBurst),
	}
	s.proxy = s.newProxy()
	s.mux = s.routes()
	return s, nil
}

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	limited := s.limiter.middleware

	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.handleProtectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/{rest...}", s.handleProtectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleAuthServerMetadata)
	mux.Handle("POST /register", limited(http.HandlerFunc(s.handleRegister)))
	mux.Handle("GET /authorize", limited(http.HandlerFunc(s.handleAuthorize)))
	mux.Handle("POST /token", limited(http.HandlerFunc(s.handleToken)))
	mux.Handle("POST /revoke", limited(http.HandlerFunc(s.handleRevoke)))
	mux.Handle("POST /machine/token", limited(http.HandlerFunc(s.handleMachineToken)))
	mux.HandleFunc("GET /healthz", s.handleHealthz)

	// Everything else is the upstream, behind auth.
	mux.Handle("/", s.requireAuth(s.proxy))
	return mux
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// RunGC periodically deletes expired state until ctx is done.
func (s *Server) RunGC(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := s.store.GC(ctx, s.now()); err != nil && ctx.Err() == nil {
			s.log.Error("gc", "err", err)
		}
		s.limiter.gc(s.now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// userAllowed reports whether an exe.dev user is on the allowlist.
func (s *Server) userAllowed(u *identity.User) bool {
	for _, a := range s.cfg.AllowedUsers {
		if a == u.ID || (u.Email != "" && strings.EqualFold(a, u.Email)) {
			return true
		}
	}
	return false
}

// identityAllowed re-checks, on every use, that the identity a token was
// issued to is still allowed by the current configuration.
func (s *Server) identityAllowed(id store.Identity) bool {
	switch id.Source {
	case "exedev":
		// Subject is the user ID, Name the email (or ID if no email).
		return s.userAllowed(&identity.User{ID: id.Subject, Email: id.Name})
	case "ssh":
		return s.keys.Lookup(id.Subject) != nil
	}
	return false
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	upstream := "up"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.upstream.String(), nil)
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		upstream = "down"
	} else {
		resp.Body.Close()
	}
	status := http.StatusOK
	if upstream != "up" {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]string{"status": "ok", "upstream": upstream})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// tokenLogID is how tokens appear in logs: a prefix of their hash.
func tokenLogID(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}
