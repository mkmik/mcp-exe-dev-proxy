package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/mkmik/mcp-exe-dev-proxy/internal/sshauth"
	"github.com/mkmik/mcp-exe-dev-proxy/internal/store"
)

type identityKey struct{}

// requestIdentity returns the identity requireAuth attached to the request.
func requestIdentity(ctx context.Context) (store.Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(store.Identity)
	return id, ok
}

// unauthorized sends the MCP-spec 401 that points clients at the protected
// resource metadata.
func (s *Server) unauthorized(w http.ResponseWriter, errCode, desc string) {
	v := fmt.Sprintf(`Bearer resource_metadata=%q`, s.endpoint("/.well-known/oauth-protected-resource"))
	if errCode != "" {
		v += fmt.Sprintf(`, error=%q, error_description=%q`, errCode, desc)
	}
	w.Header().Set("WWW-Authenticate", v)
	w.Header().Add("WWW-Authenticate", sshauth.Scheme+` namespace="`+sshauth.Namespace+`"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// requireAuth admits requests carrying a valid access token or SSHSIG
// signature and rejects everything else.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, errCode, err := s.authenticate(r)
		if err != nil {
			s.log.Info("unauthorized request", "method", r.Method, "path", r.URL.Path, "reason", err)
			s.unauthorized(w, errCode, err.Error())
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, id)))
	})
}

var errNoCredentials = errors.New("no credentials")

func (s *Server) authenticate(r *http.Request) (store.Identity, string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return store.Identity{}, "", errNoCredentials
	}
	if p, ok, err := s.parseSSHSIG(r); ok {
		if err != nil {
			return store.Identity{}, "invalid_request", err
		}
		key, err := s.verifySSHSIG(r, p)
		if err != nil {
			return store.Identity{}, "invalid_token", err
		}
		return store.Identity{Source: "ssh", Subject: key.Fingerprint, Name: key.Name()}, "", nil
	}
	scheme, tok, _ := strings.Cut(h, " ")
	if !strings.EqualFold(scheme, "Bearer") || tok == "" {
		return store.Identity{}, "invalid_request", errors.New("unsupported authorization scheme")
	}
	hash := store.Hash(strings.TrimSpace(tok))
	t, err := s.store.GetToken(r.Context(), hash, store.Access, s.now())
	if errors.Is(err, store.ErrNotFound) {
		return store.Identity{}, "invalid_token", errors.New("invalid or expired token")
	} else if err != nil {
		return store.Identity{}, "", fmt.Errorf("token lookup: %w", err)
	}
	// RFC 8707 audience check: the token must have been issued for a
	// resource on this proxy.
	if t.Resource != s.cfg.PublicURL && !strings.HasPrefix(t.Resource, s.cfg.PublicURL+"/") {
		return store.Identity{}, "invalid_token", fmt.Errorf("token %s was issued for another resource", tokenLogID(hash))
	}
	if !s.identityAllowed(t.Identity) {
		return store.Identity{}, "invalid_token", fmt.Errorf("token %s: %s is no longer allowed", tokenLogID(hash), t.Name)
	}
	return t.Identity, "", nil
}

func (s *Server) parseSSHSIG(r *http.Request) (sshauth.Params, bool, error) {
	return sshauth.ParseHeader(r.Header.Get("Authorization"))
}

// verifySSHSIG checks the signature, then records the nonce so the same
// signed request cannot be replayed.
func (s *Server) verifySSHSIG(r *http.Request, p sshauth.Params) (*sshauth.Key, error) {
	now := s.now()
	key, err := s.keys.Verify(p, r.Method, r.URL.RequestURI(), now)
	if err != nil {
		return nil, err
	}
	// Nonces only need remembering while their timestamp is acceptable.
	if err := s.store.UseNonce(r.Context(), key.Fingerprint+":"+p.Nonce, now.Add(2*sshauth.MaxSkew)); err != nil {
		return nil, err
	}
	return key, nil
}
