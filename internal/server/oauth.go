package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/mkmik/mcp-exe-dev-proxy/internal/store"
)

const (
	authNone        = "none"
	authSecretPost  = "client_secret_post"
	authSecretBasic = "client_secret_basic"
)

func (s *Server) issuer() string { return s.cfg.PublicURL }

func (s *Server) endpoint(path string) string { return s.cfg.PublicURL + path }

// handleProtectedResourceMetadata serves RFC 9728 metadata. The
// path-suffixed variant describes the resource at that path; both point at
// this proxy as the authorization server.
func (s *Server) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	resource := s.cfg.PublicURL
	if rest := r.PathValue("rest"); rest != "" {
		resource += "/" + rest
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 resource,
		"authorization_servers":    []string{s.issuer()},
		"bearer_methods_supported": []string{"header"},
	})
}

// handleAuthServerMetadata serves RFC 8414 metadata.
func (s *Server) handleAuthServerMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         s.issuer(),
		"authorization_endpoint":                         s.endpoint("/authorize"),
		"token_endpoint":                                 s.endpoint("/token"),
		"registration_endpoint":                          s.endpoint("/register"),
		"revocation_endpoint":                            s.endpoint("/revoke"),
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{authNone, authSecretPost, authSecretBasic},
		"revocation_endpoint_auth_methods_supported":     []string{authNone, authSecretPost, authSecretBasic},
		"authorization_response_iss_parameter_supported": true,
	})
}

// oauthError writes an RFC 6749 section 5.2 error response.
func oauthError(w http.ResponseWriter, status int, code, desc string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="mcp-exe-dev-proxy"`)
	}
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// isLoopbackRedirect reports whether u is an http loopback redirect URI, which
// native apps such as Claude Code use (RFC 8252 section 7.3).
func isLoopbackRedirect(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	switch h := u.Hostname(); h {
	case "localhost":
		return true
	default:
		ip := net.ParseIP(h)
		return ip != nil && ip.IsLoopback()
	}
}

func parseRedirectURI(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return nil, fmt.Errorf("redirect URI %q is not absolute", raw)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return nil, fmt.Errorf("redirect URI %q must not have a fragment", raw)
	}
	return u, nil
}

// redirectAllowedAtRegistration checks a redirect URI against the
// configured allowlist.
func (s *Server) redirectAllowedAtRegistration(raw string) error {
	u, err := parseRedirectURI(raw)
	if err != nil {
		return err
	}
	if isLoopbackRedirect(u) || slices.Contains(s.cfg.AllowedRedirectURIs, raw) {
		return nil
	}
	return fmt.Errorf("redirect URI %q is not allowed", raw)
}

// matchRedirect checks a redirect URI from an authorization request against
// a client's registered ones. Matching is exact, except that loopback URIs
// may use any port.
func matchRedirect(registered []string, raw string) bool {
	if slices.Contains(registered, raw) {
		return true
	}
	u, err := parseRedirectURI(raw)
	if err != nil || !isLoopbackRedirect(u) {
		return false
	}
	for _, reg := range registered {
		r, err := url.Parse(reg)
		if err != nil || !isLoopbackRedirect(r) {
			continue
		}
		if r.Hostname() == u.Hostname() && r.Path == u.Path && r.RawQuery == u.RawQuery {
			return true
		}
	}
	return false
}

type registrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
}

// handleRegister implements RFC 7591 dynamic client registration.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registrationRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "body must be a JSON object")
		return
	}
	if len(req.RedirectURIs) == 0 {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris is required")
		return
	}
	for _, u := range req.RedirectURIs {
		if err := s.redirectAllowedAtRegistration(u); err != nil {
			s.log.Warn("register: rejected redirect URI", "uri", u, "client_name", req.ClientName)
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
			return
		}
	}
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = authSecretBasic // RFC 7591 default
	}
	if !slices.Contains([]string{authNone, authSecretPost, authSecretBasic}, req.TokenEndpointAuthMethod) {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported token_endpoint_auth_method")
		return
	}
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	for _, g := range req.GrantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported grant type "+g)
			return
		}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	for _, rt := range req.ResponseTypes {
		if rt != "code" {
			oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported response type "+rt)
			return
		}
	}
	if len(req.ClientName) > 200 {
		req.ClientName = req.ClientName[:200]
	}

	now := s.now()
	c := &store.Client{
		ID:           store.NewSecret(),
		Name:         req.ClientName,
		RedirectURIs: req.RedirectURIs,
		AuthMethod:   req.TokenEndpointAuthMethod,
		CreatedAt:    now,
	}
	resp := map[string]any{
		"client_id":                  c.ID,
		"client_id_issued_at":        now.Unix(),
		"client_name":                c.Name,
		"redirect_uris":              c.RedirectURIs,
		"grant_types":                req.GrantTypes,
		"response_types":             req.ResponseTypes,
		"token_endpoint_auth_method": c.AuthMethod,
	}
	if req.Scope != "" {
		resp["scope"] = req.Scope
	}
	if c.AuthMethod != authNone {
		secret := store.NewSecret()
		c.SecretHash = store.Hash(secret)
		resp["client_secret"] = secret
		resp["client_secret_expires_at"] = 0
	}
	if err := s.store.CreateClient(r.Context(), c); err != nil {
		s.log.Error("register", "err", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "could not store client")
		return
	}
	s.log.Info("registered client", "client_id", c.ID, "client_name", c.Name, "redirect_uris", c.RedirectURIs)
	writeJSON(w, http.StatusCreated, resp)
}

// canonicalResource validates an RFC 8707 resource indicator. Any URL on
// this proxy's origin is accepted; the empty value means the whole origin.
func (s *Server) canonicalResource(raw string) (string, error) {
	if raw == "" {
		return s.cfg.PublicURL, nil
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Fragment != "" {
		return "", errors.New("resource must be an absolute URI without a fragment")
	}
	if !strings.EqualFold(u.Scheme, s.public.Scheme) || !strings.EqualFold(u.Host, s.public.Host) {
		return "", fmt.Errorf("resource %q is not served by this proxy", raw)
	}
	return s.cfg.PublicURL + strings.TrimRight(u.EscapedPath(), "/"), nil
}

// resourceParam returns the single resource parameter from a form, if any.
func resourceParam(v url.Values) (string, error) {
	switch rs := v["resource"]; len(rs) {
	case 0:
		return "", nil
	case 1:
		return rs[0], nil
	default:
		return "", errors.New("only one resource is supported")
	}
}

func s256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// validPKCEString checks the RFC 7636 syntax shared by code_verifier and an
// S256 code_challenge.
func validPKCEString(v string, minLen, maxLen int) bool {
	if len(v) < minLen || len(v) > maxLen {
		return false
	}
	for _, c := range v {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}

func errorPage(w http.ResponseWriter, status int, title, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><title>%s</title><h1>%s</h1><p>%s</p>\n",
		html.EscapeString(title), html.EscapeString(title), html.EscapeString(msg))
}

// handleAuthorize is the authorization endpoint. It sends the browser
// through exe.dev login, checks the allowlist and, with no consent screen,
// redirects back to the client with a code.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ctx := r.Context()

	// Until the client and redirect URI are validated, errors are shown to
	// the user rather than redirected (RFC 6749 section 4.1.2.1).
	client, err := s.store.GetClient(ctx, q.Get("client_id"))
	if err != nil {
		errorPage(w, http.StatusBadRequest, "Unknown client", "The application is not registered with this server. Try removing and re-adding the connector.")
		return
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" && len(client.RedirectURIs) == 1 {
		redirectURI = client.RedirectURIs[0]
	}
	if !matchRedirect(client.RedirectURIs, redirectURI) {
		errorPage(w, http.StatusBadRequest, "Invalid redirect URI", "The redirect URI does not match the registered client.")
		return
	}
	state := q.Get("state")
	redirect := func(params url.Values) {
		u, _ := url.Parse(redirectURI)
		rq := u.Query()
		for k, vs := range params {
			rq[k] = vs
		}
		if state != "" {
			rq.Set("state", state)
		}
		rq.Set("iss", s.issuer())
		u.RawQuery = rq.Encode()
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
	fail := func(code, desc string) {
		redirect(url.Values{"error": {code}, "error_description": {desc}})
	}

	if q.Get("response_type") != "code" {
		fail("unsupported_response_type", "only response_type=code is supported")
		return
	}
	challenge := q.Get("code_challenge")
	if challenge == "" {
		fail("invalid_request", "code_challenge is required (PKCE)")
		return
	}
	if q.Get("code_challenge_method") != "S256" {
		fail("invalid_request", "code_challenge_method must be S256")
		return
	}
	if !validPKCEString(challenge, 43, 43) {
		fail("invalid_request", "malformed code_challenge")
		return
	}
	rawResource, err := resourceParam(q)
	if err != nil {
		fail("invalid_target", err.Error())
		return
	}
	resource, err := s.canonicalResource(rawResource)
	if err != nil {
		fail("invalid_target", err.Error())
		return
	}

	user := s.id.User(r)
	if user == nil {
		http.Redirect(w, r, s.id.LoginURL(r.URL.RequestURI()), http.StatusFound)
		return
	}
	if !s.userAllowed(user) {
		s.log.Warn("authorize: user not allowed", "user_id", user.ID, "email", user.Email, "client_id", client.ID)
		errorPage(w, http.StatusForbidden, "Access denied",
			fmt.Sprintf("%s is not allowed to use this server.", user.Name()))
		return
	}

	code := store.NewSecret()
	err = s.store.SaveCode(ctx, &store.Code{
		Hash:          store.Hash(code),
		ClientID:      client.ID,
		RedirectURI:   redirectURI,
		CodeChallenge: challenge,
		Resource:      resource,
		Scope:         q.Get("scope"),
		Identity:      store.Identity{Source: "exedev", Subject: user.ID, Name: user.Name()},
		ExpiresAt:     s.now().Add(authCodeTTL),
	})
	if err != nil {
		s.log.Error("authorize: save code", "err", err)
		fail("server_error", "could not issue code")
		return
	}
	s.log.Info("authorized", "user", user.Name(), "client_id", client.ID, "client_name", client.Name, "resource", resource)
	redirect(url.Values{"code": {code}})
}

// authenticateClient implements client authentication at the token and
// revocation endpoints. It writes the error response itself.
func (s *Server) authenticateClient(w http.ResponseWriter, r *http.Request) (*store.Client, bool) {
	id, secret, basic := r.BasicAuth()
	if basic {
		// RFC 6749 section 2.3.1: credentials are form-urlencoded first.
		if v, err := url.QueryUnescape(id); err == nil {
			id = v
		}
		if v, err := url.QueryUnescape(secret); err == nil {
			secret = v
		}
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id == "" {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication required")
		return nil, false
	}
	c, err := s.store.GetClient(r.Context(), id)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return nil, false
	}
	if c.AuthMethod != authNone {
		if secret == "" || subtle.ConstantTimeCompare([]byte(store.Hash(secret)), []byte(c.SecretHash)) != 1 {
			oauthError(w, http.StatusUnauthorized, "invalid_client", "bad client credentials")
			return nil, false
		}
	}
	return c, true
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	client, ok := s.authenticateClient(w, r)
	if !ok {
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.codeGrant(w, r, client)
	case "refresh_token":
		s.refreshGrant(w, r, client)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
	}
}

func (s *Server) codeGrant(w http.ResponseWriter, r *http.Request, client *store.Client) {
	ctx := r.Context()
	f := r.PostForm
	code, err := s.store.TakeCode(ctx, store.Hash(f.Get("code")), s.now())
	if errors.Is(err, store.ErrNotFound) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid, expired or already used code")
		return
	} else if err != nil {
		s.log.Error("token: take code", "err", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	if code.ClientID != client.ID {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "code was issued to another client")
		return
	}
	if ru := f.Get("redirect_uri"); ru != "" && ru != code.RedirectURI {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	verifier := f.Get("code_verifier")
	if !validPKCEString(verifier, 43, 128) || subtle.ConstantTimeCompare([]byte(s256(verifier)), []byte(code.CodeChallenge)) != 1 {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	if !s.checkResourceParam(w, f, code.Resource) {
		return
	}
	if !s.identityAllowed(code.Identity) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "user is no longer allowed")
		return
	}
	family := store.NewSecret()
	s.issueTokens(w, r, client.ID, family, code.Resource, code.Scope, code.Identity, true)
}

// checkResourceParam enforces that a resource parameter at the token
// endpoint, if present, names the resource the grant was issued for.
func (s *Server) checkResourceParam(w http.ResponseWriter, f url.Values, granted string) bool {
	raw, err := resourceParam(f)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_target", err.Error())
		return false
	}
	if raw == "" {
		return true
	}
	res, err := s.canonicalResource(raw)
	if err != nil || res != granted {
		oauthError(w, http.StatusBadRequest, "invalid_target", "resource does not match the grant")
		return false
	}
	return true
}

func (s *Server) newTokenPair(clientID, family, resource, scope string, id store.Identity, withRefresh bool) (access, refresh string, ts []*store.Token) {
	now := s.now()
	access = store.NewSecret()
	ts = append(ts, &store.Token{
		Hash: store.Hash(access), Kind: store.Access, FamilyID: family, ClientID: clientID,
		Resource: resource, Scope: scope, Identity: id, CreatedAt: now, ExpiresAt: now.Add(s.cfg.AccessTokenTTL),
	})
	if withRefresh {
		refresh = store.NewSecret()
		ts = append(ts, &store.Token{
			Hash: store.Hash(refresh), Kind: store.Refresh, FamilyID: family, ClientID: clientID,
			Resource: resource, Scope: scope, Identity: id, CreatedAt: now, ExpiresAt: now.Add(s.cfg.RefreshTokenTTL),
		})
	}
	return access, refresh, ts
}

func (s *Server) tokenResponse(w http.ResponseWriter, access, refresh, scope string) {
	resp := map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   int(s.cfg.AccessTokenTTL.Seconds()),
	}
	if refresh != "" {
		resp["refresh_token"] = refresh
	}
	if scope != "" {
		resp["scope"] = scope
	}
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) issueTokens(w http.ResponseWriter, r *http.Request, clientID, family, resource, scope string, id store.Identity, withRefresh bool) {
	access, refresh, ts := s.newTokenPair(clientID, family, resource, scope, id, withRefresh)
	if err := s.store.InsertTokens(r.Context(), ts...); err != nil {
		s.log.Error("token: insert", "err", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	s.store.TouchClient(r.Context(), clientID, s.now())
	s.log.Info("issued tokens", "user", id.Name, "client_id", clientID, "access", tokenLogID(ts[0].Hash))
	s.tokenResponse(w, access, refresh, scope)
}

var errGrantMismatch = errors.New("grant mismatch")

func (s *Server) refreshGrant(w http.ResponseWriter, r *http.Request, client *store.Client) {
	f := r.PostForm
	rawResource, err := resourceParam(f)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_target", err.Error())
		return
	}
	oldHash := store.Hash(f.Get("refresh_token"))
	var access, refresh string
	var checkCode, checkMsg string
	old, err := s.store.RotateRefresh(r.Context(), oldHash, s.now(),
		func(old *store.Token) error {
			switch {
			case old.ClientID != client.ID:
				checkCode, checkMsg = "invalid_grant", "refresh token was issued to another client"
			case !s.identityAllowed(old.Identity):
				checkCode, checkMsg = "invalid_grant", "user is no longer allowed"
			case rawResource != "":
				// A resource on refresh may only name the granted resource.
				if res, err := s.canonicalResource(rawResource); err != nil || res != old.Resource {
					checkCode, checkMsg = "invalid_target", "resource does not match the grant"
				}
			}
			if checkCode != "" {
				return errGrantMismatch
			}
			return nil
		},
		func(old *store.Token) []*store.Token {
			var ts []*store.Token
			access, refresh, ts = s.newTokenPair(client.ID, old.FamilyID, old.Resource, old.Scope, old.Identity, true)
			return ts
		})
	switch {
	case errors.Is(err, store.ErrRefreshReuse):
		s.log.Warn("refresh token reuse: revoked token family", "user", old.Name, "client_id", old.ClientID, "refresh", tokenLogID(oldHash))
		oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token already used")
		return
	case errors.Is(err, store.ErrNotFound):
		oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired refresh token")
		return
	case errors.Is(err, errGrantMismatch):
		oauthError(w, http.StatusBadRequest, checkCode, checkMsg)
		return
	case err != nil:
		s.log.Error("token: rotate refresh", "err", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	s.store.TouchClient(r.Context(), client.ID, s.now())
	s.log.Info("refreshed tokens", "user", old.Name, "client_id", client.ID, "refresh", tokenLogID(oldHash))
	s.tokenResponse(w, access, refresh, old.Scope)
}

// handleRevoke implements RFC 7009 token revocation.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	client, ok := s.authenticateClient(w, r)
	if !ok {
		return
	}
	hash := store.Hash(r.PostForm.Get("token"))
	for _, kind := range []string{store.Access, store.Refresh} {
		t, err := s.store.GetToken(r.Context(), hash, kind, s.now())
		if err != nil || t.ClientID != client.ID {
			continue
		}
		if err := s.store.RevokeToken(r.Context(), hash); err != nil {
			s.log.Error("revoke", "err", err)
			oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "")
			return
		}
		s.log.Info("revoked token", "kind", kind, "client_id", client.ID, "token", tokenLogID(hash))
	}
	// Unknown tokens are not an error (RFC 7009 section 2.2).
	w.WriteHeader(http.StatusOK)
}

// handleMachineToken mints a short-lived access token for a request signed
// with an authorized SSH key.
func (s *Server) handleMachineToken(w http.ResponseWriter, r *http.Request) {
	p, ok, err := s.parseSSHSIG(r)
	if !ok || err != nil {
		msg := "SSHSIG authorization required"
		if err != nil {
			msg = err.Error()
		}
		oauthError(w, http.StatusUnauthorized, "invalid_client", msg)
		return
	}
	key, err := s.verifySSHSIG(r, p)
	if err != nil {
		s.log.Warn("machine token: bad signature", "err", err)
		oauthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	id := store.Identity{Source: "ssh", Subject: key.Fingerprint, Name: key.Name()}
	s.issueTokens(w, r, "machine", store.NewSecret(), s.cfg.PublicURL, "", id, false)
}
