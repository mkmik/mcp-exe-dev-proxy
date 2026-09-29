package server

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mkmik/mcp-exe-dev-proxy/internal/config"
	"github.com/mkmik/mcp-exe-dev-proxy/internal/identity"
	"github.com/mkmik/mcp-exe-dev-proxy/internal/sshauth"
	"github.com/mkmik/mcp-exe-dev-proxy/internal/sshsig"
	"github.com/mkmik/mcp-exe-dev-proxy/internal/store"
)

const (
	allowedID    = "user-marko"
	allowedEmail = "marko@example.com"
)

type env struct {
	t        *testing.T
	url      string
	srv      *Server
	store    *store.Store
	signer   ssh.Signer
	upstream *recorder
	noRedir  *http.Client
}

// recorder is a fake upstream MCP server.
type recorder struct {
	mu   sync.Mutex
	last *http.Request
}

func (rec *recorder) lastRequest() *http.Request {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return rec.last
}

func (rec *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec.mu.Lock()
	rec.last = r.Clone(r.Context())
	rec.mu.Unlock()
	switch r.URL.Path {
	case "/sse":
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Mcp-Session-Id", "sess-1")
		fmt.Fprint(w, "event: endpoint\ndata: /messages?sessionId=1\n\n")
		w.(http.Flusher).Flush()
		// Half an event, then silence: no keepalive may be injected here.
		time.Sleep(150 * time.Millisecond)
		fmt.Fprint(w, "data: partial")
		w.(http.Flusher).Flush()
		time.Sleep(150 * time.Millisecond)
		fmt.Fprint(w, "\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	default:
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Mcp-Session-Id", "sess-1")
		fmt.Fprintf(w, "upstream %s %s %s", r.Method, r.URL.RequestURI(), body)
	}
}

func newEnv(t *testing.T) *env {
	t.Helper()
	up := &recorder{}
	upstream := httptest.NewServer(up)
	t.Cleanup(upstream.Close)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	dir := t.TempDir()
	akPath := filepath.Join(dir, "authorized_keys")
	os.WriteFile(akPath, append(ssh.MarshalAuthorizedKey(signer.PublicKey())[:len(ssh.MarshalAuthorizedKey(signer.PublicKey()))-1], []byte(" laptop-agent\n")...), 0o600)

	ts := httptest.NewUnstartedServer(nil)
	publicURL := "http://" + ts.Listener.Addr().String()
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
public_url: %s
upstream: %s
allowed_users: [%s]
authorized_keys: %s
db: %s
rate_burst: 1000
sse_keepalive: 100ms
`, publicURL, upstream.URL, allowedEmail, akPath, filepath.Join(dir, "state.db"))))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg.DB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	keys, err := sshauth.NewKeyring(cfg.AuthorizedKeys)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg, st, keys, identity.ExeDev{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = srv
	ts.Start()
	t.Cleanup(ts.Close)
	return &env{
		t: t, url: publicURL, srv: srv, store: st, signer: signer, upstream: up,
		noRedir: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
}

func (e *env) do(req *http.Request) (*http.Response, string) {
	e.t.Helper()
	resp, err := e.noRedir.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (e *env) get(path string, hdr map[string]string) (*http.Response, string) {
	req, _ := http.NewRequest("GET", e.url+path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return e.do(req)
}

func (e *env) postForm(path string, form url.Values) (*http.Response, map[string]any) {
	e.t.Helper()
	req, _ := http.NewRequest("POST", e.url+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, body := e.do(req)
	var m map[string]any
	json.Unmarshal([]byte(body), &m)
	return resp, m
}

func (e *env) register(body string) (int, map[string]any) {
	e.t.Helper()
	req, _ := http.NewRequest("POST", e.url+"/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, b := e.do(req)
	var m map[string]any
	json.Unmarshal([]byte(b), &m)
	return resp.StatusCode, m
}

var loggedIn = map[string]string{identity.ExeDevUserIDHeader: allowedID, identity.ExeDevEmailHeader: allowedEmail}

const verifier = "0123456789abcdefghijklmnopqrstuvwxyz-._~ABCDEFG"

// authorize runs /authorize as a logged-in allowed user and returns the code.
func (e *env) authorize(clientID, redirectURI string, extra url.Values) string {
	e.t.Helper()
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
		"code_challenge": {s256(verifier)}, "code_challenge_method": {"S256"}, "state": {"xyz"},
	}
	for k, v := range extra {
		q[k] = v
	}
	resp, body := e.get("/authorize?"+q.Encode(), loggedIn)
	if resp.StatusCode != http.StatusFound {
		e.t.Fatalf("authorize: %d %s", resp.StatusCode, body)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if got := loc.Query().Get("state"); got != "xyz" {
		e.t.Fatalf("state = %q", got)
	}
	if got := loc.Query().Get("iss"); got != e.url {
		e.t.Fatalf("iss = %q", got)
	}
	code := loc.Query().Get("code")
	if code == "" {
		e.t.Fatalf("no code in %s", loc)
	}
	return code
}

func (e *env) bearerGet(path, tok string) *http.Response {
	resp, _ := e.get(path, map[string]string{"Authorization": "Bearer " + tok})
	return resp
}

func TestUnauthenticated(t *testing.T) {
	e := newEnv(t)
	resp, _ := e.get("/mcp", nil)
	if resp.StatusCode != 401 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	want := fmt.Sprintf(`resource_metadata="%s/.well-known/oauth-protected-resource"`, e.url)
	if h := resp.Header.Get("WWW-Authenticate"); !strings.Contains(h, want) {
		t.Fatalf("WWW-Authenticate = %q", h)
	}
	if e.upstream.lastRequest() != nil {
		t.Fatal("unauthenticated request reached upstream")
	}
	// Browser identity headers alone are not credentials.
	if resp, _ := e.get("/mcp", loggedIn); resp.StatusCode != 401 {
		t.Fatalf("exe.dev headers alone: status %d", resp.StatusCode)
	}
	if resp := e.bearerGet("/mcp", "garbage"); resp.StatusCode != 401 {
		t.Fatalf("bad token: status %d", resp.StatusCode)
	}
}

func TestMetadata(t *testing.T) {
	e := newEnv(t)
	_, body := e.get("/.well-known/oauth-protected-resource", nil)
	var prm map[string]any
	json.Unmarshal([]byte(body), &prm)
	if prm["resource"] != e.url || prm["authorization_servers"].([]any)[0] != e.url {
		t.Fatalf("protected resource metadata: %s", body)
	}
	_, body = e.get("/.well-known/oauth-protected-resource/mcp", nil)
	json.Unmarshal([]byte(body), &prm)
	if prm["resource"] != e.url+"/mcp" {
		t.Fatalf("path-suffixed metadata: %s", body)
	}
	_, body = e.get("/.well-known/oauth-authorization-server", nil)
	var asm map[string]any
	json.Unmarshal([]byte(body), &asm)
	if asm["issuer"] != e.url || asm["token_endpoint"] != e.url+"/token" || asm["registration_endpoint"] != e.url+"/register" {
		t.Fatalf("AS metadata: %s", body)
	}
}

func TestRegistration(t *testing.T) {
	e := newEnv(t)
	for _, uri := range []string{"https://evil.example/cb", "javascript:alert(1)", "http://localhost/cb#frag"} {
		if code, _ := e.register(`{"redirect_uris":["` + uri + `"],"token_endpoint_auth_method":"none"}`); code != 400 {
			t.Errorf("%s: status %d, want 400", uri, code)
		}
	}
	for _, uri := range []string{"https://claude.ai/api/mcp/auth_callback", "http://localhost:3456/callback", "http://127.0.0.1:9/cb"} {
		if code, m := e.register(`{"redirect_uris":["` + uri + `"],"token_endpoint_auth_method":"none"}`); code != 201 || m["client_secret"] != nil {
			t.Errorf("%s: status %d %v", uri, code, m)
		}
	}
	// Default auth method is client_secret_basic, which gets a secret.
	if code, m := e.register(`{"redirect_uris":["http://localhost/cb"]}`); code != 201 || m["client_secret"] == nil {
		t.Errorf("confidential: %d %v", code, m)
	}
}

func TestAuthorizeErrors(t *testing.T) {
	e := newEnv(t)
	_, c := e.register(`{"redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"token_endpoint_auth_method":"none"}`)
	clientID := c["client_id"].(string)
	base := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {"https://claude.ai/api/mcp/auth_callback"},
		"code_challenge": {s256(verifier)}, "code_challenge_method": {"S256"}, "state": {"s"},
	}
	with := func(k, v string) string {
		q := url.Values{}
		for kk, vv := range base {
			q[kk] = vv
		}
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
		return "/authorize?" + q.Encode()
	}

	// Not logged in: sent to exe.dev login, coming back to the same URL.
	resp, _ := e.get(with("state", "s"), nil)
	loc := resp.Header.Get("Location")
	if resp.StatusCode != 302 || !strings.HasPrefix(loc, "/__exe.dev/login?redirect=") {
		t.Fatalf("login redirect: %d %q", resp.StatusCode, loc)
	}
	back, _ := url.QueryUnescape(strings.TrimPrefix(loc, "/__exe.dev/login?redirect="))
	if !strings.HasPrefix(back, "/authorize?") || !strings.Contains(back, clientID) {
		t.Fatalf("login return path %q", back)
	}

	// Logged in but not on the allowlist.
	resp, _ = e.get(with("state", "s"), map[string]string{identity.ExeDevUserIDHeader: "u2", identity.ExeDevEmailHeader: "eve@example.com"})
	if resp.StatusCode != 403 || resp.Header.Get("Location") != "" {
		t.Fatalf("disallowed user: %d", resp.StatusCode)
	}

	// Unregistered redirect URI: error page, never a redirect.
	resp, _ = e.get(with("redirect_uri", "https://claude.ai/other"), loggedIn)
	if resp.StatusCode != 400 {
		t.Fatalf("bad redirect_uri: %d", resp.StatusCode)
	}
	resp, _ = e.get(with("client_id", "nope"), loggedIn)
	if resp.StatusCode != 400 {
		t.Fatalf("unknown client: %d", resp.StatusCode)
	}

	for name, path := range map[string]string{
		"plain PKCE":    with("code_challenge_method", "plain"),
		"no PKCE":       with("code_challenge", ""),
		"no method":     with("code_challenge_method", ""),
		"foreign res":   with("resource", "https://evil.example/mcp"),
		"response_type": with("response_type", "token"),
	} {
		resp, _ := e.get(path, loggedIn)
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if resp.StatusCode != 302 || loc.Query().Get("error") == "" || loc.Query().Get("code") != "" {
			t.Errorf("%s: %d %s", name, resp.StatusCode, loc)
		}
	}
}

func TestOAuthFlowAndProxy(t *testing.T) {
	e := newEnv(t)
	redirect := "http://127.0.0.1:33418/callback"
	_, c := e.register(`{"client_name":"Claude Code","redirect_uris":["` + redirect + `"],"token_endpoint_auth_method":"none"}`)
	clientID := c["client_id"].(string)

	// Loopback redirects may change port between registration and use.
	code := e.authorize(clientID, "http://127.0.0.1:40000/callback", url.Values{"resource": {e.url + "/mcp"}})

	exchange := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {"http://127.0.0.1:40000/callback"}, "code_verifier": {"wrong" + verifier[5:]}, "resource": {e.url + "/mcp"}}
	// A bad verifier burns the code.
	if resp, m := e.postForm("/token", exchange); resp.StatusCode != 400 || m["error"] != "invalid_grant" {
		t.Fatalf("bad verifier: %d %v", resp.StatusCode, m)
	}
	code = e.authorize(clientID, "http://127.0.0.1:40000/callback", url.Values{"resource": {e.url + "/mcp"}})
	exchange.Set("code", code)
	exchange.Set("code_verifier", verifier)
	resp, tok := e.postForm("/token", exchange)
	if resp.StatusCode != 200 || tok["token_type"] != "Bearer" || tok["refresh_token"] == nil {
		t.Fatalf("token: %d %v", resp.StatusCode, tok)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("token response is cacheable")
	}
	// Codes are single use.
	if resp, _ := e.postForm("/token", exchange); resp.StatusCode != 400 {
		t.Fatalf("code reuse: %d", resp.StatusCode)
	}
	access := tok["access_token"].(string)

	// Proxied request: body, path, query and MCP headers pass through;
	// credentials and identity headers do not.
	req, _ := http.NewRequest("POST", e.url+"/mcp?x=1", strings.NewReader(`{"jsonrpc":"2.0"}`))
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Mcp-Session-Id", "sess-1")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	req.Header.Set("X-Forwarded-User", "spoofed")
	req.Header.Set(identity.ExeDevEmailHeader, "spoofed@example.com")
	resp, body := e.do(req)
	if resp.StatusCode != 200 || body != `upstream POST /mcp?x=1 {"jsonrpc":"2.0"}` {
		t.Fatalf("proxy: %d %q", resp.StatusCode, body)
	}
	if resp.Header.Get("Mcp-Session-Id") != "sess-1" {
		t.Error("Mcp-Session-Id not returned")
	}
	up := e.upstream.lastRequest()
	for h, want := range map[string]string{
		"Authorization":            "",
		identity.ExeDevEmailHeader: "",
		"X-Forwarded-User":         allowedEmail,
		"X-Forwarded-Proto":        "http",
		"Mcp-Session-Id":           "sess-1",
		"Mcp-Protocol-Version":     "2025-06-18",
	} {
		if got := up.Header.Get(h); got != want {
			t.Errorf("upstream %s = %q, want %q", h, got, want)
		}
	}

	// Refresh rotates.
	refresh1 := tok["refresh_token"].(string)
	resp, tok2 := e.postForm("/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh1}, "client_id": {clientID}})
	if resp.StatusCode != 200 || tok2["refresh_token"] == refresh1 {
		t.Fatalf("refresh: %d %v", resp.StatusCode, tok2)
	}
	access2 := tok2["access_token"].(string)
	if r := e.bearerGet("/mcp", access2); r.StatusCode != 200 {
		t.Fatalf("refreshed token rejected: %d", r.StatusCode)
	}
	// Reusing the old refresh token kills the whole chain.
	if resp, _ := e.postForm("/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh1}, "client_id": {clientID}}); resp.StatusCode != 400 {
		t.Fatalf("refresh reuse: %d", resp.StatusCode)
	}
	if r := e.bearerGet("/mcp", access2); r.StatusCode != 401 {
		t.Fatalf("access token survived refresh reuse: %d", r.StatusCode)
	}
	if resp, _ := e.postForm("/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok2["refresh_token"].(string)}, "client_id": {clientID}}); resp.StatusCode != 400 {
		t.Fatalf("new refresh token survived reuse: %d", resp.StatusCode)
	}
}

func TestConfidentialClientAndRevoke(t *testing.T) {
	e := newEnv(t)
	_, c := e.register(`{"redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"token_endpoint_auth_method":"client_secret_post"}`)
	id, secret := c["client_id"].(string), c["client_secret"].(string)
	code := e.authorize(id, "https://claude.ai/api/mcp/auth_callback", nil)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {id}, "code_verifier": {verifier}}
	if resp, m := e.postForm("/token", form); resp.StatusCode != 401 || m["error"] != "invalid_client" {
		t.Fatalf("missing secret: %d %v", resp.StatusCode, m)
	}
	code = e.authorize(id, "https://claude.ai/api/mcp/auth_callback", nil)
	form.Set("code", code)
	form.Set("client_secret", secret)
	resp, tok := e.postForm("/token", form)
	if resp.StatusCode != 200 {
		t.Fatalf("token: %d %v", resp.StatusCode, tok)
	}
	access, refresh := tok["access_token"].(string), tok["refresh_token"].(string)
	if r := e.bearerGet("/anything", access); r.StatusCode != 200 {
		t.Fatalf("access: %d", r.StatusCode)
	}
	// Revoking the refresh token revokes its access tokens too.
	if resp, _ := e.postForm("/revoke", url.Values{"token": {refresh}, "client_id": {id}, "client_secret": {secret}}); resp.StatusCode != 200 {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	if r := e.bearerGet("/anything", access); r.StatusCode != 401 {
		t.Fatalf("access after revoke: %d", r.StatusCode)
	}
}

func (e *env) sshsigHeader(method, path string, ts time.Time, nonce string) string {
	blob, err := sshsig.Sign(e.signer, sshauth.Namespace, sshauth.Message(method, path, ts.Unix(), nonce))
	if err != nil {
		e.t.Fatal(err)
	}
	return sshauth.Params{Timestamp: ts.Unix(), Nonce: nonce, Sig: blob}.Header()
}

func TestMachineAuth(t *testing.T) {
	e := newEnv(t)
	now := time.Now()

	// Direct SSHSIG on a proxied request.
	h := e.sshsigHeader("GET", "/api/recall?q=x", now, sshauth.NewNonce())
	resp, body := e.get("/api/recall?q=x", map[string]string{"Authorization": h})
	if resp.StatusCode != 200 {
		t.Fatalf("sshsig: %d %s", resp.StatusCode, body)
	}
	if got := e.upstream.lastRequest().Header.Get("X-Forwarded-User"); got != "laptop-agent" {
		t.Errorf("X-Forwarded-User = %q", got)
	}
	// Replay.
	if resp, _ := e.get("/api/recall?q=x", map[string]string{"Authorization": h}); resp.StatusCode != 401 {
		t.Fatalf("replay: %d", resp.StatusCode)
	}
	// Signature for another path.
	h = e.sshsigHeader("GET", "/api/other", now, sshauth.NewNonce())
	if resp, _ := e.get("/api/recall", map[string]string{"Authorization": h}); resp.StatusCode != 401 {
		t.Fatalf("wrong path: %d", resp.StatusCode)
	}
	// Stale timestamp.
	h = e.sshsigHeader("GET", "/x", now.Add(-6*time.Minute), sshauth.NewNonce())
	if resp, _ := e.get("/x", map[string]string{"Authorization": h}); resp.StatusCode != 401 {
		t.Fatalf("stale: %d", resp.StatusCode)
	}
	// Unknown key.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := ssh.NewSignerFromKey(other)
	nonce := sshauth.NewNonce()
	blob, _ := sshsig.Sign(otherSigner, sshauth.Namespace, sshauth.Message("GET", "/x", now.Unix(), nonce))
	h = sshauth.Params{Timestamp: now.Unix(), Nonce: nonce, Sig: blob}.Header()
	if resp, _ := e.get("/x", map[string]string{"Authorization": h}); resp.StatusCode != 401 {
		t.Fatalf("unknown key: %d", resp.StatusCode)
	}

	// Minted machine token.
	req, _ := http.NewRequest("POST", e.url+"/machine/token", nil)
	req.Header.Set("Authorization", e.sshsigHeader("POST", "/machine/token", now, sshauth.NewNonce()))
	resp, body = e.do(req)
	var tok map[string]any
	json.Unmarshal([]byte(body), &tok)
	if resp.StatusCode != 200 || tok["refresh_token"] != nil {
		t.Fatalf("machine token: %d %s", resp.StatusCode, body)
	}
	if r := e.bearerGet("/api/remember", tok["access_token"].(string)); r.StatusCode != 200 {
		t.Fatalf("machine bearer: %d", r.StatusCode)
	}
	req, _ = http.NewRequest("POST", e.url+"/machine/token", nil)
	if resp, _ := e.do(req); resp.StatusCode != 401 {
		t.Fatalf("machine token without signature: %d", resp.StatusCode)
	}

	// revoke --all locks everyone out.
	if _, err := e.store.RevokeAll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if r := e.bearerGet("/api/remember", tok["access_token"].(string)); r.StatusCode != 401 {
		t.Fatalf("after revoke all: %d", r.StatusCode)
	}
}

func TestTokenForOtherResource(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	access := store.NewSecret()
	err := e.store.InsertTokens(t.Context(), &store.Token{
		Hash: store.Hash(access), Kind: store.Access, FamilyID: "f", ClientID: "c",
		Resource: "https://other.example", Identity: store.Identity{Source: "exedev", Subject: allowedID, Name: allowedEmail},
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := e.bearerGet("/mcp", access); r.StatusCode != 401 {
		t.Fatalf("foreign-audience token accepted: %d", r.StatusCode)
	}
}

func TestSSEStreaming(t *testing.T) {
	e := newEnv(t)
	req, _ := http.NewRequest("GET", e.url+"/sse", nil)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Authorization", e.sshsigHeader("GET", "/sse", time.Now(), sshauth.NewNonce()))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if up := e.upstream.lastRequest(); up.Header.Get("Accept-Encoding") != "" {
		t.Errorf("Accept-Encoding forwarded on event stream: %q", up.Header.Get("Accept-Encoding"))
	}

	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	next := func() string {
		select {
		case l := <-lines:
			return l
		case <-time.After(2 * time.Second):
			t.Fatal("stream stalled")
			return ""
		}
	}
	// The first event must arrive unbuffered, while upstream is still open.
	want := []string{"event: endpoint", "data: /messages?sessionId=1", ""}
	for _, w := range want {
		if got := next(); got != w {
			t.Fatalf("got %q, want %q", got, w)
		}
	}
	// Upstream pauses between events (a keepalive is fine there), then
	// sends half an event and pauses again; that keepalive must wait, or it
	// would corrupt the event into "data: partial: keepalive".
	got := next()
	for got == ": keepalive" {
		if blank := next(); blank != "" {
			t.Fatalf("keepalive not terminated: %q", blank)
		}
		got = next()
	}
	if got != "data: partial" {
		t.Fatalf("got %q, want the partial event intact", got)
	}
	if got := next(); got != "" {
		t.Fatalf("got %q", got)
	}
	// Now upstream is silent: keepalives flow.
	if got := next(); got != ": keepalive" {
		t.Fatalf("got %q, want keepalive", got)
	}
}
