# mcp-exe-dev-proxy

Authenticates an MCP server using exe.dev built-in auth.

A small Go reverse proxy that adds MCP-compliant OAuth to any MCP server
running on an [exe.dev](https://exe.dev) VM, using exe.dev login as the
identity source. The upstream MCP server stays unauthenticated and bound to
localhost; the proxy is the only thing on the public endpoint. It makes any
localhost MCP server usable as a Claude custom connector (claude.ai, mobile,
Desktop, Claude Code) with no changes to the upstream.

```
Claude (cloud / app / Code) ─┐
laptop hooks (SSHSIG) ───────┼─► exe.dev HTTPS front ─► mcp-exe-dev-proxy ─► upstream MCP server
browser (_login) ────────────┘                           (127.0.0.1:8000)     (127.0.0.1:9527)
```

## How it works

The proxy is both the OAuth 2.1 authorization server and the resource server.

**Interactive clients (Claude connectors)** follow the MCP authorization spec:

1. A request without a token gets `401` with
   `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource"`.
2. The client reads the metadata (RFC 9728, RFC 8414), registers itself
   (RFC 7591) and opens `/authorize` in a browser.
3. `/authorize` sends the browser to `/__exe.dev/login` if there is no exe.dev
   session. exe.dev's front then adds `X-ExeDev-UserID` / `X-ExeDev-Email` to
   the request.
4. Users on `allowed_users` get a code straight away (no consent screen);
   everyone else gets a 403 page.
5. The client exchanges the code (PKCE S256 required) for a 1-hour access
   token and a rotating 30-day refresh token.

Tokens are opaque random strings stored as SHA-256 hashes in SQLite: revoking
is a row delete and there are no signing keys. Reusing a rotated refresh
token revokes the whole token family. Access tokens are bound (RFC 8707) to a
resource on this proxy's `public_url` and rejected anywhere else. The
allowlist and `authorized_keys` are re-checked on every request, so removing a
user or key takes effect immediately.

**Machines** (hooks, agents, scripts) sign each request with an SSH key
listed in `authorized_keys`:

```
Authorization: SSHSIG ts=<unix seconds>,nonce=<16-128 chars>,sig=<base64 SSHSIG blob>
```

The signature is `ssh-keygen -Y sign -n mcp-exe-dev-proxy` over
`METHOD\nREQUEST_URI\nTS\nNONCE\n` (request URI = path plus query).
Timestamps more than 5 minutes off and reused nonces are rejected. Clients
that can only send a static bearer header can mint a 1-hour token instead:

```sh
export MCP_EXE_DEV_PROXY_URL=https://clickmem.myvm.exe.xyz
curl -H "Authorization: Bearer $(mcp-exe-dev-proxy token -key ~/.ssh/id_ed25519)" \
  $MCP_EXE_DEV_PROXY_URL/api/...
```

`token` shells out to `ssh-keygen`, so encrypted keys, hardware keys and
ssh-agent (pass the `.pub` file as `-key`) all work.

### Proxying

After the auth check, traffic is passed through byte for byte; JSON-RPC is
not parsed. Streamable HTTP, legacy SSE (`GET /sse` + `POST /messages`) and
plain REST all work.

- Responses are flushed after every upstream write. Event streams are
  requested uncompressed and have no timeouts; if the upstream is silent for
  25 s the proxy sends a `: keepalive` comment (only between events).
- The upstream is mounted at the same paths it uses locally, so the SSE
  `endpoint` event needs no rewriting.
- `Mcp-Session-Id`, `MCP-Protocol-Version`, `Last-Event-ID` and all other
  end-to-end headers pass through. `Authorization` and `X-ExeDev-*` are
  stripped; `X-Forwarded-User` (exe.dev email, or SSH key comment),
  `X-Forwarded-Proto`, `X-Forwarded-Host` and `X-Forwarded-For` are set.
- One upstream per proxy instance.

### Endpoints served by the proxy

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `GET /.well-known/oauth-protected-resource[/<path>]` | none | RFC 9728 metadata |
| `GET /.well-known/oauth-authorization-server` | none | RFC 8414 metadata |
| `POST /register` | none, rate limited | RFC 7591 dynamic client registration |
| `GET /authorize` | exe.dev login, rate limited | issues a code to allowed users |
| `POST /token` | client, rate limited | code exchange and refresh |
| `POST /revoke` | client, rate limited | RFC 7009 revocation |
| `POST /machine/token` | SSHSIG, rate limited | mint an access token for a machine |
| `GET /healthz` | none | proxy status and upstream reachability |
| everything else | bearer token or SSHSIG | forwarded to the upstream |

## Security notes

- Default deny: only the endpoints above are reachable without credentials.
- Dynamic registration only accepts redirect URIs in `allowed_redirect_uris`
  (default: Claude's `https://claude.ai/api/mcp/auth_callback` and
  `https://claude.com/api/mcp/auth_callback`) plus `http` loopback URIs for
  Claude Code, which may use any port (RFC 8252).
- Auth codes are single use and expire after 60 seconds.
- Tokens never appear in logs; a 12-character prefix of their hash does.
- The `X-ExeDev-*` identity headers are only trustworthy because exe.dev's
  front sets them. The proxy must only be reachable through that front, and
  the upstream must only be reachable through the proxy.
- The exe.dev endpoint must be public (Anthropic's cloud has to reach it), so
  exe.dev's own access gate cannot sit in front; `_login` is used only inside
  the `/authorize` flow.

## Deployment

One static binary (pure-Go SQLite, no cgo), one YAML file, one SQLite file.

```sh
CGO_ENABLED=0 go build -o mcp-exe-dev-proxy .
sudo install mcp-exe-dev-proxy /usr/local/bin/
sudo install -D -m 644 deploy/config.example.yaml /etc/mcp-exe-dev-proxy/config.yaml   # then edit
sudo install -m 644 ~/.ssh/id_ed25519.pub /etc/mcp-exe-dev-proxy/authorized_keys      # optional
sudo install -m 644 deploy/mcp-exe-dev-proxy.service /etc/systemd/system/
sudo systemctl enable --now mcp-exe-dev-proxy
```

Then point the exe.dev HTTPS front at the `listen` port, make it public, and
add `public_url` (plus the upstream's MCP path, e.g. `/mcp` or `/sse`) as a
custom connector in Claude, or run
`claude mcp add --transport http clickmem https://clickmem.myvm.exe.xyz/mcp`.

Losing the SQLite file only forces clients to log in again.

## CLI

```
mcp-exe-dev-proxy serve   [-config /etc/mcp-exe-dev-proxy/config.yaml]
mcp-exe-dev-proxy token   -url https://… [-key ~/.ssh/id_ed25519]
mcp-exe-dev-proxy revoke  --all [-config …]
mcp-exe-dev-proxy clients [-config …]
```

The config path can also be set with `MCP_EXE_DEV_PROXY_CONFIG`.

## Open questions from the PRD

- exe.dev `_login` contract: implemented from exe.dev's docs
  (`/__exe.dev/login?redirect=<path>`, `X-ExeDev-UserID`, `X-ExeDev-Email`),
  not from tot-server's code, which wasn't available when this was written.
- Claude's exact callback URL: defaults above, overridable with
  `allowed_redirect_uris`; rejected registrations are logged with the URI.
- Whether exe.dev's front buffers SSE or cuts idle connections: the 25 s
  keepalive is there in case it does; still to be verified in a 30-minute
  soak test.
