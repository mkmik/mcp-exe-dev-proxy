// Package store keeps the proxy's OAuth state in SQLite: registered clients,
// authorization codes, token hashes and SSHSIG nonces. Secrets are only ever
// stored hashed.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound = errors.New("not found")
	// ErrRefreshReuse means an already-rotated refresh token was presented;
	// the whole token family has been revoked.
	ErrRefreshReuse = errors.New("refresh token reuse detected")
	// ErrReplay means an SSHSIG nonce was seen before.
	ErrReplay = errors.New("nonce already used")
)

const schema = `
CREATE TABLE IF NOT EXISTS clients (
	client_id TEXT PRIMARY KEY,
	client_name TEXT NOT NULL,
	redirect_uris TEXT NOT NULL,
	secret_hash TEXT NOT NULL DEFAULT '',
	auth_method TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	last_used_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS codes (
	code_hash TEXT PRIMARY KEY,
	client_id TEXT NOT NULL,
	redirect_uri TEXT NOT NULL,
	code_challenge TEXT NOT NULL,
	resource TEXT NOT NULL,
	scope TEXT NOT NULL,
	source TEXT NOT NULL,
	subject TEXT NOT NULL,
	user_name TEXT NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
	token_hash TEXT PRIMARY KEY,
	kind TEXT NOT NULL,
	family_id TEXT NOT NULL,
	client_id TEXT NOT NULL,
	resource TEXT NOT NULL,
	scope TEXT NOT NULL,
	source TEXT NOT NULL,
	subject TEXT NOT NULL,
	user_name TEXT NOT NULL,
	rotated INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS tokens_family ON tokens(family_id);
CREATE TABLE IF NOT EXISTS nonces (
	nonce TEXT PRIMARY KEY,
	expires_at INTEGER NOT NULL
);
`

// Store is the SQLite-backed state.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the database at path.
func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Hash returns the storage key for a secret (token, code or client secret).
func Hash(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

// NewSecret returns a random 256-bit URL-safe string.
func NewSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Identity is who a code or token was issued to.
type Identity struct {
	// Source is "exedev" or "ssh".
	Source string
	// Subject is the stable identifier: exe.dev user ID or SSH key
	// fingerprint.
	Subject string
	// Name is what the upstream sees in X-Forwarded-User: exe.dev email or
	// SSH key comment.
	Name string
}

// Client is a dynamically registered OAuth client.
type Client struct {
	ID           string
	Name         string
	RedirectURIs []string
	SecretHash   string
	AuthMethod   string
	CreatedAt    time.Time
	LastUsedAt   time.Time
}

func (s *Store) CreateClient(ctx context.Context, c *Client) error {
	uris, _ := json.Marshal(c.RedirectURIs)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO clients (client_id, client_name, redirect_uris, secret_hash, auth_method, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		c.ID, c.Name, string(uris), c.SecretHash, c.AuthMethod, c.CreatedAt.Unix())
	return err
}

func (s *Store) GetClient(ctx context.Context, id string) (*Client, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT client_id, client_name, redirect_uris, secret_hash, auth_method, created_at, last_used_at FROM clients WHERE client_id = ?`, id)
	c, err := scanClient(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

func (s *Store) ListClients(ctx context.Context) ([]*Client, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT client_id, client_name, redirect_uris, secret_hash, auth_method, created_at, last_used_at FROM clients ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cs []*Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		cs = append(cs, c)
	}
	return cs, rows.Err()
}

func scanClient(row interface{ Scan(...any) error }) (*Client, error) {
	var c Client
	var uris string
	var created, used int64
	if err := row.Scan(&c.ID, &c.Name, &uris, &c.SecretHash, &c.AuthMethod, &created, &used); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(uris), &c.RedirectURIs); err != nil {
		return nil, err
	}
	c.CreatedAt = time.Unix(created, 0)
	if used != 0 {
		c.LastUsedAt = time.Unix(used, 0)
	}
	return &c, nil
}

func (s *Store) TouchClient(ctx context.Context, id string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE clients SET last_used_at = ? WHERE client_id = ?`, now.Unix(), id)
	return err
}

// Code is a pending authorization code.
type Code struct {
	Hash          string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	Resource      string
	Scope         string
	Identity
	ExpiresAt time.Time
}

func (s *Store) SaveCode(ctx context.Context, c *Code) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO codes (code_hash, client_id, redirect_uri, code_challenge, resource, scope, source, subject, user_name, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Hash, c.ClientID, c.RedirectURI, c.CodeChallenge, c.Resource, c.Scope, c.Source, c.Subject, c.Name, c.ExpiresAt.Unix())
	return err
}

// TakeCode deletes and returns the code with the given hash. Codes are
// single-use: a second TakeCode for the same hash returns ErrNotFound.
func (s *Store) TakeCode(ctx context.Context, hash string, now time.Time) (*Code, error) {
	var c Code
	var exp int64
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM codes WHERE code_hash = ? RETURNING client_id, redirect_uri, code_challenge, resource, scope, source, subject, user_name, expires_at`, hash).
		Scan(&c.ClientID, &c.RedirectURI, &c.CodeChallenge, &c.Resource, &c.Scope, &c.Source, &c.Subject, &c.Name, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.Hash = hash
	c.ExpiresAt = time.Unix(exp, 0)
	if !now.Before(c.ExpiresAt) {
		return nil, ErrNotFound
	}
	return &c, nil
}

// Token kinds.
const (
	Access  = "access"
	Refresh = "refresh"
)

// Token is a stored access or refresh token. Tokens issued from the same
// authorization grant share a FamilyID.
type Token struct {
	Hash     string
	Kind     string
	FamilyID string
	ClientID string
	Resource string
	Scope    string
	Identity
	Rotated   bool
	CreatedAt time.Time
	ExpiresAt time.Time
}

func insertToken(ctx context.Context, x interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, t *Token) error {
	_, err := x.ExecContext(ctx,
		`INSERT INTO tokens (token_hash, kind, family_id, client_id, resource, scope, source, subject, user_name, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.Hash, t.Kind, t.FamilyID, t.ClientID, t.Resource, t.Scope, t.Source, t.Subject, t.Name, t.CreatedAt.Unix(), t.ExpiresAt.Unix())
	return err
}

// InsertTokens stores tokens atomically.
func (s *Store) InsertTokens(ctx context.Context, ts ...*Token) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, t := range ts {
		if err := insertToken(ctx, tx, t); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const tokenCols = `token_hash, kind, family_id, client_id, resource, scope, source, subject, user_name, rotated, created_at, expires_at`

func scanToken(row interface{ Scan(...any) error }) (*Token, error) {
	var t Token
	var created, exp int64
	err := row.Scan(&t.Hash, &t.Kind, &t.FamilyID, &t.ClientID, &t.Resource, &t.Scope, &t.Source, &t.Subject, &t.Name, &t.Rotated, &created, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.CreatedAt, t.ExpiresAt = time.Unix(created, 0), time.Unix(exp, 0)
	return &t, nil
}

// GetToken returns a live (unexpired, unrotated) token of the given kind.
func (s *Store) GetToken(ctx context.Context, hash, kind string, now time.Time) (*Token, error) {
	t, err := scanToken(s.db.QueryRowContext(ctx,
		`SELECT `+tokenCols+` FROM tokens WHERE token_hash = ? AND kind = ?`, hash, kind))
	if err != nil {
		return nil, err
	}
	if t.Rotated || !now.Before(t.ExpiresAt) {
		return nil, ErrNotFound
	}
	return t, nil
}

// RotateRefresh marks the refresh token oldHash as used and stores the
// replacement tokens, all in one transaction. check is called with the old
// token before anything changes; an error from it aborts the rotation. If
// the old token was already rotated, the whole family is revoked and
// ErrRefreshReuse is returned.
func (s *Store) RotateRefresh(ctx context.Context, oldHash string, now time.Time, check func(*Token) error, issue func(old *Token) []*Token) (*Token, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	old, err := scanToken(tx.QueryRowContext(ctx,
		`SELECT `+tokenCols+` FROM tokens WHERE token_hash = ? AND kind = ?`, oldHash, Refresh))
	if err != nil {
		return nil, err
	}
	if old.Rotated {
		if _, err := tx.ExecContext(ctx, `DELETE FROM tokens WHERE family_id = ?`, old.FamilyID); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return old, ErrRefreshReuse
	}
	if !now.Before(old.ExpiresAt) {
		return nil, ErrNotFound
	}
	if err := check(old); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE tokens SET rotated = 1 WHERE token_hash = ?`, oldHash); err != nil {
		return nil, err
	}
	for _, t := range issue(old) {
		if err := insertToken(ctx, tx, t); err != nil {
			return nil, err
		}
	}
	return old, tx.Commit()
}

// RevokeToken deletes the token with the given hash. Revoking a refresh
// token revokes its whole family, including access tokens.
func (s *Store) RevokeToken(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM tokens WHERE token_hash = ?1
		 OR family_id IN (SELECT family_id FROM tokens WHERE token_hash = ?1 AND kind = 'refresh')`, hash)
	return err
}

// RevokeAll deletes every token and pending code and returns how many
// tokens were deleted.
func (s *Store) RevokeAll(ctx context.Context) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM tokens`)
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM codes`); err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, tx.Commit()
}

// UseNonce records nonce, returning ErrReplay if it was already recorded.
func (s *Store) UseNonce(ctx context.Context, nonce string, expires time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO nonces (nonce, expires_at) VALUES (?, ?) ON CONFLICT(nonce) DO NOTHING`, nonce, expires.Unix())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrReplay
	}
	return nil
}

// GC deletes expired codes, tokens and nonces.
func (s *Store) GC(ctx context.Context, now time.Time) error {
	for _, q := range []string{
		`DELETE FROM codes WHERE expires_at <= ?`,
		`DELETE FROM tokens WHERE expires_at <= ?`,
		`DELETE FROM nonces WHERE expires_at <= ?`,
	} {
		if _, err := s.db.ExecContext(ctx, q, now.Unix()); err != nil {
			return err
		}
	}
	return nil
}
