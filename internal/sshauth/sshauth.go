// Package sshauth authenticates HTTP requests signed with an SSH key.
//
// The client signs a short challenge with `ssh-keygen -Y sign -n
// mcp-exe-dev-proxy` and sends it as
//
//	Authorization: SSHSIG ts=<unix seconds>,nonce=<random>,sig=<base64 SSHSIG blob>
//
// The signed message is the request method, request URI (path and query),
// timestamp and nonce, each followed by a newline.
package sshauth

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mkmik/mcp-exe-dev-proxy/internal/sshsig"
)

// Namespace is the SSHSIG namespace all request signatures must use.
const Namespace = "mcp-exe-dev-proxy"

// Scheme is the Authorization header scheme.
const Scheme = "SSHSIG"

// MaxSkew is how far a signature timestamp may be from the server clock.
const MaxSkew = 5 * time.Minute

// Message returns the bytes a client signs for a request.
func Message(method, requestURI string, ts int64, nonce string) []byte {
	return fmt.Appendf(nil, "%s\n%s\n%d\n%s\n", method, requestURI, ts, nonce)
}

// NewNonce returns a random nonce suitable for a request.
func NewNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Params are the fields of an SSHSIG Authorization header.
type Params struct {
	Timestamp int64
	Nonce     string
	Sig       []byte // raw SSHSIG blob
}

// Header formats p as an Authorization header value.
func (p Params) Header() string {
	return fmt.Sprintf("%s ts=%d,nonce=%s,sig=%s", Scheme, p.Timestamp, p.Nonce, sshsig.EncodeBlob(p.Sig))
}

// ParseHeader parses an Authorization header value. ok is false when the
// header does not use the SSHSIG scheme at all.
func ParseHeader(h string) (p Params, ok bool, err error) {
	scheme, rest, _ := strings.Cut(h, " ")
	if !strings.EqualFold(scheme, Scheme) {
		return p, false, nil
	}
	for _, kv := range strings.Split(rest, ",") {
		k, v, found := strings.Cut(strings.TrimSpace(kv), "=")
		if !found {
			return p, true, fmt.Errorf("malformed parameter %q", kv)
		}
		switch k {
		case "ts":
			if p.Timestamp, err = strconv.ParseInt(v, 10, 64); err != nil {
				return p, true, fmt.Errorf("bad ts: %w", err)
			}
		case "nonce":
			p.Nonce = v
		case "sig":
			// base64 may itself end in '=' padding, which Cut leaves in v.
			if p.Sig, err = sshsig.DecodeBlob(v); err != nil {
				return p, true, fmt.Errorf("bad sig: %w", err)
			}
		}
	}
	if p.Timestamp == 0 || p.Nonce == "" || len(p.Sig) == 0 {
		return p, true, errors.New("missing ts, nonce or sig")
	}
	if len(p.Nonce) < 16 || len(p.Nonce) > 128 {
		return p, true, errors.New("nonce must be 16 to 128 characters")
	}
	return p, true, nil
}

// Key is an authorized SSH key.
type Key struct {
	PublicKey   ssh.PublicKey
	Comment     string
	Fingerprint string
}

// Name is the identity reported for the key: its comment, or its
// fingerprint when the comment is empty.
func (k *Key) Name() string {
	if k.Comment != "" {
		return k.Comment
	}
	return k.Fingerprint
}

// Keyring is an authorized_keys file, re-read when it changes on disk.
type Keyring struct {
	path string

	mu      sync.Mutex
	modTime time.Time
	size    int64
	keys    map[string]*Key // by fingerprint
}

// NewKeyring loads path. An empty path yields a keyring that accepts nothing.
func NewKeyring(path string) (*Keyring, error) {
	kr := &Keyring{path: path}
	if path == "" {
		return kr, nil
	}
	if err := kr.reload(); err != nil {
		return nil, err
	}
	return kr, nil
}

func (kr *Keyring) reload() error {
	fi, err := os.Stat(kr.path)
	if err != nil {
		return err
	}
	if kr.keys != nil && fi.ModTime().Equal(kr.modTime) && fi.Size() == kr.size {
		return nil
	}
	data, err := os.ReadFile(kr.path)
	if err != nil {
		return err
	}
	keys, err := ParseAuthorizedKeys(data)
	if err != nil {
		return fmt.Errorf("%s: %w", kr.path, err)
	}
	kr.keys, kr.modTime, kr.size = keys, fi.ModTime(), fi.Size()
	return nil
}

// ParseAuthorizedKeys parses an authorized_keys-style file.
func ParseAuthorizedKeys(data []byte) (map[string]*Key, error) {
	keys := map[string]*Key{}
	for len(bytes.TrimSpace(data)) > 0 {
		pub, comment, _, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			return nil, err
		}
		fp := ssh.FingerprintSHA256(pub)
		keys[fp] = &Key{PublicKey: pub, Comment: comment, Fingerprint: fp}
		data = rest
	}
	return keys, nil
}

// Lookup returns the authorized key with the given fingerprint, or nil.
func (kr *Keyring) Lookup(fingerprint string) *Key {
	if kr.path == "" {
		return nil
	}
	kr.mu.Lock()
	defer kr.mu.Unlock()
	// On a reload error keep serving the last good set of keys; a missing
	// file (never loaded) means no keys.
	_ = kr.reload()
	return kr.keys[fingerprint]
}

// Verify checks p against the request and returns the key that signed it.
// It does not check nonce reuse; the caller must do that.
func (kr *Keyring) Verify(p Params, method, requestURI string, now time.Time) (*Key, error) {
	skew := now.Sub(time.Unix(p.Timestamp, 0))
	if skew > MaxSkew || skew < -MaxSkew {
		return nil, errors.New("timestamp outside allowed window")
	}
	sig, err := sshsig.Parse(p.Sig)
	if err != nil {
		return nil, err
	}
	key := kr.Lookup(ssh.FingerprintSHA256(sig.PublicKey))
	if key == nil {
		return nil, fmt.Errorf("key %s is not authorized", ssh.FingerprintSHA256(sig.PublicKey))
	}
	if err := sig.Verify(Namespace, Message(method, requestURI, p.Timestamp, p.Nonce)); err != nil {
		return nil, err
	}
	return key, nil
}
