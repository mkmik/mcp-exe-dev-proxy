// Package config loads the proxy's YAML configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultPath is where serve and the admin commands look for the config.
const DefaultPath = "/etc/mcp-exe-dev-proxy/config.yaml"

// DefaultRedirectURIs are the redirect URIs accepted at dynamic client
// registration when the config does not list its own. Loopback URIs (for
// Claude Code) are always accepted on any port.
var DefaultRedirectURIs = []string{
	"https://claude.ai/api/mcp/auth_callback",
	"https://claude.com/api/mcp/auth_callback",
}

// Config is the proxy configuration.
type Config struct {
	// PublicURL is the URL clients use to reach the proxy, e.g.
	// https://clickmem.myvm.exe.xyz. It is the OAuth issuer and resource.
	PublicURL string `yaml:"public_url"`
	// Listen is the address the proxy listens on.
	Listen string `yaml:"listen"`
	// Upstream is the base URL of the MCP server being protected.
	Upstream string `yaml:"upstream"`
	// AllowedUsers lists exe.dev user IDs or emails that may log in.
	AllowedUsers []string `yaml:"allowed_users"`
	// AuthorizedKeys is an authorized_keys-style file of SSH keys that may
	// authenticate with SSHSIG.
	AuthorizedKeys string `yaml:"authorized_keys"`
	// DB is the SQLite state file.
	DB string `yaml:"db"`

	AccessTokenTTL  time.Duration `yaml:"access_token_ttl"`
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl"`

	// AllowedRedirectURIs are exact redirect URIs accepted at client
	// registration, in addition to loopback URIs.
	AllowedRedirectURIs []string `yaml:"allowed_redirect_uris"`

	// RateLimit is the sustained per-IP request rate (per second) on the
	// OAuth and machine token endpoints; RateBurst is the burst size.
	RateLimit float64 `yaml:"rate_limit"`
	RateBurst int     `yaml:"rate_burst"`

	// SSEKeepalive is how long an event stream may be silent before the
	// proxy injects a comment line. Zero uses the default; negative disables.
	SSEKeepalive time.Duration `yaml:"sse_keepalive"`
}

// Load reads and validates the config at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse parses and validates a YAML config.
func Parse(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c.setDefaults()
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &c, nil
}

func (c *Config) setDefaults() {
	c.PublicURL = strings.TrimRight(c.PublicURL, "/")
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8000"
	}
	if c.DB == "" {
		c.DB = "/var/lib/mcp-exe-dev-proxy/state.db"
	}
	if c.AccessTokenTTL == 0 {
		c.AccessTokenTTL = time.Hour
	}
	if c.RefreshTokenTTL == 0 {
		c.RefreshTokenTTL = 30 * 24 * time.Hour
	}
	if len(c.AllowedRedirectURIs) == 0 {
		c.AllowedRedirectURIs = DefaultRedirectURIs
	}
	if c.RateLimit == 0 {
		c.RateLimit = 1
	}
	if c.RateBurst == 0 {
		c.RateBurst = 30
	}
	if c.SSEKeepalive == 0 {
		c.SSEKeepalive = 25 * time.Second
	}
}

func (c *Config) validate() error {
	u, err := url.Parse(c.PublicURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("public_url must be an absolute http(s) URL, got %q", c.PublicURL)
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("public_url must not have a path, query or fragment")
	}
	u, err = url.Parse(c.Upstream)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("upstream must be an absolute http(s) URL, got %q", c.Upstream)
	}
	if len(c.AllowedUsers) == 0 && c.AuthorizedKeys == "" {
		return errors.New("neither allowed_users nor authorized_keys is set; nobody could log in")
	}
	if c.AccessTokenTTL < 0 || c.RefreshTokenTTL < 0 {
		return errors.New("token TTLs must be positive")
	}
	return nil
}
