package config

import (
	"testing"
	"time"
)

func TestExampleConfig(t *testing.T) {
	c, err := Load("../../deploy/config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessTokenTTL != time.Hour || c.RefreshTokenTTL != 720*time.Hour {
		t.Errorf("TTLs = %v, %v", c.AccessTokenTTL, c.RefreshTokenTTL)
	}
	if c.SSEKeepalive != 25*time.Second || len(c.AllowedRedirectURIs) != 2 {
		t.Errorf("defaults not applied: %+v", c)
	}
}

func TestInvalid(t *testing.T) {
	for name, y := range map[string]string{
		"no public_url":  "upstream: http://127.0.0.1:1\nallowed_users: [a]\n",
		"path in public": "public_url: https://x.exe.xyz/mcp\nupstream: http://127.0.0.1:1\nallowed_users: [a]\n",
		"nobody allowed": "public_url: https://x.exe.xyz\nupstream: http://127.0.0.1:1\n",
		"unknown field":  "public_url: https://x.exe.xyz\nupstream: http://127.0.0.1:1\nallowed_users: [a]\ntypo: 1\n",
	} {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
