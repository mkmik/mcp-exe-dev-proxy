// Package identity abstracts where interactive users are authenticated.
// Only exe.dev is implemented.
package identity

import (
	"net/http"
	"net/url"
)

// User is an authenticated interactive user.
type User struct {
	// ID is a stable, unique identifier.
	ID string
	// Email is the user's email address, if known.
	Email string
}

// Name is the identity shown to the upstream.
func (u *User) Name() string {
	if u.Email != "" {
		return u.Email
	}
	return u.ID
}

// Provider identifies the user behind a browser request.
type Provider interface {
	// User returns the logged-in user, or nil if the request carries no
	// login.
	User(r *http.Request) *User
	// LoginURL is where to send the browser to log in and then come back
	// to returnTo (a path on this host).
	LoginURL(returnTo string) string
	// StripHeaders removes any identity headers from a request before it
	// is forwarded upstream.
	StripHeaders(h http.Header)
}

// exe.dev's HTTPS front adds these headers when the browser has an exe.dev
// login cookie for the VM's domain. They are set (and client-supplied ones
// removed) by the front, so they can be trusted as long as the proxy is only
// reachable through it.
const (
	ExeDevUserIDHeader = "X-ExeDev-UserID"
	ExeDevEmailHeader  = "X-ExeDev-Email"
	exeDevLoginPath    = "/__exe.dev/login"
)

// ExeDev authenticates users with exe.dev's built-in login.
type ExeDev struct{}

func (ExeDev) User(r *http.Request) *User {
	id := r.Header.Get(ExeDevUserIDHeader)
	if id == "" {
		return nil
	}
	return &User{ID: id, Email: r.Header.Get(ExeDevEmailHeader)}
}

func (ExeDev) LoginURL(returnTo string) string {
	return exeDevLoginPath + "?redirect=" + url.QueryEscape(returnTo)
}

func (ExeDev) StripHeaders(h http.Header) {
	h.Del(ExeDevUserIDHeader)
	h.Del(ExeDevEmailHeader)
}
