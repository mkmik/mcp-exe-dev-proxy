package server

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ipLimiter rate-limits requests per client IP.
type ipLimiter struct {
	limit rate.Limit
	burst int

	mu       sync.Mutex
	limiters map[string]*ipEntry
}

type ipEntry struct {
	lim  *rate.Limiter
	seen time.Time
}

func newIPLimiter(perSecond float64, burst int) *ipLimiter {
	return &ipLimiter{limit: rate.Limit(perSecond), burst: burst, limiters: map[string]*ipEntry{}}
}

func (l *ipLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.limiters[ip]
	if !ok {
		e = &ipEntry{lim: rate.NewLimiter(l.limit, l.burst)}
		l.limiters[ip] = e
	}
	e.seen = now
	return e.lim.AllowN(now, 1)
}

// gc forgets clients that have been idle long enough to have a full bucket.
func (l *ipLimiter) gc(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip, e := range l.limiters {
		if now.Sub(e.seen) > 10*time.Minute {
			delete(l.limiters, ip)
		}
	}
}

func (l *ipLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(clientIP(r), time.Now()) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP returns the address of the client. Behind exe.dev's HTTPS front
// the connection comes from the front, which appends the real client address
// to X-Forwarded-For, so the last entry is used.
func clientIP(r *http.Request) string {
	if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
		parts := strings.Split(xff[len(xff)-1], ",")
		if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
