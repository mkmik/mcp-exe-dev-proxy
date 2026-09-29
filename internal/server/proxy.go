package server

import (
	"bytes"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"
)

func (s *Server) newProxy() http.Handler {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Never let the transport add gzip on its own: it would buffer event
	// streams behind a decompressor.
	transport.DisableCompression = true
	return &httputil.ReverseProxy{
		Rewrite:        s.rewrite,
		Transport:      transport,
		FlushInterval:  -1, // flush after every write
		ModifyResponse: s.modifyResponse,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if r.Context().Err() == nil {
				s.log.Error("upstream", "method", r.Method, "path", r.URL.Path, "err", err)
			}
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
}

// rewrite prepares the outbound request. ReverseProxy has already removed
// hop-by-hop and X-Forwarded-* headers from the copy it passes in.
func (s *Server) rewrite(pr *httputil.ProxyRequest) {
	pr.SetURL(s.upstream)
	h := pr.Out.Header

	// The upstream never sees client credentials or spoofable identity.
	h.Del("Authorization")
	h.Del("X-Forwarded-User")
	s.id.StripHeaders(h)

	if id, ok := requestIdentity(pr.In.Context()); ok {
		h.Set("X-Forwarded-User", id.Name)
	}
	h.Set("X-Forwarded-Proto", s.public.Scheme)
	h.Set("X-Forwarded-Host", s.public.Host)
	xff := pr.In.Header.Values("X-Forwarded-For")
	if ip, _, err := net.SplitHostPort(pr.In.RemoteAddr); err == nil {
		xff = append(xff, ip)
	}
	if len(xff) > 0 {
		h.Set("X-Forwarded-For", strings.Join(xff, ", "))
	}

	// Ask for an uncompressed event stream so every event can be flushed
	// as soon as it arrives.
	if strings.Contains(pr.In.Header.Get("Accept"), "text/event-stream") {
		h.Del("Accept-Encoding")
	}
}

func (s *Server) modifyResponse(resp *http.Response) error {
	if s.cfg.SSEKeepalive <= 0 {
		return nil
	}
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if mt == "text/event-stream" && resp.Header.Get("Content-Encoding") == "" {
		resp.Body = newKeepaliveBody(resp.Body, s.cfg.SSEKeepalive)
	}
	return nil
}

var keepaliveComment = []byte(": keepalive\n\n")

// keepaliveBody wraps an event stream and, when the upstream has been silent
// for interval, yields an SSE comment line so idle-connection cutoffs in
// front proxies do not kill the stream. Comments are only injected between
// events, never in the middle of one.
type keepaliveBody struct {
	src      io.ReadCloser
	interval time.Duration

	chunks chan []byte
	done   chan struct{}
	once   sync.Once

	// Owned by the reader.
	pending []byte
	err     error
	tail    []byte // last few bytes passed through, to find event boundaries
}

func newKeepaliveBody(src io.ReadCloser, interval time.Duration) *keepaliveBody {
	k := &keepaliveBody{
		src:      src,
		interval: interval,
		chunks:   make(chan []byte),
		done:     make(chan struct{}),
	}
	go k.pump()
	return k
}

func (k *keepaliveBody) pump() {
	var errOut error
	defer func() {
		k.err = errOut // published by the close of chunks below
		close(k.chunks)
	}()
	for {
		buf := make([]byte, 32<<10)
		n, err := k.src.Read(buf)
		if n > 0 {
			select {
			case k.chunks <- buf[:n]:
			case <-k.done:
				errOut = io.ErrClosedPipe
				return
			}
		}
		if err != nil {
			errOut = err
			return
		}
	}
}

// atBoundary reports whether the bytes sent so far end an SSE event (or
// nothing has been sent yet).
func (k *keepaliveBody) atBoundary() bool {
	t := k.tail
	return len(t) == 0 ||
		bytes.HasSuffix(t, []byte("\n\n")) ||
		bytes.HasSuffix(t, []byte("\r\r")) ||
		bytes.HasSuffix(t, []byte("\r\n\r\n"))
}

func (k *keepaliveBody) track(b []byte) {
	k.tail = append(k.tail, b...)
	if len(k.tail) > 4 {
		k.tail = append(k.tail[:0], k.tail[len(k.tail)-4:]...)
	}
}

func (k *keepaliveBody) Read(p []byte) (int, error) {
	if len(k.pending) > 0 {
		n := copy(p, k.pending)
		k.pending = k.pending[n:]
		return n, nil
	}
	timer := time.NewTimer(k.interval)
	defer timer.Stop()
	for {
		select {
		case b, ok := <-k.chunks:
			if !ok {
				return 0, k.err
			}
			k.track(b)
			n := copy(p, b)
			k.pending = b[n:]
			return n, nil
		case <-timer.C:
			if !k.atBoundary() {
				timer.Reset(k.interval)
				continue
			}
			n := copy(p, keepaliveComment)
			k.pending = keepaliveComment[n:]
			return n, nil
		}
	}
}

func (k *keepaliveBody) Close() error {
	k.once.Do(func() { close(k.done) })
	return k.src.Close()
}
