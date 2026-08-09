// Package httpsse proxies MCP traffic over HTTP with Server-Sent Events.
//
// The awkward part is that SSE is a long-lived server-to-client stream, so
// responses arrive asynchronously and each frame has to be routed through the
// interceptor individually. That framing logic is the highest-risk code in the
// package and carries the most test coverage.
package httpsse

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/JohnnyDoer/mcpguard/internal/protocol"
	"github.com/JohnnyDoer/mcpguard/internal/transport/stdio"
)

// Config holds the options for the HTTP/SSE proxy.
type Config struct {
	// Upstream is the real MCP server's base URL.
	Upstream string
	// Listen is the address to bind, used by Run. Handler ignores it.
	Listen string
	// Interceptor is the same interface stdio uses, so enforcement logic is
	// shared rather than reimplemented.
	Interceptor stdio.Interceptor
	// Client may be nil, in which case a client with sane timeouts is used. The
	// read timeout must be zero or SSE streams are cut off mid-session.
	Client *http.Client
}

func (c Config) validate() (*url.URL, error) {
	if c.Upstream == "" {
		return nil, errors.New("httpsse: Upstream is required")
	}
	if c.Interceptor == nil {
		return nil, errors.New("httpsse: Interceptor is required")
	}
	u, err := url.Parse(c.Upstream)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("httpsse: Upstream %q is not a valid URL", c.Upstream)
	}
	return u, nil
}

type proxy struct {
	upstream    *url.URL
	interceptor stdio.Interceptor
	client      *http.Client
}

// Handler returns the reverse proxy handler.
func Handler(cfg Config) (http.Handler, error) {
	upstream, err := cfg.validate()
	if err != nil {
		return nil, err
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{
			// No overall timeout: an SSE stream is meant to stay open. Bounding
			// only the handshake avoids cutting live streams while still failing
			// fast on an unreachable server.
			Transport: &http.Transport{
				ResponseHeaderTimeout: 30 * time.Second,
			},
		}
	}
	return &proxy{upstream: upstream, interceptor: cfg.Interceptor, client: client}, nil
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		p.serveStream(w, r)
		return
	}
	p.servePost(w, r)
}

// servePost handles a single request/response exchange.
func (p *proxy) servePost(w http.ResponseWriter, r *http.Request) {
	// Bound the body with the same limit the stdio codec uses, so both transports
	// behave identically against a hostile peer.
	body, err := io.ReadAll(io.LimitReader(r.Body, protocol.MaxMessageBytes+1))
	if err != nil {
		http.Error(w, "cannot read body", http.StatusBadRequest)
		return
	}
	if len(body) > protocol.MaxMessageBytes {
		http.Error(w, "message too large", http.StatusRequestEntityTooLarge)
		return
	}

	var m protocol.Message
	if err := json.Unmarshal(body, &m); err != nil {
		http.Error(w, "malformed JSON-RPC message", http.StatusBadRequest)
		return
	}

	forward, reply := p.interceptor.Inbound(r.Context(), &m)
	if reply != nil {
		// HTTP 200 with a JSON-RPC error: the transport succeeded and the call
		// was refused. A 4xx would make well-behaved clients treat it as a
		// connection problem and retry.
		writeMessage(w, http.StatusOK, reply)
		return
	}
	if !forward {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	upstreamResp, err := p.forward(r.Context(), r, body)
	if err != nil {
		writeMessage(w, http.StatusOK, protocol.ErrorResponse(m.ID,
			protocol.CodeInternalError, "upstream unreachable", struct {
				Reason string `json:"reason"`
			}{Reason: err.Error()}))
		return
	}
	defer func() { _ = upstreamResp.Body.Close() }()

	// Use +1 so a response exactly at the limit is not silently truncated —
	// the same sentinel the inbound path uses (line 91).
	respBody, err := io.ReadAll(io.LimitReader(upstreamResp.Body, protocol.MaxMessageBytes+1))
	if err != nil {
		writeMessage(w, http.StatusOK, protocol.ErrorResponse(m.ID,
			protocol.CodeInternalError, "cannot read upstream response", nil))
		return
	}
	if len(respBody) > protocol.MaxMessageBytes {
		writeMessage(w, http.StatusOK, protocol.ErrorResponse(m.ID,
			protocol.CodeInternalError, "upstream response too large", nil))
		return
	}

	var out protocol.Message
	if err := json.Unmarshal(respBody, &out); err != nil {
		// Not a JSON-RPC message, so there is nothing to filter. Pass the bytes
		// through rather than guessing.
		w.Header().Set("Content-Type", upstreamResp.Header.Get("Content-Type"))
		w.WriteHeader(upstreamResp.StatusCode)
		_, _ = w.Write(respBody)
		return
	}

	filtered := p.interceptor.Outbound(&out)
	if filtered == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeMessage(w, upstreamResp.StatusCode, filtered)
}

// serveStream proxies an SSE stream, routing each frame through Outbound.
func (p *proxy) serveStream(w http.ResponseWriter, r *http.Request) {
	upstreamResp, err := p.forward(r.Context(), r, nil)
	if err != nil {
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	defer func() { _ = upstreamResp.Body.Close() }()

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	dec := protocol.NewDecoder(newSSEFrames(upstreamResp.Body))
	for {
		m, err := dec.Decode()
		if err != nil {
			return
		}
		out := p.interceptor.Outbound(m)
		if out == nil {
			continue
		}
		encoded, err := json.Marshal(out)
		if err != nil {
			continue
		}
		if _, err := io.WriteString(w, "data: "+string(encoded)+"\n\n"); err != nil {
			return
		}
		flusher.Flush()
	}
}

func (p *proxy) forward(ctx context.Context, r *http.Request, body []byte) (*http.Response, error) {
	target := *p.upstream
	target.Path = strings.TrimSuffix(target.Path, "/") + r.URL.Path
	target.RawQuery = r.URL.RawQuery

	var reader io.Reader
	if body != nil {
		reader = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, target.String(), reader)
	if err != nil {
		return nil, err
	}
	for name, values := range r.Header {
		// Hop-by-hop headers must not be forwarded.
		switch strings.ToLower(name) {
		case "connection", "keep-alive", "transfer-encoding", "upgrade", "host":
			continue
		}
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	return p.client.Do(req) //nolint:gosec // upstream URL is validated in Config.validate; SSRF is intentional by design
}

func writeMessage(w http.ResponseWriter, status int, m *protocol.Message) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(m)
}

// sseFrames adapts an SSE byte stream to the line-delimited JSON the protocol
// decoder expects, by stripping "data: " prefixes and blank separator lines.
//
// The previous chunk-based approach had two bugs. First, returning (0, nil) for
// keep-alive lines caused bufio.Scanner to reach maxConsecutiveEmptyReads=100
// and return io.ErrNoProgress, silently breaking the stream. Second, reading raw
// 32 KiB chunks meant a data: line larger than a chunk (or spanning two chunks)
// was silently truncated, corrupting the JSON fed to protocol.NewDecoder.
//
// Using bufio.Scanner here fixes both: each Scan() call returns one complete
// line regardless of how the transport delivers the bytes, and non-data lines
// are skipped with a continue rather than surfaced as empty reads.
type sseFrames struct {
	scanner *bufio.Scanner
	buf     []byte
	pos     int
}

func newSSEFrames(r io.Reader) *sseFrames {
	sc := bufio.NewScanner(r)
	// MCP tool results can be large. Allow up to 4 MiB per line so a single
	// large response does not break the stream.
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	return &sseFrames{scanner: sc}
}

func (s *sseFrames) Read(p []byte) (int, error) {
	for s.pos >= len(s.buf) {
		if !s.scanner.Scan() {
			if err := s.scanner.Err(); err != nil {
				return 0, err
			}
			return 0, io.EOF
		}
		line := strings.TrimSpace(s.scanner.Text())
		after, found := strings.CutPrefix(line, "data:")
		if !found || strings.TrimSpace(after) == "" {
			// keep-alive, comment, or blank separator — loop to the next line
			// rather than returning (0, nil), which would trigger ErrNoProgress.
			continue
		}
		s.buf = append([]byte(strings.TrimSpace(after)), '\n')
		s.pos = 0
	}
	n := copy(p, s.buf[s.pos:])
	s.pos += n
	return n, nil
}

// Run serves the proxy until ctx is cancelled.
func Run(ctx context.Context, cfg Config) error {
	handler, err := Handler(cfg)
	if err != nil {
		return err
	}
	if cfg.Listen == "" {
		return errors.New("httpsse: Listen is required")
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
