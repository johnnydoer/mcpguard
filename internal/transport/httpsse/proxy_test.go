package httpsse

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JohnnyDoer/mcpguard/internal/protocol"
	"github.com/JohnnyDoer/mcpguard/internal/transport/stdio"
)

// denyDeletes forwards everything except tools/call for delete_file.
type denyDeletes struct{}

func (denyDeletes) Inbound(m *protocol.Message) (bool, *protocol.Message) {
	if m.Method != protocol.MethodToolsCall {
		return true, nil
	}
	p, err := protocol.ParseToolsCall(m)
	if err != nil || p.Name == "delete_file" {
		return false, protocol.DenyResponse(m.ID, "deny-deletes", "not permitted")
	}
	return true, nil
}

func (denyDeletes) Outbound(m *protocol.Message) *protocol.Message { return m }

// upstream returns a test server that answers any request with a fixed result.
func upstream(t *testing.T, seen *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		*seen = append(*seen, string(body))

		var m protocol.Message
		_ = json.Unmarshal(body, &m)
		resp := &protocol.Message{JSONRPC: protocol.Version, ID: m.ID,
			Result: json.RawMessage(`{"ok":true}`)}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func post(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestForwardsAllowedCall(t *testing.T) {
	var seen []string
	up := upstream(t, &seen)
	defer up.Close()

	h, err := Handler(Config{Upstream: up.URL, Interceptor: denyDeletes{}})
	if err != nil {
		t.Fatal(err)
	}
	rec := post(t, h, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if len(seen) != 1 {
		t.Errorf("upstream saw %d requests, want 1", len(seen))
	}
}

func TestDeniedCallNeverReachesUpstream(t *testing.T) {
	var seen []string
	up := upstream(t, &seen)
	defer up.Close()

	h, err := Handler(Config{Upstream: up.URL, Interceptor: denyDeletes{}})
	if err != nil {
		t.Fatal(err)
	}
	rec := post(t, h, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_file","arguments":{}}}`)

	if len(seen) != 0 {
		t.Errorf("upstream saw %d requests; a denied call must not be forwarded", len(seen))
	}

	var got protocol.Message
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not a JSON-RPC message: %v", err)
	}
	if got.Error == nil || got.Error.Code != protocol.CodePolicyDenied {
		t.Errorf("response = %+v, want a policy denial", got)
	}
	if got.IDKey() != "2" {
		t.Errorf("id = %q, want 2", got.IDKey())
	}
	// HTTP 200 with a JSON-RPC error is correct: the transport succeeded, the
	// call was refused. A 403 would make well-behaved clients treat it as a
	// connection problem and retry.
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 with a JSON-RPC error body", rec.Code)
	}
}

func TestRejectsMalformedBody(t *testing.T) {
	var seen []string
	up := upstream(t, &seen)
	defer up.Close()

	h, _ := Handler(Config{Upstream: up.URL, Interceptor: denyDeletes{}})
	rec := post(t, h, `{not json}`)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if len(seen) != 0 {
		t.Error("an unparseable body must not be forwarded")
	}
}

func TestRejectsOversizedBody(t *testing.T) {
	var seen []string
	up := upstream(t, &seen)
	defer up.Close()

	h, _ := Handler(Config{Upstream: up.URL, Interceptor: denyDeletes{}})
	rec := post(t, h, strings.Repeat("x", protocol.MaxMessageBytes+1))

	if rec.Code != http.StatusRequestEntityTooLarge && rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 413 or 400", rec.Code)
	}
	if len(seen) != 0 {
		t.Error("an oversized body must not be forwarded")
	}
}

func TestFiltersSSEStream(t *testing.T) {
	// The hard part of this transport. Responses arrive asynchronously on a
	// long-lived stream and have to be routed through Outbound individually.
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("test server does not support flushing")
		}
		for _, frame := range []string{
			`{"jsonrpc":"2.0","id":1,"result":{"first":true}}`,
			`{"jsonrpc":"2.0","id":2,"result":{"second":true}}`,
		} {
			_, _ = io.WriteString(w, "data: "+frame+"\n\n")
			flusher.Flush()
		}
	}))
	defer up.Close()

	h, _ := Handler(Config{Upstream: up.URL, Interceptor: stdio.PassthroughInterceptor{}})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/event-stream")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	for _, want := range []string{"first", "second"} {
		if !strings.Contains(body, want) {
			t.Errorf("SSE body missing %q:\n%s", want, body)
		}
	}
	if strings.Count(body, "data: ") != 2 {
		t.Errorf("expected 2 SSE frames, got:\n%s", body)
	}
}

func TestHandlerRejectsBadConfig(t *testing.T) {
	if _, err := Handler(Config{Interceptor: denyDeletes{}}); err == nil {
		t.Error("Upstream is required")
	}
	if _, err := Handler(Config{Upstream: "http://x"}); err == nil {
		t.Error("Interceptor is required")
	}
	if _, err := Handler(Config{Upstream: "not a url", Interceptor: denyDeletes{}}); err == nil {
		t.Error("Upstream must be a valid URL")
	}
}
