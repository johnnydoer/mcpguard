package stdio

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JohnnyDoer/mcpguard/internal/protocol"
)

// buildFakeServer compiles testdata/fakeserver once per test binary run and
// returns its path.
func buildFakeServer(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test that builds a subprocess")
	}
	bin := filepath.Join(t.TempDir(), "fakeserver")
	cmd := exec.CommandContext(context.Background(), "go", "build", "-o", bin, "../../../testdata/fakeserver")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building fakeserver: %v\n%s", err, out)
	}
	return bin
}

// runProxy feeds the given frames through the proxy and returns what the agent
// side received.
func runProxy(t *testing.T, interceptor Interceptor, frames ...string) []*protocol.Message {
	t.Helper()
	bin := buildFakeServer(t)

	var agentOut bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	err := Run(ctx, Config{
		Command:     []string{bin},
		Interceptor: interceptor,
		AgentIn:     strings.NewReader(strings.Join(frames, "\n") + "\n"),
		AgentOut:    &agentOut,
		Stderr:      io.Discard,
	})
	if err != nil && !isCleanShutdown(err) {
		t.Fatalf("Run: %v", err)
	}

	var got []*protocol.Message
	d := protocol.NewDecoder(bytes.NewReader(agentOut.Bytes()))
	for {
		m, err := d.Decode()
		if err != nil {
			break
		}
		got = append(got, m)
	}
	return got
}

func isCleanShutdown(err error) bool {
	return err == nil || strings.Contains(err.Error(), "exit status") ||
		strings.Contains(err.Error(), "file already closed")
}

func TestIntegrationPassthroughForwardsRequestAndResponse(t *testing.T) {
	got := runProxy(t, PassthroughInterceptor{},
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)

	if len(got) != 1 {
		t.Fatalf("agent received %d messages, want 1", len(got))
	}
	if got[0].IDKey() != "1" {
		t.Errorf("response id = %q, want 1", got[0].IDKey())
	}
	var result protocol.ToolsListResult
	if err := json.Unmarshal(got[0].Result, &result); err != nil {
		t.Fatalf("result is not a tools/list result: %v", err)
	}
	if len(result.Tools) != 3 {
		t.Errorf("passthrough returned %d tools, want all 3 unfiltered", len(result.Tools))
	}
}

func TestIntegrationPassthroughPreservesArgumentsExactly(t *testing.T) {
	// The fakeserver echoes its arguments. If the proxy re-marshals params, the
	// echo differs and this catches it.
	got := runProxy(t, PassthroughInterceptor{},
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/srv/a","depth":2}}}`)

	if len(got) != 1 {
		t.Fatalf("got %d messages, want 1", len(got))
	}
	if !bytes.Contains(got[0].Result, []byte(`\"path\":\"/srv/a\"`)) {
		t.Errorf("arguments were altered in transit: %s", got[0].Result)
	}
}

func TestIntegrationPreservesRequestOrdering(t *testing.T) {
	got := runProxy(t, PassthroughInterceptor{},
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":2,"method":"resources/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)

	if len(got) != 3 {
		t.Fatalf("got %d responses, want 3", len(got))
	}
	for i, want := range []string{"1", "2", "3"} {
		if got[i].IDKey() != want {
			t.Errorf("response %d has id %q, want %q", i, got[i].IDKey(), want)
		}
	}
}

func TestIntegrationNotificationsAreForwardedWithoutResponse(t *testing.T) {
	got := runProxy(t, PassthroughInterceptor{},
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)

	if len(got) != 1 {
		t.Fatalf("got %d messages, want 1 — a notification must not produce a response", len(got))
	}
}

func TestIntegrationLargeResponseSurvivesFraming(t *testing.T) {
	got := runProxy(t, PassthroughInterceptor{},
		`{"jsonrpc":"2.0","id":1,"method":"bigresult"}`)

	if len(got) != 1 {
		t.Fatalf("got %d messages, want 1", len(got))
	}
	if len(got[0].Result) < 200*1024 {
		t.Errorf("result is %d bytes, want >200KiB — framing truncated it", len(got[0].Result))
	}
}

func TestIntegrationChildCrashDoesNotHangTheAgent(t *testing.T) {
	// AgentIn must never reach EOF on its own here: a finite reader would let
	// the agent->server pump unwind by itself once exhausted, passing this
	// test regardless of whether the crash was ever noticed. An io.Pipe whose
	// write side is held open — no further writes, never closed — blocks any
	// read indefinitely, so the only way Run can return is through the
	// cancellation path the server->agent goroutine triggers when it notices
	// the child died. If the supervisor does not notice, Run hangs forever
	// and the test's own timeout is the failure, not an assertion.
	bin := buildFakeServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	agentInR, agentInW := io.Pipe()
	t.Cleanup(func() { _ = agentInW.Close() })

	var agentOut bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{
			Command:     []string{bin},
			Interceptor: PassthroughInterceptor{},
			AgentIn:     agentInR,
			AgentOut:    &agentOut,
			Stderr:      io.Discard,
		})
	}()

	if _, err := agentInW.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"crash"}` + "\n")); err != nil {
		t.Fatalf("writing crash trigger: %v", err)
	}

	select {
	case <-done:
		// Returned rather than hanging. Whether the error is nil or an exit
		// status does not matter; not blocking forever does.
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the child crashed")
	}
}

func TestIntegrationAgentEOFShutsDownCleanly(t *testing.T) {
	bin := buildFakeServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	start := time.Now()
	var agentOut bytes.Buffer
	_ = Run(ctx, Config{
		Command:     []string{bin},
		Interceptor: PassthroughInterceptor{},
		AgentIn:     strings.NewReader(""), // immediate EOF
		AgentOut:    &agentOut,
		Stderr:      io.Discard,
	})

	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("shutdown took %v; the child should be terminated promptly on agent EOF", elapsed)
	}
}

func TestRunRejectsEmptyCommand(t *testing.T) {
	err := Run(context.Background(), Config{
		Command:     nil,
		Interceptor: PassthroughInterceptor{},
		AgentIn:     strings.NewReader(""),
		AgentOut:    io.Discard,
	})
	if err == nil {
		t.Fatal("expected an error when Command is empty")
	}
}

func TestRunRejectsNilInterceptor(t *testing.T) {
	// A nil interceptor would panic mid-session. Failing at startup is the only
	// acceptable behaviour for a security proxy.
	err := Run(context.Background(), Config{
		Command:     []string{"/bin/true"},
		Interceptor: nil,
		AgentIn:     strings.NewReader(""),
		AgentOut:    io.Discard,
	})
	if err == nil {
		t.Fatal("expected an error when Interceptor is nil")
	}
}

func TestPassthroughInterceptorForwardsEverything(t *testing.T) {
	i := PassthroughInterceptor{}
	m := &protocol.Message{Method: protocol.MethodToolsCall}

	forward, reply := i.Inbound(context.Background(), m)
	if !forward || reply != nil {
		t.Errorf("Inbound = (%v, %v), want (true, nil)", forward, reply)
	}
	if out := i.Outbound(m); out != m {
		t.Error("Outbound should return the message unchanged")
	}
}
