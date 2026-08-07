package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/JohnnyDoer/mcpguard/internal/enforce"
	"github.com/JohnnyDoer/mcpguard/internal/policy"
)

func record(t *testing.T, cfg policy.AuditConfig, ev enforce.Event) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	lg, err := New(cfg, "abcd1234", &buf)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := lg.Record(ev); err != nil {
		t.Fatalf("Record: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &got); err != nil {
		t.Fatalf("output is not a single JSON object: %v\n%s", err, buf.String())
	}
	return got
}

func sampleEvent() enforce.Event {
	return enforce.Event{
		Server: "fs", Method: "tools/call", Tool: "read_file",
		Args:    map[string]any{"path": "/srv/public/a"},
		Mode:    policy.ModeEnforce,
		Latency: 2 * time.Millisecond,
		Decision: policy.Decision{
			Action: policy.ActionAllow, Rule: "allow-public", Reason: "matched path",
		},
	}
}

func TestRecordWritesExpectedFields(t *testing.T) {
	got := record(t, policy.AuditConfig{OnError: policy.OnErrorDeny}, sampleEvent())

	for _, field := range []string{
		"ts", "session_id", "server", "method", "tool", "args", "args_hash",
		"decision", "rule", "mode", "latency_ms",
	} {
		if _, ok := got[field]; !ok {
			t.Errorf("missing field %q in %v", field, got)
		}
	}
	if got["decision"] != "allow" || got["rule"] != "allow-public" {
		t.Errorf("decision/rule = %v/%v", got["decision"], got["rule"])
	}
	if got["session_id"] != "abcd1234" {
		t.Errorf("session_id = %v", got["session_id"])
	}
}

func TestRecordIsOneLinePerEvent(t *testing.T) {
	var buf bytes.Buffer
	lg, err := New(policy.AuditConfig{OnError: policy.OnErrorDeny}, "s", &buf)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := lg.Record(sampleEvent()); err != nil {
			t.Fatal(err)
		}
	}
	if lines := strings.Count(strings.TrimSpace(buf.String()), "\n"); lines != 2 {
		t.Errorf("got %d newlines for 3 records, want 2 (JSON lines format)", lines)
	}
}

func TestRedactionReplacesValueButKeepsKey(t *testing.T) {
	// Keeping the key proves the argument was present without disclosing it.
	ev := sampleEvent()
	ev.Args = map[string]any{"path": "/srv/a", "token": "super-secret-value"}

	got := record(t, policy.AuditConfig{
		OnError: policy.OnErrorDeny, Redact: []string{"args.token"},
	}, ev)

	args := got["args"].(map[string]any)
	if args["token"] == "super-secret-value" {
		t.Error("token was not redacted")
	}
	if args["token"] != redactedPlaceholder {
		t.Errorf("token = %v, want %q", args["token"], redactedPlaceholder)
	}
	if args["path"] != "/srv/a" {
		t.Errorf("path should be untouched, got %v", args["path"])
	}
}

func TestRedactionSupportsWildcardPaths(t *testing.T) {
	ev := sampleEvent()
	ev.Args = map[string]any{
		"outer": map[string]any{"secret": "hide-me", "public": "keep-me"},
	}
	got := record(t, policy.AuditConfig{
		OnError: policy.OnErrorDeny, Redact: []string{"args.*.secret"},
	}, ev)

	outer := got["args"].(map[string]any)["outer"].(map[string]any)
	if outer["secret"] != redactedPlaceholder {
		t.Errorf("nested secret = %v, want redacted", outer["secret"])
	}
	if outer["public"] != "keep-me" {
		t.Errorf("nested public = %v, want untouched", outer["public"])
	}
}

func TestArgsHashCoversUnredactedValues(t *testing.T) {
	// The hash exists so repeated calls can be correlated without storing the
	// sensitive value. Hashing the redacted form would make every redacted call
	// hash identically and destroy that property.
	base := sampleEvent()
	base.Args = map[string]any{"token": "value-one"}
	other := sampleEvent()
	other.Args = map[string]any{"token": "value-two"}

	cfg := policy.AuditConfig{OnError: policy.OnErrorDeny, Redact: []string{"args.token"}}
	a := record(t, cfg, base)
	b := record(t, cfg, other)

	if a["args_hash"] == b["args_hash"] {
		t.Error("different secret values must produce different hashes")
	}
	if !strings.HasPrefix(a["args_hash"].(string), "sha256:") {
		t.Errorf("args_hash = %v, want a sha256: prefix", a["args_hash"])
	}
}

func TestArgsHashIsStableAcrossKeyOrder(t *testing.T) {
	// Go map iteration order is random, so the hash must be computed over a
	// canonical form or it would differ between runs for identical calls.
	ev1 := sampleEvent()
	ev1.Args = map[string]any{"a": "1", "b": "2"}
	ev2 := sampleEvent()
	ev2.Args = map[string]any{"b": "2", "a": "1"}

	cfg := policy.AuditConfig{OnError: policy.OnErrorDeny}
	if record(t, cfg, ev1)["args_hash"] != record(t, cfg, ev2)["args_hash"] {
		t.Error("args_hash must not depend on map iteration order")
	}
}

func TestRecordDoesNotMutateTheEventArgs(t *testing.T) {
	// Redaction must not corrupt the arguments, because the same Event is used
	// for metrics and, in Task 20, for the approval prompt.
	ev := sampleEvent()
	ev.Args = map[string]any{"token": "original"}
	record(t, policy.AuditConfig{OnError: policy.OnErrorDeny,
		Redact: []string{"args.token"}}, ev)

	if ev.Args["token"] != "original" {
		t.Errorf("Record mutated the caller's args: %v", ev.Args)
	}
}

func TestOpenRefusesUnwritablePath(t *testing.T) {
	// Startup with an unwritable log path always fails, regardless of on_error.
	// on_error governs runtime failures only.
	_, err := Open(policy.AuditConfig{
		Path: "/nonexistent-directory-xyz/audit.jsonl", OnError: policy.OnErrorContinue,
	}, "s")
	if err == nil {
		t.Fatal("Open must fail when the log path cannot be written")
	}
}

func TestOpenWithEmptyPathWritesToStderrSink(t *testing.T) {
	lg, err := Open(policy.AuditConfig{OnError: policy.OnErrorDeny}, "s")
	if err != nil {
		t.Fatalf("an empty path should fall back to a stderr sink, got %v", err)
	}
	t.Cleanup(func() { _ = lg.Close() })
	if err := lg.Record(sampleEvent()); err != nil {
		t.Errorf("Record: %v", err)
	}
}

func TestNewSessionIDIsEightHexChars(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := NewSessionID()
		if len(id) != 8 {
			t.Fatalf("NewSessionID() = %q, want 8 characters", id)
		}
		if strings.Trim(id, "0123456789abcdef") != "" {
			t.Fatalf("NewSessionID() = %q, want lowercase hex", id)
		}
		seen[id] = true
	}
	if len(seen) < 90 {
		t.Errorf("only %d unique ids in 100 draws; entropy looks wrong", len(seen))
	}
}
