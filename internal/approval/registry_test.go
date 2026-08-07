package approval

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JohnnyDoer/mcpguard/internal/enforce"
)

func sampleEvent() enforce.Event {
	return enforce.Event{Server: "fs", Method: "tools/call", Tool: "write_file",
		Args: map[string]any{"path": "/srv/a", "content": "x"}}
}

func TestCallHashIsStableAndSpecific(t *testing.T) {
	a, err := CallHash(sampleEvent())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := CallHash(sampleEvent())
	if a != b {
		t.Error("identical calls must hash identically")
	}

	other := sampleEvent()
	other.Args = map[string]any{"path": "/srv/b", "content": "x"}
	c, _ := CallHash(other)
	if a == c {
		t.Error("different arguments must hash differently")
	}
}

func TestResolveApprovesTheWaiter(t *testing.T) {
	r := NewRegistry()
	nonce, wait, err := r.Register(sampleEvent())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Resolve(nonce, true); err != nil {
		t.Fatal(err)
	}
	select {
	case approved := <-wait:
		if !approved {
			t.Error("waiter should have received true")
		}
	case <-time.After(time.Second):
		t.Fatal("waiter was never signalled")
	}
}

func TestNonceIsSingleUse(t *testing.T) {
	// A replayable nonce would let one approval authorize repeated calls.
	r := NewRegistry()
	nonce, _, _ := r.Register(sampleEvent())
	if err := r.Resolve(nonce, true); err != nil {
		t.Fatal(err)
	}
	if err := r.Resolve(nonce, true); err == nil {
		t.Error("a nonce must not be usable twice")
	}
}

func TestResolveUnknownNonceFails(t *testing.T) {
	if err := NewRegistry().Resolve("does-not-exist", true); err == nil {
		t.Error("an unknown nonce must be rejected")
	}
}

func TestRegisterBindsToTheCallHash(t *testing.T) {
	// The TOCTOU guard. Two different calls must get different nonces, so an
	// approval issued for one cannot be consumed by the other.
	r := NewRegistry()
	n1, _, _ := r.Register(sampleEvent())

	other := sampleEvent()
	other.Args = map[string]any{"path": "/etc/shadow"}
	n2, _, _ := r.Register(other)

	if n1 == n2 {
		t.Error("distinct calls must produce distinct nonces")
	}
}

func TestPendingIsCleanedUpOnResolve(t *testing.T) {
	r := NewRegistry()
	nonce, _, _ := r.Register(sampleEvent())
	if r.Pending() != 1 {
		t.Fatalf("Pending() = %d, want 1", r.Pending())
	}
	_ = r.Resolve(nonce, true)
	if r.Pending() != 0 {
		t.Errorf("Pending() = %d after resolve, want 0", r.Pending())
	}
}

func TestHandlerApprovesViaHTTP(t *testing.T) {
	r := NewRegistry()
	nonce, wait, _ := r.Register(sampleEvent())

	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/approve/" + nonce) //nolint:noctx
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	select {
	case approved := <-wait:
		if !approved {
			t.Error("expected approval")
		}
	case <-time.After(time.Second):
		t.Fatal("waiter was never signalled")
	}
}

func TestHandlerDeniesViaHTTP(t *testing.T) {
	r := NewRegistry()
	nonce, wait, _ := r.Register(sampleEvent())
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	resp, _ := http.Get(srv.URL + "/deny/" + nonce) //nolint:noctx
	_ = resp.Body.Close()

	select {
	case approved := <-wait:
		if approved {
			t.Error("expected denial")
		}
	case <-time.After(time.Second):
		t.Fatal("waiter was never signalled")
	}
}

func TestHandlerRejectsUnknownNonceWithoutLeakingWhether(t *testing.T) {
	// A distinguishable response would let an attacker enumerate valid nonces.
	r := NewRegistry()
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	resp, _ := http.Get(srv.URL + "/approve/bogus") //nolint:noctx
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Error("an unknown nonce must not return 200")
	}
}

func TestHandlerRejectsUnknownPath(t *testing.T) {
	r := NewRegistry()
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	resp, _ := http.Get(srv.URL + "/something-else/x") //nolint:noctx
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Error("an unrecognised path must not return 200")
	}
}
