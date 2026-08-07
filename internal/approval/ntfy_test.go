package approval

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JohnnyDoer/mcpguard/internal/policy"
)

func TestBrokerPublishesAndWaits(t *testing.T) {
	var published string
	ntfy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		published = string(body) + "|" + req.Header.Get("Actions")
		w.WriteHeader(http.StatusOK)
	}))
	defer ntfy.Close()

	b, err := NewBroker(policy.ApprovalConfig{
		Channel: "ntfy", URL: ntfy.URL, Topic: "mcpguard",
		Timeout: 2 * time.Second, OnTimeout: policy.ActionDeny,
	}, "http://127.0.0.1:8901")
	if err != nil {
		t.Fatal(err)
	}

	// Approve out of band shortly after the call blocks.
	go func() {
		time.Sleep(50 * time.Millisecond)
		for _, nonce := range b.registry.nonces() {
			_ = b.registry.Resolve(nonce, true)
		}
	}()

	approved, err := b.Approve(context.Background(), sampleEvent())
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if !approved {
		t.Error("expected approval")
	}
	for _, want := range []string{"write_file", "Approve", "Deny", "127.0.0.1:8901"} {
		if !strings.Contains(published, want) {
			t.Errorf("notification missing %q:\n%s", want, published)
		}
	}
}

func TestBrokerDeniesOnTimeout(t *testing.T) {
	ntfy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ntfy.Close()

	b, _ := NewBroker(policy.ApprovalConfig{
		Channel: "ntfy", URL: ntfy.URL, Topic: "t",
		Timeout: 50 * time.Millisecond, OnTimeout: policy.ActionDeny,
	}, "http://127.0.0.1:8901")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	approved, _ := b.Approve(ctx, sampleEvent())
	if approved {
		t.Error("an unanswered approval must deny")
	}
	if b.registry.Pending() != 0 {
		t.Errorf("Pending() = %d after timeout; the entry leaked", b.registry.Pending())
	}
}

func TestBrokerDeniesWhenNtfyUnreachable(t *testing.T) {
	// Cannot reach a human, therefore cannot have approval.
	b, _ := NewBroker(policy.ApprovalConfig{
		Channel: "ntfy", URL: "http://127.0.0.1:1", Topic: "t",
		Timeout: time.Second, OnTimeout: policy.ActionDeny,
	}, "http://127.0.0.1:8901")

	approved, err := b.Approve(context.Background(), sampleEvent())
	if err == nil {
		t.Error("an unreachable notification channel must surface an error")
	}
	if approved {
		t.Error("must not approve when the notification could not be sent")
	}
}

func TestNewBrokerRejectsUnsupportedChannel(t *testing.T) {
	if _, err := NewBroker(policy.ApprovalConfig{Channel: "carrier-pigeon", URL: "http://x",
		Topic: "t"}, "http://127.0.0.1:1"); err == nil {
		t.Error("an unsupported channel must be rejected at startup")
	}
}
