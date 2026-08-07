package approval

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/JohnnyDoer/mcpguard/internal/enforce"
	"github.com/JohnnyDoer/mcpguard/internal/policy"
)

// Broker publishes approval requests to ntfy and blocks for the answer.
type Broker struct {
	cfg          policy.ApprovalConfig
	callbackBase string
	registry     *Registry
	client       *http.Client
}

// NewBroker builds a broker. callbackBase is the externally reachable base URL
// of the Registry handler, e.g. http://127.0.0.1:8901.
func NewBroker(cfg policy.ApprovalConfig, callbackBase string) (*Broker, error) {
	if cfg.Channel != "ntfy" {
		return nil, fmt.Errorf("approval: unsupported channel %q, want ntfy", cfg.Channel)
	}
	if cfg.URL == "" || cfg.Topic == "" {
		return nil, fmt.Errorf("approval: ntfy needs both url and topic")
	}
	if callbackBase == "" {
		return nil, fmt.Errorf("approval: callback base URL is required")
	}
	return &Broker{
		cfg:          cfg,
		callbackBase: strings.TrimSuffix(callbackBase, "/"),
		registry:     NewRegistry(),
		client:       &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// Registry exposes the registry so run can mount its handler.
func (b *Broker) Registry() *Registry { return b.registry }

// Approve blocks until a human answers, the context expires, or the configured
// timeout elapses.
func (b *Broker) Approve(ctx context.Context, ev enforce.Event) (bool, error) {
	nonce, wait, err := b.registry.Register(ev)
	if err != nil {
		return false, err
	}

	if err := b.publish(ctx, ev, nonce); err != nil {
		// Cannot reach a human, therefore cannot have approval. Cleaning up the
		// entry prevents the registry growing on every failed publish.
		b.registry.Cancel(nonce)
		return false, fmt.Errorf("approval: publish: %w", err)
	}

	timer := time.NewTimer(b.cfg.Timeout)
	defer timer.Stop()

	select {
	case approved := <-wait:
		return approved, nil
	case <-timer.C:
		b.registry.Cancel(nonce)
		// on_timeout is validated at load time to never be allow, so this is
		// always a denial in practice.
		return b.cfg.OnTimeout == policy.ActionAllow, nil
	case <-ctx.Done():
		b.registry.Cancel(nonce)
		return false, ctx.Err()
	}
}

func (b *Broker) publish(ctx context.Context, ev enforce.Event, nonce string) error {
	args, err := json.Marshal(ev.Args)
	if err != nil {
		args = []byte("{}")
	}
	body := fmt.Sprintf("%s wants to call %s on %s\n\narguments: %s\n\nrule: %s",
		"mcpguard", ev.Tool, ev.Server, truncate(string(args), 400), ev.Decision.Rule)

	target := strings.TrimSuffix(b.cfg.URL, "/") + "/" + b.cfg.Topic
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Title", "mcpguard approval required")
	req.Header.Set("Priority", "high")
	req.Header.Set("Tags", "warning,lock")
	// ntfy action buttons. The nonce in the URL is the credential, which is why
	// the callback binds to loopback and the nonce is single-use.
	req.Header.Set("Actions", strings.Join([]string{
		fmt.Sprintf("http, Approve, %s/approve/%s, clear=true", b.callbackBase, nonce),
		fmt.Sprintf("http, Deny, %s/deny/%s, clear=true", b.callbackBase, nonce),
	}, "; "))

	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ntfy returned %d", resp.StatusCode)
	}
	return nil
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "…"
}
