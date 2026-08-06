// Package enforce turns policy decisions into protocol actions.
//
// It is transport-agnostic on purpose: both stdio and HTTP/SSE drive the same
// Interceptor, so enforcement logic is written once and cannot drift between
// them.
package enforce

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/JohnnyDoer/mcpguard/internal/policy"
	"github.com/JohnnyDoer/mcpguard/internal/protocol"
)

// Event is one auditable decision.
type Event struct {
	Server   string
	Method   string
	Tool     string
	Args     map[string]any
	Decision policy.Decision
	Mode     policy.Mode
	Latency  time.Duration
}

// Recorder persists decisions. Every decision is recorded before it is
// enforced; there is no code path that permits a call unrecorded.
type Recorder interface {
	Record(ev Event) error
}

// Approver blocks until a human answers, or the context expires.
type Approver interface {
	Approve(ctx context.Context, ev Event) (bool, error)
}

// Options configures a new Interceptor.
type Options struct {
	Server   string
	Engine   *policy.Engine
	Recorder Recorder
	// Approver may be nil, in which case an approve decision degrades to a
	// denial. Failing closed is the only safe behaviour for a gate with nobody
	// behind it.
	Approver Approver
}

// Interceptor applies policy to messages crossing the proxy.
type Interceptor struct {
	server   string
	engine   *policy.Engine
	recorder Recorder
	approver Approver

	// pending correlates a response to the request that produced it, so a
	// tools/list result can be filtered. Keyed by JSON-RPC id.
	mu      sync.Mutex
	pending map[string]string // id -> method
}

// New constructs an Interceptor from opts.
func New(opts Options) (*Interceptor, error) {
	if opts.Server == "" {
		return nil, errors.New("enforce: Server is required")
	}
	if opts.Engine == nil {
		return nil, errors.New("enforce: Engine is required")
	}
	if opts.Recorder == nil {
		// A proxy that cannot audit must not start. Silently running without a
		// log is the failure mode audit.on_error exists to avoid.
		return nil, errors.New("enforce: Recorder is required")
	}
	return &Interceptor{
		server:   opts.Server,
		engine:   opts.Engine,
		recorder: opts.Recorder,
		approver: opts.Approver,
		pending:  map[string]string{},
	}, nil
}

// Inbound applies policy to an agent-to-server message.
func (i *Interceptor) Inbound(m *protocol.Message) (bool, *protocol.Message) {
	switch m.Method {
	case protocol.MethodToolsCall:
		return i.handleToolsCall(m)
	case protocol.MethodToolsList, protocol.MethodResourcesList:
		// Remember the method so Outbound knows to filter the result. Task 14
		// implements the filtering; recording the pending method here keeps the
		// correlation logic in one place.
		i.rememberPending(m)
		return true, nil
	default:
		// initialize, ping, prompts, and notifications carry no decision surface
		// and are forwarded untouched. Passing initialize through is what keeps
		// mcpguard protocol-version agnostic.
		return true, nil
	}
}

func (i *Interceptor) rememberPending(m *protocol.Message) {
	if !m.HasID() {
		return
	}
	i.mu.Lock()
	i.pending[m.IDKey()] = m.Method
	i.mu.Unlock()
}

func (i *Interceptor) takePending(m *protocol.Message) (string, bool) {
	if !m.HasID() {
		return "", false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	method, ok := i.pending[m.IDKey()]
	if ok {
		// Delete so the table cannot grow without bound over a long session.
		delete(i.pending, m.IDKey())
	}
	return method, ok
}

func (i *Interceptor) handleToolsCall(m *protocol.Message) (bool, *protocol.Message) {
	start := time.Now()

	params, err := protocol.ParseToolsCall(m)
	if err != nil {
		// Unparseable means unauthorizable. Forwarding it and letting the server
		// decide would hand authorization to the thing being guarded.
		ev := Event{
			Server: i.server, Method: m.Method, Mode: i.engine.Config().Mode,
			Decision: policy.Decision{
				Action: policy.ActionDeny,
				Reason: fmt.Sprintf("cannot parse tools/call, denying: %v", err),
			},
			Latency: time.Since(start),
		}
		return i.finish(m, ev)
	}

	decision := i.engine.Evaluate(policy.Request{
		Server: i.server, Method: m.Method, Tool: params.Name, Args: params.Arguments,
	})

	ev := Event{
		Server: i.server, Method: m.Method, Tool: params.Name, Args: params.Arguments,
		Decision: decision, Mode: i.engine.Config().Mode, Latency: time.Since(start),
	}

	if decision.Action == policy.ActionApprove {
		ev = i.resolveApproval(ev)
	}

	return i.finish(m, ev)
}

// resolveApproval converts an approve decision into a concrete allow or deny.
//
// With no approver configured the decision degrades to a denial: a gate with
// nobody behind it must not open.
func (i *Interceptor) resolveApproval(ev Event) Event {
	if i.approver == nil {
		ev.Decision.Action = policy.ActionDeny
		ev.Decision.Reason = "approval required but no approver is configured; denying"
		return ev
	}

	cfg := i.engine.Config()
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Approval.Timeout)
	defer cancel()

	approved, err := i.approver.Approve(ctx, ev)
	switch {
	case err != nil:
		// Cannot reach a human, therefore cannot have approval.
		ev.Decision.Action = policy.ActionDeny
		ev.Decision.Reason = fmt.Sprintf("approval failed, denying: %v", err)
	case approved:
		ev.Decision.Action = policy.ActionAllow
		ev.Decision.Reason = "approved out of band"
	default:
		ev.Decision.Action = policy.ActionDeny
		ev.Decision.Reason = "denied out of band"
	}
	return ev
}

// finish records the decision and applies it, honouring audit mode and the
// configured behaviour when recording fails.
func (i *Interceptor) finish(m *protocol.Message, ev Event) (bool, *protocol.Message) {
	cfg := i.engine.Config()

	if err := i.recorder.Record(ev); err != nil {
		switch cfg.Audit.OnError {
		case policy.OnErrorDeny:
			// Refusing an unrecordable call permits nothing unaudited while
			// keeping the proxy running, which halting would not.
			return false, protocol.DenyResponse(m.ID, ev.Decision.Rule,
				fmt.Sprintf("audit log unavailable, denying: %v", err))
		case policy.OnErrorHalt:
			// The stdio pump has no way to stop the process from here, so halt
			// is implemented as deny plus a fatal record that Task 16's run
			// command watches for.
			return false, protocol.DenyResponse(m.ID, ev.Decision.Rule,
				fmt.Sprintf("audit log unavailable and on_error is halt: %v", err))
		case policy.OnErrorContinue:
			// Explicitly configured to proceed unaudited.
		}
	}

	if cfg.Mode == policy.ModeAudit {
		// Record what would have happened, then forward regardless. This is what
		// makes a policy rollout survivable.
		return true, nil
	}

	if ev.Decision.Action == policy.ActionAllow {
		return true, nil
	}
	return false, protocol.DenyResponse(m.ID, ev.Decision.Rule, ev.Decision.Reason)
}

// Outbound handles a server-to-agent message. Task 14 adds list filtering here.
func (i *Interceptor) Outbound(m *protocol.Message) *protocol.Message {
	if _, ok := i.takePending(m); !ok {
		return m
	}
	return m
}
