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
	"strings"
	"sync"
	"time"

	"github.com/JohnnyDoer/mcpguard/internal/canon"
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
	// Cancel, when non-nil, is called when audit.on_error:halt triggers. Calling
	// it cancels the proxy's lifecycle context, which causes both transports to
	// exit cleanly after the in-flight denial is delivered.
	Cancel context.CancelFunc
}

// Interceptor applies policy to messages crossing the proxy.
type Interceptor struct {
	server   string
	engine   *policy.Engine
	recorder Recorder
	approver Approver
	cancel   context.CancelFunc

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
		cancel:   opts.Cancel,
		pending:  map[string]string{},
	}, nil
}

// Inbound applies policy to an agent-to-server message.
func (i *Interceptor) Inbound(ctx context.Context, m *protocol.Message) (bool, *protocol.Message) {
	switch m.Method {
	case protocol.MethodToolsCall:
		return i.handleToolsCall(ctx, m)
	case protocol.MethodResourcesRead:
		return i.handleResourcesRead(ctx, m)
	case protocol.MethodToolsList, protocol.MethodResourcesList:
		i.rememberPending(m)
		return true, nil
	default:
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

func (i *Interceptor) handleToolsCall(ctx context.Context, m *protocol.Message) (bool, *protocol.Message) {
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

	// Audit mode observes without blocking: skip approval wait, finish will
	// forward regardless of the decision.
	if decision.Action == policy.ActionApprove && i.engine.Config().Mode != policy.ModeAudit {
		ev = i.resolveApproval(ctx, ev)
	}

	return i.finish(m, ev)
}

// handleResourcesRead authorizes a resource read.
//
// resources/read is a read primitive with real exfiltration reach. A tool
// allowlist that ignores it does not do what its users think it does, which is
// why it goes through the same engine as tools/call — the URI takes the place of
// the tool name, so one rule syntax covers both.
//
// For file:// URIs the URI is canonicalized before evaluation. A raw URI such as
// file:///srv/public/../etc/shadow would match a glob like file:///srv/public/*
// because GlobMatch does not understand "..". Canonicalization rejects any URI
// containing a traversal element, closing that bypass class.
func (i *Interceptor) handleResourcesRead(ctx context.Context, m *protocol.Message) (bool, *protocol.Message) {
	start := time.Now()

	params, err := protocol.ParseResourcesRead(m)
	if err != nil {
		ev := Event{
			Server: i.server, Method: m.Method, Mode: i.engine.Config().Mode,
			Decision: policy.Decision{
				Action: policy.ActionDeny,
				Reason: fmt.Sprintf("cannot parse resources/read, denying: %v", err),
			},
			Latency: time.Since(start),
		}
		return i.finish(m, ev)
	}

	toolURI := params.URI
	if strings.HasPrefix(params.URI, "file://") {
		canonPath, canonErr := canon.FileURIPath(params.URI)
		if canonErr != nil {
			ev := Event{
				Server: i.server, Method: m.Method, Tool: params.URI,
				Mode: i.engine.Config().Mode,
				Decision: policy.Decision{
					Action: policy.ActionDeny,
					Reason: fmt.Sprintf("resource URI rejected: %v", canonErr),
				},
				Latency: time.Since(start),
			}
			return i.finish(m, ev)
		}
		toolURI = "file://" + canonPath
	}

	decision := i.engine.Evaluate(policy.Request{
		Server: i.server, Method: m.Method, Tool: toolURI, Args: map[string]any{},
	})

	ev := Event{
		Server: i.server, Method: m.Method, Tool: toolURI, Mode: i.engine.Config().Mode,
		Decision: decision, Latency: time.Since(start),
	}
	// Audit mode observes without blocking: skip approval wait, finish will
	// forward regardless of the decision.
	if decision.Action == policy.ActionApprove && i.engine.Config().Mode != policy.ModeAudit {
		ev = i.resolveApproval(ctx, ev)
	}
	return i.finish(m, ev)
}

// resolveApproval converts an approve decision into a concrete allow or deny.
//
// With no approver configured the decision degrades to a denial: a gate with
// nobody behind it must not open.
//
// The caller's context is respected: if the transport shuts down (SIGTERM,
// HTTP client disconnect) the approval wait is interrupted rather than blocking
// for the full Approval.Timeout.
func (i *Interceptor) resolveApproval(ctx context.Context, ev Event) Event {
	if i.approver == nil {
		ev.Decision.Action = policy.ActionDeny
		ev.Decision.Reason = "approval required but no approver is configured; denying"
		return ev
	}

	cfg := i.engine.Config()
	approvalCtx, cancel := context.WithTimeout(ctx, cfg.Approval.Timeout)
	defer cancel()

	approved, err := i.approver.Approve(approvalCtx, ev)
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
			// Cancel the proxy's lifecycle context so the transport exits cleanly
			// after delivering this denial. The in-flight call is denied first so
			// the agent gets a response rather than a silent disconnect.
			if i.cancel != nil {
				i.cancel()
			}
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

// Outbound filters list results so the agent never learns about denied
// capabilities.
func (i *Interceptor) Outbound(m *protocol.Message) *protocol.Message {
	method, ok := i.takePending(m)
	if !ok {
		return m
	}
	// An error response has no result to filter, and parsing one would turn a
	// server error into a proxy error.
	if m.Error != nil || len(m.Result) == 0 {
		return m
	}

	var (
		filtered []byte
		err      error
	)
	switch method {
	case protocol.MethodToolsList:
		filtered, err = protocol.FilterToolsList(m.Result, func(name string) bool {
			return i.engine.ToolVisible(i.server, name)
		})
	case protocol.MethodResourcesList:
		filtered, err = protocol.FilterResourcesList(m.Result, func(uri string) bool {
			return i.engine.ToolVisible(i.server, uri)
		})
	default:
		return m
	}

	if err != nil {
		// Forwarding an unfilterable list would advertise denied capabilities.
		// Replacing it with an error is the fail-closed choice.
		return protocol.ErrorResponse(m.ID, protocol.CodeInternalError,
			"mcpguard could not filter the response", struct {
				Reason string `json:"reason"`
			}{Reason: err.Error()})
	}

	m.Result = filtered
	return m
}
