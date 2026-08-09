// Package stdio proxies MCP traffic between an agent and a child MCP server over
// line-delimited stdio.
//
// The proxy is also a process supervisor: it owns the child's lifetime, and both
// directions must shut down cleanly when either side goes away. A proxy that
// leaves the agent waiting on a dead child is worse than no proxy.
package stdio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"

	"github.com/JohnnyDoer/mcpguard/internal/protocol"
)

// Interceptor decides what happens to each message crossing the proxy.
//
// The same interface serves both transports, so enforcement logic is written
// once and cannot drift between stdio and HTTP/SSE.
type Interceptor interface {
	// Inbound handles an agent-to-server message. The context carries the
	// transport's lifetime — cancellation must interrupt any blocking approval
	// wait. Returning forward=false with a non-nil reply short-circuits the call:
	// the reply goes back to the agent and the server never sees the request.
	// Returning forward=false with a nil reply drops the message, which is only
	// correct for notifications.
	Inbound(ctx context.Context, m *protocol.Message) (forward bool, reply *protocol.Message)

	// Outbound handles a server-to-agent message and returns what the agent
	// should receive. Returning nil drops it.
	Outbound(m *protocol.Message) *protocol.Message
}

// PassthroughInterceptor forwards everything unchanged. It exists so the
// transport can be proven transparent before any policy is applied.
type PassthroughInterceptor struct{}

// Inbound forwards every agent-to-server message unchanged.
func (PassthroughInterceptor) Inbound(_ context.Context, _ *protocol.Message) (bool, *protocol.Message) {
	return true, nil
}

// Outbound forwards every server-to-agent message unchanged.
func (PassthroughInterceptor) Outbound(m *protocol.Message) *protocol.Message { return m }

// Config configures a proxy session.
type Config struct {
	// Command is the real MCP server to spawn. Command[0] is the executable.
	Command []string
	// Interceptor applies policy. Required; a nil value is a startup error
	// rather than a mid-session panic.
	Interceptor Interceptor
	// AgentIn, AgentOut are the agent-facing streams — in production, the
	// process's own stdin and stdout.
	AgentIn  io.Reader
	AgentOut io.Writer
	// Stderr receives the child's stderr, forwarded verbatim so the server's
	// own diagnostics remain visible.
	Stderr io.Writer
}

func (c Config) validate() error {
	if len(c.Command) == 0 {
		return errors.New("stdio: Command must not be empty")
	}
	if c.Interceptor == nil {
		return errors.New("stdio: Interceptor must not be nil")
	}
	if c.AgentIn == nil || c.AgentOut == nil {
		return errors.New("stdio: AgentIn and AgentOut must not be nil")
	}
	return nil
}

// Run proxies until the agent closes its input, the child exits, or ctx is
// cancelled. It always reaps the child before returning.
func Run(ctx context.Context, cfg Config) error {
	if err := cfg.validate(); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd := exec.CommandContext(ctx, cfg.Command[0], cfg.Command[1:]...)
	if cfg.Stderr != nil {
		cmd.Stderr = cfg.Stderr
	}

	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdio: child stdin: %w", err)
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdio: child stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("stdio: start %q: %w", cfg.Command[0], err)
	}

	agentEnc := protocol.NewEncoder(cfg.AgentOut)
	serverEnc := protocol.NewEncoder(serverIn)

	// A plain io.Reader's blocking Read is not interruptible by ctx alone: if
	// the child dies while the agent->server pump is blocked waiting for the
	// next request (the agent has gone quiet, not closed its input), nothing
	// above would ever wake it and wg.Wait below would hang forever. Closing
	// AgentIn once ctx is done — whether because the caller cancelled it or
	// because the server->agent pump noticed the child died — turns that
	// blocked read into an error and lets the pump return. os.Stdin, the
	// production AgentIn, is exactly such a closer.
	if closer, ok := cfg.AgentIn.(io.Closer); ok {
		go func() {
			<-ctx.Done()
			_ = closer.Close()
		}()
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Agent -> server.
	go func() {
		defer wg.Done()
		// Closing the child's stdin is what makes a well-behaved server exit,
		// so it must happen even on an error path.
		defer func() { _ = serverIn.Close() }()

		dec := protocol.NewDecoder(cfg.AgentIn)
		for {
			m, err := dec.Decode()
			if err != nil {
				return // EOF or malformed input: stop pumping this direction
			}

			forward, reply := cfg.Interceptor.Inbound(ctx, m)
			if reply != nil {
				if err := agentEnc.Encode(reply); err != nil {
					return
				}
			}
			if !forward {
				continue
			}
			if err := serverEnc.Encode(m); err != nil {
				return
			}
		}
	}()

	// Server -> agent.
	go func() {
		defer wg.Done()
		// Cancelling on return unblocks the other direction when the child dies,
		// which is what prevents the agent hanging forever on a crashed server.
		defer cancel()

		dec := protocol.NewDecoder(serverOut)
		for {
			m, err := dec.Decode()
			if err != nil {
				return
			}
			out := cfg.Interceptor.Outbound(m)
			if out == nil {
				continue
			}
			if err := agentEnc.Encode(out); err != nil {
				return
			}
		}
	}()

	wg.Wait()

	// Always reap. A non-zero exit is information, not a proxy failure, so it is
	// returned rather than swallowed but is not treated as an internal error.
	waitErr := cmd.Wait()
	if waitErr != nil && !processSucceeded(cmd) {
		return fmt.Errorf("stdio: child exited: %w", waitErr)
	}
	return nil
}

// processSucceeded reports whether the child's own exit was clean (status 0).
//
// exec.CommandContext ties the child to ctx, and the pumps above cancel ctx
// once they are done to force a misbehaving child to die. That cancellation
// races harmlessly with a child that already exited on its own: on Unix,
// signaling an unreaped zombie still succeeds, so the exec package reports
// ctx.Err() from Wait even though the process finished successfully first.
// Trusting the recorded exit status over that racy error is what keeps a
// clean shutdown from being misreported as "context canceled".
func processSucceeded(cmd *exec.Cmd) bool {
	return cmd.ProcessState != nil && cmd.ProcessState.Success()
}
