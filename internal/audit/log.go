// Package audit writes one JSON object per policy decision.
//
// Every decision is recorded before it is enforced. The interaction with
// policy.AuditConfig.OnError is deliberate: startup with an unwritable path
// always fails, whereas a runtime write failure applies the configured policy —
// deny by default, so calls are refused rather than permitted unrecorded.
package audit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/JohnnyDoer/mcpguard/internal/enforce"
	"github.com/JohnnyDoer/mcpguard/internal/policy"
)

const redactedPlaceholder = "[REDACTED]"

// Logger writes JSON-lines audit records.
type Logger struct {
	sessionID string
	redact    []string

	mu     sync.Mutex
	w      io.Writer
	closer io.Closer
}

// New builds a Logger writing to w. Used directly by tests and by Open.
func New(cfg policy.AuditConfig, sessionID string, w io.Writer) (*Logger, error) {
	if w == nil {
		return nil, fmt.Errorf("audit: writer must not be nil")
	}
	return &Logger{sessionID: sessionID, redact: cfg.Redact, w: w}, nil
}

// Open opens the configured path for appending.
//
// An empty path falls back to stderr rather than disabling auditing: a proxy
// that silently records nothing is the outcome this package exists to prevent.
func Open(cfg policy.AuditConfig, sessionID string) (*Logger, error) {
	if cfg.Path == "" {
		return New(cfg, sessionID, os.Stderr)
	}
	if dir := filepath.Dir(cfg.Path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("audit: create log directory: %w", err)
		}
	}
	f, err := os.OpenFile(cfg.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		// Startup always fails on an unwritable path, whatever on_error says.
		return nil, fmt.Errorf("audit: open %s: %w", cfg.Path, err)
	}
	lg, err := New(cfg, sessionID, f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	lg.closer = f
	return lg, nil
}

// Close closes the underlying file, if any. A no-op when writing to stderr.
func (l *Logger) Close() error {
	if l.closer == nil {
		return nil
	}
	return l.closer.Close()
}

type logRecord struct {
	Timestamp string         `json:"ts"`
	SessionID string         `json:"session_id"`
	Server    string         `json:"server"`
	Method    string         `json:"method"`
	Tool      string         `json:"tool"`
	Args      map[string]any `json:"args"`
	ArgsHash  string         `json:"args_hash"`
	Decision  string         `json:"decision"`
	Rule      string         `json:"rule"`
	Reason    string         `json:"reason,omitempty"`
	Mode      string         `json:"mode"`
	LatencyMS int64          `json:"latency_ms"`
}

// Record writes one audit line.
func (l *Logger) Record(ev enforce.Event) error {
	// The hash is computed over the UNREDACTED canonical form so repeated calls
	// correlate without the value being stored. Hashing the redacted form would
	// make every redacted call hash identically.
	hash, err := hashArgs(ev.Args)
	if err != nil {
		return fmt.Errorf("audit: hash args: %w", err)
	}

	rec := logRecord{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		SessionID: l.sessionID,
		Server:    ev.Server,
		Method:    ev.Method,
		Tool:      ev.Tool,
		Args:      redactCopy(ev.Args, l.redact),
		ArgsHash:  hash,
		Decision:  string(ev.Decision.Action),
		Rule:      ev.Decision.Rule,
		Reason:    ev.Decision.Reason,
		Mode:      string(ev.Mode),
		LatencyMS: ev.Latency.Milliseconds(),
	}

	encoded, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("audit: marshal record: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.w.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("audit: write: %w", err)
	}
	return nil
}

// hashArgs produces a stable hash over the arguments.
//
// json.Marshal sorts map keys, so the canonical form does not depend on Go's
// random map iteration order — without that, identical calls would hash
// differently between runs.
func hashArgs(args map[string]any) (string, error) {
	if len(args) == 0 {
		return "sha256:" + hex.EncodeToString(sha256.New().Sum(nil)), nil
	}
	canonical, err := json.Marshal(args)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// redactCopy returns a deep copy with redacted paths replaced.
//
// A copy rather than in-place mutation, because the same Event is also used for
// metrics and for the approval prompt, and corrupting its arguments would
// corrupt both.
func redactCopy(args map[string]any, patterns []string) map[string]any {
	if len(args) == 0 {
		return map[string]any{}
	}
	out := deepCopyMap(args)
	for _, pattern := range patterns {
		// Patterns are written as "args.token" and "args.*.secret", so the
		// leading "args." is stripped before walking.
		segments := strings.Split(strings.TrimPrefix(pattern, "args."), ".")
		applyRedaction(out, segments)
	}
	return out
}

func applyRedaction(node map[string]any, segments []string) {
	if len(segments) == 0 {
		return
	}
	head := segments[0]
	rest := segments[1:]

	keys := make([]string, 0, len(node))
	for k := range node {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		if head != "*" && head != k {
			continue
		}
		if len(rest) == 0 {
			node[k] = redactedPlaceholder
			continue
		}
		if child, ok := node[k].(map[string]any); ok {
			applyRedaction(child, rest)
		}
	}
}

func deepCopyMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch typed := v.(type) {
		case map[string]any:
			out[k] = deepCopyMap(typed)
		case []any:
			out[k] = deepCopySlice(typed)
		default:
			out[k] = v
		}
	}
	return out
}

func deepCopySlice(in []any) []any {
	out := make([]any, len(in))
	for i, v := range in {
		switch typed := v.(type) {
		case map[string]any:
			out[i] = deepCopyMap(typed)
		case []any:
			out[i] = deepCopySlice(typed)
		default:
			out[i] = v
		}
	}
	return out
}

// NewSessionID returns 8 random hex characters.
//
// One stdio process is one session by construction, so there is nothing to
// derive from the protocol handshake.
func NewSessionID() string {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing is not recoverable and not something to paper over
		// with a weak fallback, but an audit id is not a security boundary — a
		// timestamp is a sufficient degraded identifier.
		return fmt.Sprintf("%08x", time.Now().UnixNano()&0xffffffff)
	}
	return hex.EncodeToString(buf)
}
