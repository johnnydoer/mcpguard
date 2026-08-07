// Package approval gates high-risk calls on a human.
//
// Two details separate a working implementation from a decorative one. The
// callback endpoint must authenticate, or anyone who can reach the port approves
// anything. And an approval must bind to the exact call, or a second call
// arriving during the window can consume an approval issued for the first — a
// TOCTOU race that is invisible in ordinary testing.
package approval

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/JohnnyDoer/mcpguard/internal/enforce"
)

// CallHash identifies a specific call: server, tool, and canonical arguments.
//
// json.Marshal sorts map keys, so the hash does not depend on Go's random map
// iteration order.
func CallHash(ev enforce.Event) (string, error) {
	args, err := json.Marshal(ev.Args)
	if err != nil {
		return "", fmt.Errorf("approval: hash args: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(ev.Server))
	h.Write([]byte{0})
	h.Write([]byte(ev.Method))
	h.Write([]byte{0})
	h.Write([]byte(ev.Tool))
	h.Write([]byte{0})
	h.Write(args)
	return hex.EncodeToString(h.Sum(nil)), nil
}

type pending struct {
	callHash string
	ch       chan bool
}

// Registry tracks calls awaiting a decision.
type Registry struct {
	mu      sync.Mutex
	entries map[string]pending
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{entries: map[string]pending{}}
}

// Register creates a single-use nonce bound to the call and returns a channel
// that receives the decision.
func (r *Registry) Register(ev enforce.Event) (string, <-chan bool, error) {
	callHash, err := CallHash(ev)
	if err != nil {
		return "", nil, err
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		// Without a strong nonce the endpoint is guessable, so this is fatal
		// rather than something to degrade around.
		return "", nil, fmt.Errorf("approval: generate nonce: %w", err)
	}
	nonce := hex.EncodeToString(buf)

	// Buffered so Resolve never blocks if the waiter has already timed out.
	ch := make(chan bool, 1)

	r.mu.Lock()
	r.entries[nonce] = pending{callHash: callHash, ch: ch}
	r.mu.Unlock()

	return nonce, ch, nil
}

// Resolve delivers a decision and consumes the nonce.
func (r *Registry) Resolve(nonce string, approved bool) error {
	r.mu.Lock()
	entry, ok := r.entries[nonce]
	if ok {
		// Deleted under the same lock so a concurrent second Resolve cannot also
		// succeed. A replayable nonce would let one approval authorize repeated
		// calls.
		delete(r.entries, nonce)
	}
	r.mu.Unlock()

	if !ok {
		return errors.New("approval: unknown or already-used nonce")
	}
	entry.ch <- approved
	return nil
}

// Cancel discards a pending entry, used when the waiter times out.
func (r *Registry) Cancel(nonce string) {
	r.mu.Lock()
	delete(r.entries, nonce)
	r.mu.Unlock()
}

// Pending returns the number of calls awaiting a decision.
func (r *Registry) Pending() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

// nonces is used by tests to drive an approval without parsing the notification.
func (r *Registry) nonces() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.entries))
	for nonce := range r.entries {
		out = append(out, nonce)
	}
	return out
}

// Handler serves the approve and deny callbacks.
//
// Bind this to loopback. The nonce is the only credential, so exposing it more
// widely than necessary widens the attack surface for no benefit.
func (r *Registry) Handler() http.Handler {
	mux := http.NewServeMux()
	handle := func(approved bool) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			prefix := "/deny/"
			if approved {
				prefix = "/approve/"
			}
			nonce := strings.TrimPrefix(req.URL.Path, prefix)
			if nonce == "" || strings.Contains(nonce, "/") {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			if err := r.Resolve(nonce, approved); err != nil {
				// A uniform response for unknown and used nonces alike, so the
				// endpoint cannot be used to enumerate valid ones.
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			if approved {
				_, _ = w.Write([]byte("approved\n"))
			} else {
				_, _ = w.Write([]byte("denied\n"))
			}
		}
	}
	mux.HandleFunc("/approve/", handle(true))
	mux.HandleFunc("/deny/", handle(false))
	return mux
}
