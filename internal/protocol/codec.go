package protocol

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// MaxMessageBytes bounds a single JSON-RPC frame.
//
// The bufio.Scanner default of 64 KiB is far too small: a tool returning a
// modest file exceeds it, and the scanner's failure mode is truncation rather
// than a clean error. 1 MiB accommodates realistic tool results while still
// bounding memory against a hostile peer.
const MaxMessageBytes = 1 << 20

// ErrMessageTooLarge is returned when a frame exceeds MaxMessageBytes.
var ErrMessageTooLarge = errors.New("protocol: message exceeds maximum size")

// Decoder reads newline-delimited JSON-RPC messages, the framing MCP uses over
// stdio.
type Decoder struct {
	sc *bufio.Scanner
}

// NewDecoder returns a new Decoder that reads from r.
func NewDecoder(r io.Reader) *Decoder {
	sc := bufio.NewScanner(r)
	// The second argument is the cap, not the initial size, so this does not
	// allocate 1 MiB per decoder up front.
	sc.Buffer(make([]byte, 0, 64*1024), MaxMessageBytes)
	return &Decoder{sc: sc}
}

// Decode returns the next message, or io.EOF when the stream ends cleanly.
//
// Blank lines are skipped rather than treated as parse errors: some servers
// emit a trailing newline per frame, and killing the session over cosmetic
// whitespace would be a poor trade.
func (d *Decoder) Decode() (*Message, error) {
	for {
		if !d.sc.Scan() {
			if err := d.sc.Err(); err != nil {
				if errors.Is(err, bufio.ErrTooLong) {
					return nil, ErrMessageTooLarge
				}
				return nil, fmt.Errorf("protocol: read: %w", err)
			}
			return nil, io.EOF
		}

		line := bytes.TrimSpace(d.sc.Bytes())
		if len(line) == 0 {
			continue
		}

		var m Message
		if err := json.Unmarshal(line, &m); err != nil {
			return nil, fmt.Errorf("protocol: decode: %w", err)
		}
		return &m, nil
	}
}

// Encoder writes newline-delimited JSON-RPC messages.
//
// Writes are serialised because two goroutines legitimately share one encoder:
// the pump forwarding upstream responses, and the interceptor injecting policy
// denials. Interleaved writes would corrupt both frames.
type Encoder struct {
	mu sync.Mutex
	w  io.Writer
}

// NewEncoder returns a new Encoder that writes to w.
func NewEncoder(w io.Writer) *Encoder { return &Encoder{w: w} }

// Encode writes the message as a newline-terminated JSON frame.
func (e *Encoder) Encode(m *Message) error {
	encoded, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("protocol: encode: %w", err)
	}
	// json.Marshal escapes newlines inside strings, so appending one here is
	// unambiguous as a frame terminator.
	encoded = append(encoded, '\n')

	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.w.Write(encoded); err != nil {
		return fmt.Errorf("protocol: write: %w", err)
	}
	return nil
}
