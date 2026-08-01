// Package protocol implements the JSON-RPC 2.0 and Model Context Protocol
// message handling mcpguard needs to proxy and inspect traffic.
//
// Message deliberately keeps id, params, and result as json.RawMessage. A proxy
// does not need to interpret most of what it forwards, and preserving the exact
// bytes avoids two classes of corruption: large integer ids being mangled
// through float64, and re-marshalling changing a payload the peer will hash or
// compare.
package protocol

import (
	"bytes"
	"encoding/json"
)

// Version is the only JSON-RPC version MCP uses.
const Version = "2.0"

// Message is a JSON-RPC 2.0 request, notification, or response. Which one it is
// depends on the combination of fields present; use the predicates rather than
// checking fields directly.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

var nullLiteral = []byte("null")

// HasID reports whether the message carries a usable correlation id.
//
// A literal null id does not count. JSON-RPC permits null when responding to a
// request whose id could not be parsed, and treating it as a real id would make
// every such failure collide on one correlation-table key.
func (m *Message) HasID() bool {
	trimmed := bytes.TrimSpace(m.ID)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, nullLiteral)
}

// IsRequest reports whether the message expects a response.
func (m *Message) IsRequest() bool { return m.Method != "" && m.HasID() }

// IsNotification reports whether the message is fire-and-forget.
func (m *Message) IsNotification() bool { return m.Method != "" && !m.HasID() }

// IsResponse reports whether the message answers an earlier request.
func (m *Message) IsResponse() bool { return m.Method == "" && m.HasID() }

// IDKey returns a stable map key for correlating a response to its request.
//
// Surrounding whitespace is stripped so that peers with different encoders
// still correlate, but the JSON quoting is preserved so that the string id "1"
// and the numeric id 1 remain distinct keys.
func (m *Message) IDKey() string { return string(bytes.TrimSpace(m.ID)) }
