package protocol

import (
	"encoding/json"
	"fmt"
)

// Standard JSON-RPC 2.0 error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603

	// CodePolicyDenied sits in the -32000..-32099 implementation-defined range
	// reserved by the JSON-RPC spec for application errors.
	CodePolicyDenied = -32001

	// CodeApprovalTimeout distinguishes "a human did not answer in time" from
	// "policy said no", which matters when reading an audit log after the fact.
	CodeApprovalTimeout = -32002
)

// Error is a JSON-RPC error object.
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message)
}

// ErrorResponse builds an error response for the given request id.
//
// If data cannot be marshalled the field is omitted rather than propagating a
// second error, because this function is itself on the error path and must not
// be able to fail.
func ErrorResponse(id json.RawMessage, code int, msg string, data any) *Message {
	e := &Error{Code: code, Message: msg}
	if data != nil {
		if encoded, err := json.Marshal(data); err == nil {
			e.Data = encoded
		}
	}
	return &Message{JSONRPC: Version, ID: id, Error: e}
}

// DenyResponse builds the error returned to the agent when policy denies a call.
//
// The rule name and reason are included deliberately: a model that receives
// "denied by rule deny-protected-branches: branch is main" can choose a
// different approach, whereas one that receives a bare failure tends to retry
// the identical call.
func DenyResponse(id json.RawMessage, rule, reason string) *Message {
	msg := "denied by policy"
	if rule != "" {
		msg = "denied by policy rule " + rule
	}
	return ErrorResponse(id, CodePolicyDenied, msg, struct {
		Rule   string `json:"rule"`
		Reason string `json:"reason"`
	}{Rule: rule, Reason: reason})
}
