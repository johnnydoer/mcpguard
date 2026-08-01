package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
)

// MCP method names mcpguard recognises.
//
// mcpguard does not pin a protocol revision — initialize is forwarded untouched
// so client and server negotiate directly. Interception is keyed on these method
// names, which is why `mcpguard validate` exists: a revision that renames a
// method would silently stop interception, and validate is what catches it.
const (
	MethodInitialize    = "initialize"
	MethodToolsList     = "tools/list"
	MethodToolsCall     = "tools/call"
	MethodResourcesList = "resources/list"
	MethodResourcesRead = "resources/read"
	MethodPromptsList   = "prompts/list"
)

// ToolsCallParams is the params object of a tools/call request.
type ToolsCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// ResourcesReadParams is the params object of a resources/read request.
type ResourcesReadParams struct {
	URI string `json:"uri"`
}

// Tool is one entry in a tools/list result.
//
// InputSchema stays as RawMessage: it is what the model uses to construct calls,
// and round-tripping it through a typed struct would silently drop vendor
// extensions.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// ToolsListResult is the result of a tools/list request.
type ToolsListResult struct {
	Tools      []Tool `json:"tools"`
	NextCursor string `json:"nextCursor,omitempty"`
}

// Resource is one entry in a resources/list result.
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// ResourcesListResult is the result of a resources/list request.
type ResourcesListResult struct {
	Resources  []Resource `json:"resources"`
	NextCursor string     `json:"nextCursor,omitempty"`
}

// ErrMissingField indicates a payload lacked a field required to authorize it.
var ErrMissingField = errors.New("protocol: required field missing")

// ParseToolsCall extracts the tool name and arguments from a tools/call request.
//
// A missing name is an error rather than an empty string, because an empty name
// could match a wildcard rule and be permitted. Anything unauthorizable must
// fail loudly.
func ParseToolsCall(m *Message) (*ToolsCallParams, error) {
	var p ToolsCallParams
	if err := json.Unmarshal(m.Params, &p); err != nil {
		return nil, fmt.Errorf("protocol: tools/call params: %w", err)
	}
	if p.Name == "" {
		return nil, fmt.Errorf("%w: tools/call name", ErrMissingField)
	}
	if p.Arguments == nil {
		// Non-nil so matchers can test for absent keys without a nil guard.
		p.Arguments = map[string]any{}
	}
	return &p, nil
}

// ParseResourcesRead extracts the URI from a resources/read request.
func ParseResourcesRead(m *Message) (*ResourcesReadParams, error) {
	var p ResourcesReadParams
	if err := json.Unmarshal(m.Params, &p); err != nil {
		return nil, fmt.Errorf("protocol: resources/read params: %w", err)
	}
	if p.URI == "" {
		return nil, fmt.Errorf("%w: resources/read uri", ErrMissingField)
	}
	return &p, nil
}

// FilterToolsList removes tools for which keep returns false.
//
// Filtering the advertised list is cheaper than denying at call time and
// strictly better: a model cannot attempt a tool it was never told about.
func FilterToolsList(result json.RawMessage, keep func(name string) bool) (json.RawMessage, error) {
	var parsed ToolsListResult
	if err := json.Unmarshal(result, &parsed); err != nil {
		return nil, fmt.Errorf("protocol: tools/list result: %w", err)
	}

	// Non-nil empty slice so the field marshals as [] rather than null. Denying
	// every tool is a legitimate configuration and must not emit null.
	kept := make([]Tool, 0, len(parsed.Tools))
	for _, tool := range parsed.Tools {
		if keep(tool.Name) {
			kept = append(kept, tool)
		}
	}
	parsed.Tools = kept

	encoded, err := json.Marshal(parsed)
	if err != nil {
		return nil, fmt.Errorf("protocol: re-encode tools/list: %w", err)
	}
	return encoded, nil
}

// FilterResourcesList removes resources for which keep returns false.
func FilterResourcesList(result json.RawMessage, keep func(uri string) bool) (json.RawMessage, error) {
	var parsed ResourcesListResult
	if err := json.Unmarshal(result, &parsed); err != nil {
		return nil, fmt.Errorf("protocol: resources/list result: %w", err)
	}

	kept := make([]Resource, 0, len(parsed.Resources))
	for _, r := range parsed.Resources {
		if keep(r.URI) {
			kept = append(kept, r)
		}
	}
	parsed.Resources = kept

	encoded, err := json.Marshal(parsed)
	if err != nil {
		return nil, fmt.Errorf("protocol: re-encode resources/list: %w", err)
	}
	return encoded, nil
}
