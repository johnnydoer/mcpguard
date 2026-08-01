// Command fakeserver is a minimal MCP server for mcpguard's integration tests.
//
// It implements just enough of the protocol to exercise the proxy: initialize,
// tools/list, tools/call, resources/list, resources/read, and a crash trigger.
// Using a real subprocess rather than an in-memory fake is deliberate — process
// supervision, pipe buffering, and EOF handling are exactly what Task 6 must get
// right, and an in-memory fake would test none of them.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m message
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}

		var result string
		switch m.Method {
		case "initialize":
			result = `{"protocolVersion":"2025-06-18","capabilities":{"tools":{},"resources":{}},` +
				`"serverInfo":{"name":"fakeserver","version":"0.1.0"}}`
		case "tools/list":
			result = `{"tools":[` +
				`{"name":"read_file","description":"read","inputSchema":{"type":"object"}},` +
				`{"name":"write_file","description":"write","inputSchema":{"type":"object"}},` +
				`{"name":"delete_file","description":"delete","inputSchema":{"type":"object"}}]}`
		case "tools/call":
			// Echo the arguments back so tests can assert nothing was mutated.
			var p struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}
			_ = json.Unmarshal(m.Params, &p)
			args := string(p.Arguments)
			if args == "" {
				args = "{}"
			}
			result = fmt.Sprintf(`{"content":[{"type":"text","text":%q}],"isError":false}`,
				p.Name+" called with "+args)
		case "resources/list":
			result = `{"resources":[{"uri":"file:///srv/public/a"},{"uri":"file:///etc/shadow"}]}`
		case "resources/read":
			result = `{"contents":[{"uri":"file:///srv/public/a","text":"hello"}]}`
		case "crash":
			// Exercises the supervisor's child-death path.
			os.Exit(3)
		case "bigresult":
			// Exercises framing above bufio.Scanner's default 64 KiB limit.
			result = fmt.Sprintf(`{"content":[{"type":"text","text":%q}]}`,
				strings.Repeat("x", 200*1024))
		default:
			// Unknown notifications are ignored, matching real server behaviour.
			if len(m.ID) == 0 {
				continue
			}
			result = `{}`
		}

		if len(m.ID) == 0 {
			continue // notification: no response
		}
		resp := message{JSONRPC: "2.0", ID: m.ID, Result: json.RawMessage(result)}
		encoded, err := json.Marshal(resp)
		if err != nil {
			continue
		}
		_, _ = out.Write(append(encoded, '\n'))
		_ = out.Flush()
	}
}
