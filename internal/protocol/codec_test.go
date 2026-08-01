package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestDecodeSingleMessage(t *testing.T) {
	in := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
	m, err := NewDecoder(strings.NewReader(in)).Decode()
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if m.Method != "tools/list" || m.IDKey() != "1" {
		t.Errorf("decoded %+v, want method tools/list id 1", m)
	}
}

func TestDecodeSequentialMessages(t *testing.T) {
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"a"}`,
		`{"jsonrpc":"2.0","id":2,"method":"b"}`,
		`{"jsonrpc":"2.0","id":3,"method":"c"}`,
	}, "\n") + "\n"

	d := NewDecoder(strings.NewReader(in))
	for _, want := range []string{"a", "b", "c"} {
		m, err := d.Decode()
		if err != nil {
			t.Fatalf("Decode %s: %v", want, err)
		}
		if m.Method != want {
			t.Errorf("method = %q, want %q", m.Method, want)
		}
	}
	if _, err := d.Decode(); !errors.Is(err, io.EOF) {
		t.Errorf("after the last message Decode should return io.EOF, got %v", err)
	}
}

func TestDecodeSkipsBlankLines(t *testing.T) {
	// Some servers emit a trailing newline after each frame, producing empty
	// lines. Treating one as a parse error would kill the session.
	in := "\n\n" + `{"jsonrpc":"2.0","id":1,"method":"a"}` + "\n\n"
	m, err := NewDecoder(strings.NewReader(in)).Decode()
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if m.Method != "a" {
		t.Errorf("method = %q, want a", m.Method)
	}
}

func TestDecodeRejectsMalformedJSON(t *testing.T) {
	_, err := NewDecoder(strings.NewReader("{not json}\n")).Decode()
	if err == nil {
		t.Fatal("expected a decode error for malformed JSON")
	}
	if errors.Is(err, io.EOF) {
		t.Error("a parse failure must not be reported as EOF")
	}
}

func TestDecodeHandlesLargeMessage(t *testing.T) {
	// bufio.Scanner defaults to a 64 KiB limit. A tool that returns a 200 KiB
	// file would be silently truncated, producing corruption that looks like a
	// protocol bug rather than a buffer limit. This is the single most likely
	// framing bug in the project.
	big := strings.Repeat("x", 200*1024)
	in, err := json.Marshal(&Message{
		JSONRPC: Version,
		ID:      json.RawMessage(`1`),
		Result:  json.RawMessage(`{"content":"` + big + `"}`),
	})
	if err != nil {
		t.Fatal(err)
	}

	m, err := NewDecoder(bytes.NewReader(append(in, '\n'))).Decode()
	if err != nil {
		t.Fatalf("Decode of a 200 KiB message failed: %v", err)
	}
	if !bytes.Contains(m.Result, []byte(big)) {
		t.Error("large result was truncated")
	}
}

func TestDecodeRejectsOversizedMessage(t *testing.T) {
	oversized := strings.Repeat("x", MaxMessageBytes+1) + "\n"
	_, err := NewDecoder(strings.NewReader(oversized)).Decode()
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("err = %v, want ErrMessageTooLarge", err)
	}
}

func TestEncodeIsNewlineTerminated(t *testing.T) {
	var buf bytes.Buffer
	err := NewEncoder(&buf).Encode(&Message{
		JSONRPC: Version, ID: json.RawMessage(`1`), Method: "ping",
	})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.HasSuffix(out, "\n") {
		t.Error("every frame must end with a newline or the peer blocks forever")
	}
	if strings.Count(strings.TrimSuffix(out, "\n"), "\n") != 0 {
		t.Error("a frame must not contain embedded newlines")
	}
}

func TestEncodeRoundTrips(t *testing.T) {
	want := &Message{JSONRPC: Version, ID: json.RawMessage(`"x"`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"read_file"}`)}

	var buf bytes.Buffer
	if err := NewEncoder(&buf).Encode(want); err != nil {
		t.Fatal(err)
	}
	got, err := NewDecoder(&buf).Decode()
	if err != nil {
		t.Fatal(err)
	}
	if got.Method != want.Method || got.IDKey() != want.IDKey() ||
		string(got.Params) != string(want.Params) {
		t.Errorf("round trip lost data: got %+v want %+v", got, want)
	}
}

func TestEncoderIsConcurrencySafe(t *testing.T) {
	// Two goroutines write to the agent: the pump forwarding real responses, and
	// the interceptor injecting denials. Without a mutex their frames interleave
	// and both become unparseable.
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = enc.Encode(&Message{JSONRPC: Version, Method: "notifications/x",
				Params: json.RawMessage(`{"padding":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)})
		}()
	}
	wg.Wait()

	d := NewDecoder(bytes.NewReader(buf.Bytes()))
	for i := 0; i < 50; i++ {
		if _, err := d.Decode(); err != nil {
			t.Fatalf("frame %d is corrupt, indicating interleaved writes: %v", i, err)
		}
	}
}
