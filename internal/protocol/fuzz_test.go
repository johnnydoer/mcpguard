package protocol

import (
	"strings"
	"testing"
)

// FuzzDecodeMessage asserts the decoder never panics on hostile input. A panic
// here takes the proxy down, which fails the agent closed but noisily.
func FuzzDecodeMessage(f *testing.F) {
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}` + "\n")
	f.Add("{}\n")
	f.Add("not json\n")
	f.Add("\n\n\n")

	f.Fuzz(func(_ *testing.T, in string) {
		d := NewDecoder(strings.NewReader(in))
		for i := 0; i < 100; i++ {
			m, err := d.Decode()
			if err != nil {
				return
			}
			// Exercise the predicates, which index into ID.
			_ = m.IsRequest()
			_ = m.IsNotification()
			_ = m.IsResponse()
			_ = m.IDKey()
		}
	})
}
