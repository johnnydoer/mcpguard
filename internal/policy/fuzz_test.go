package policy

import "testing"

// FuzzMatcherMatch asserts a matcher never panics and never reports a match for
// a value it could not evaluate. A panic in the matcher would crash the proxy
// mid-session; a spurious true would be a bypass.
func FuzzMatcherMatch(f *testing.F) {
	f.Add("/srv/data/public/a.txt")
	f.Add("../../etc/shadow")
	f.Add("")

	prefix := "/srv/data/public/"
	m := &Matcher{Type: "string", Canonicalize: "path", Prefix: &prefix}
	if err := m.compile(); err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, value string) {
		ok, err := m.Match(value, true)
		if err != nil && ok {
			t.Fatalf("Match(%q) returned both true and an error; an error must never "+
				"accompany a match", value)
		}
	})
}
