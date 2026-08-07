package canon

import (
	"path/filepath"
	"strings"
	"testing"
)

// FuzzPathCanonicalization asserts the invariant the whole package exists for:
// a successfully canonicalized path never contains a traversal element and is
// always absolute. If either ever fails, a prefix rule can be walked out of.
func FuzzPathCanonicalization(f *testing.F) {
	for _, seed := range []string{
		"/srv/data/public/a.txt",
		"/srv/data/public/../../etc/shadow",
		"/srv//data///x",
		"/srv/data/public/%2e%2e/etc",
		"relative/path",
		"",
		"/srv/\x00/x",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		got, err := Path(raw)
		if err != nil {
			return // rejection is always an acceptable outcome
		}
		if !filepath.IsAbs(got) {
			t.Fatalf("Path(%q) = %q, which is not absolute", raw, got)
		}
		for _, elem := range strings.Split(got, "/") {
			if elem == ".." {
				t.Fatalf("Path(%q) = %q, which still contains a traversal element", raw, got)
			}
		}
		if strings.ContainsRune(got, 0) {
			t.Fatalf("Path(%q) = %q, which contains a NUL byte", raw, got)
		}
	})
}
