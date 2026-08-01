package canon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPathCleansRedundantSeparators(t *testing.T) {
	for raw, want := range map[string]string{
		"/srv//data///x": "/srv/data/x",
		"/srv/./data/x":  "/srv/data/x",
		"/srv/data/x/":   "/srv/data/x",
		"/srv/data/x":    "/srv/data/x",
	} {
		got, err := Path(raw)
		if err != nil {
			t.Errorf("Path(%q): %v", raw, err)
			continue
		}
		if got != want {
			t.Errorf("Path(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestPathRejectsTraversal(t *testing.T) {
	// mcpguard rejects any path containing a ".." element outright rather than
	// attempting to normalize it. Normalizing correctly in the presence of
	// symlinks is genuinely hard — filepath.Clean collapses "/a/link/../b" to
	// "/a/b", but the kernel resolves it relative to link's target, so the two
	// disagree and the disagreement is exploitable. Rejecting the whole class
	// costs legitimate callers almost nothing and removes the ambiguity.
	for _, raw := range []string{
		"/srv/data/public/../../etc/shadow",
		"/srv/data/public/..",
		"/../etc/shadow",
		"/srv/../srv/data", // rejected even though it is harmless — no exceptions
		"/srv/data/public/../public/x",
	} {
		if _, err := Path(raw); !errors.Is(err, ErrTraversal) {
			t.Errorf("Path(%q) err = %v, want ErrTraversal", raw, err)
		}
	}
}

func TestPathRejectsRelative(t *testing.T) {
	// A relative path is resolved against the SERVER's working directory, which
	// mcpguard does not know. Any prefix rule written against it would be
	// meaningless, so relative paths are denied and the policy reference says so.
	for _, raw := range []string{"data/x", "./x", "x"} {
		if _, err := Path(raw); !errors.Is(err, ErrNotAbsolute) {
			t.Errorf("Path(%q) err = %v, want ErrNotAbsolute", raw, err)
		}
	}
}

func TestPathRejectsNulByte(t *testing.T) {
	// A NUL truncates the path in any C-based syscall layer, so "/srv/ok\x00/../etc"
	// can pass a Go-side prefix check and open something else entirely.
	if _, err := Path("/srv/data/public/x\x00/../../etc/shadow"); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid for a NUL byte", err)
	}
}

func TestPathRejectsInvalidUTF8(t *testing.T) {
	if _, err := Path("/srv/\xff\xfe"); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid for invalid UTF-8", err)
	}
}

func TestPathRejectsEmpty(t *testing.T) {
	if _, err := Path(""); !errors.Is(err, ErrEmpty) {
		t.Errorf("err = %v, want ErrEmpty", err)
	}
}

func TestPathResolvesSymlinks(t *testing.T) {
	// A symlink inside an allowed prefix pointing outside it is the other half of
	// the traversal problem, and rejecting ".." does nothing about it.
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	got, err := Path(filepath.Join(link, "file.txt"))
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	// The link is resolved even though file.txt does not exist.
	if !strings.HasPrefix(got, realDir) {
		t.Errorf("Path = %q, want a path under the symlink target %q", got, realDir)
	}
}

func TestPathResolvesDeepestExistingAncestor(t *testing.T) {
	// A write to a not-yet-existing file must still canonicalize. EvalSymlinks
	// fails outright on a missing path, so the implementation resolves the
	// deepest existing ancestor and re-joins the remainder.
	dir := t.TempDir()
	got, err := Path(filepath.Join(dir, "a", "b", "c.txt"))
	if err != nil {
		t.Fatalf("Path on a non-existent leaf: %v", err)
	}
	if !strings.HasSuffix(got, filepath.Join("a", "b", "c.txt")) {
		t.Errorf("Path = %q, want it to end with a/b/c.txt", got)
	}
}

func TestPathIsIdempotent(t *testing.T) {
	// A matcher may canonicalize a value that is already canonical. If that
	// changed the result, prefix comparisons would be unstable.
	first, err := Path("/srv/data/x")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Path(first)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("not idempotent: %q then %q", first, second)
	}
}

func TestURLNormalizesCaseAndDefaultPort(t *testing.T) {
	for raw, want := range map[string]string{
		"HTTPS://Example.COM/a":     "https://example.com/a",
		"https://example.com:443/a": "https://example.com/a",
		"http://example.com:80/a":   "http://example.com/a",
		"https://example.com":       "https://example.com/",
		"https://example.com//a//b": "https://example.com/a/b",
	} {
		got, err := URL(raw)
		if err != nil {
			t.Errorf("URL(%q): %v", raw, err)
			continue
		}
		if got != want {
			t.Errorf("URL(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestURLRejectsTraversalInPath(t *testing.T) {
	if _, err := URL("https://example.com/a/../../etc"); !errors.Is(err, ErrTraversal) {
		t.Errorf("err = %v, want ErrTraversal", err)
	}
}

func TestURLRejectsMalformed(t *testing.T) {
	for _, raw := range []string{"", "://nope", "ht tp://x"} {
		if _, err := URL(raw); err == nil {
			t.Errorf("URL(%q) should have failed", raw)
		}
	}
}

func TestFileURIPathExtractsCanonicalPath(t *testing.T) {
	got, err := FileURIPath("file:///srv/data//public/./x")
	if err != nil {
		t.Fatalf("FileURIPath: %v", err)
	}
	if got != "/srv/data/public/x" {
		t.Errorf("FileURIPath = %q, want /srv/data/public/x", got)
	}
}

func TestFileURIPathRejectsTraversalAfterDecoding(t *testing.T) {
	// %2e%2e decodes to "..". Checking for traversal before percent-decoding
	// would miss this entirely, which is why decoding happens first.
	for _, raw := range []string{
		"file:///srv/data/public/../../etc/shadow",
		"file:///srv/data/public/%2e%2e/%2e%2e/etc/shadow",
		"file:///srv/data/public/%2E%2E/etc/shadow",
	} {
		if _, err := FileURIPath(raw); !errors.Is(err, ErrTraversal) {
			t.Errorf("FileURIPath(%q) err = %v, want ErrTraversal", raw, err)
		}
	}
}

func TestFileURIPathRejectsNonFileScheme(t *testing.T) {
	if _, err := FileURIPath("https://example.com/a"); err == nil {
		t.Error("expected an error for a non-file scheme")
	}
}
