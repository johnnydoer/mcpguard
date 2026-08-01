// Package canon canonicalizes values before they are compared against policy.
//
// This is the security-critical primitive of mcpguard. A prefix rule compared
// against a raw string is bypassed by traversal on the first attempt, so every
// value a rule constrains passes through here first.
//
// The package makes one deliberately strict choice: any path containing a ".."
// element is rejected outright rather than normalized. Normalizing correctly in
// the presence of symlinks is genuinely hard — filepath.Clean collapses
// "/a/link/../b" to "/a/b", but the kernel resolves it relative to link's target,
// so the two disagree and the disagreement is exploitable. Rejecting the whole
// class costs legitimate callers almost nothing and removes the ambiguity
// entirely.
package canon

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Sentinel errors returned by this package's canonicalization functions.
var (
	// ErrEmpty indicates the input value was empty.
	ErrEmpty = errors.New("canon: value is empty")
	// ErrNotAbsolute indicates a path was not absolute.
	ErrNotAbsolute = errors.New("canon: path must be absolute")
	// ErrTraversal indicates a path contained a ".." element.
	ErrTraversal = errors.New("canon: path contains a traversal element")
	// ErrInvalid indicates the value was not a valid path or URL.
	ErrInvalid = errors.New("canon: value is not a valid path")
)

// hasTraversal reports whether any element of a slash-separated path is "..".
//
// A substring search for ".." would produce false positives on legitimate names
// such as "my..file", so the check is per element.
func hasTraversal(p string) bool {
	for _, elem := range strings.Split(p, "/") {
		if elem == ".." {
			return true
		}
	}
	return false
}

// Path canonicalizes an absolute filesystem path for comparison.
//
// Relative paths are rejected: they resolve against the MCP server's working
// directory, which mcpguard does not know, so any prefix rule written against
// one would be meaningless.
func Path(raw string) (string, error) {
	if raw == "" {
		return "", ErrEmpty
	}
	if strings.ContainsRune(raw, 0) {
		// A NUL truncates the path in any C-based syscall layer, so a Go-side
		// prefix check can pass while the kernel opens something else.
		return "", fmt.Errorf("%w: contains NUL byte", ErrInvalid)
	}
	if !utf8.ValidString(raw) {
		return "", fmt.Errorf("%w: not valid UTF-8", ErrInvalid)
	}
	if hasTraversal(raw) {
		return "", fmt.Errorf("%w: %q", ErrTraversal, raw)
	}
	if !filepath.IsAbs(raw) {
		return "", fmt.Errorf("%w: %q", ErrNotAbsolute, raw)
	}

	// With ".." already rejected, Clean only removes redundant separators and
	// "." elements, so it cannot disagree with the kernel.
	cleaned := filepath.Clean(raw)
	return resolveSymlinks(cleaned)
}

// resolveSymlinks resolves the deepest existing ancestor and re-appends the
// remainder.
//
// EvalSymlinks fails outright on a path that does not exist, but a write to a
// new file is a legitimate call that still has to be canonicalized. Resolving
// the existing prefix catches the case that matters: a symlink inside an allowed
// directory pointing outside it.
func resolveSymlinks(p string) (string, error) {
	remainder := ""
	current := p

	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			if remainder == "" {
				return resolved, nil
			}
			// remainder cannot contain ".." because Path rejected it, so this
			// join cannot escape resolved.
			return filepath.Join(resolved, remainder), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("%w: %w", ErrInvalid, err)
		}

		parent := filepath.Dir(current)
		if parent == current {
			// Reached the root without finding anything that exists. Nothing to
			// resolve, so the cleaned path is already canonical.
			return p, nil
		}
		remainder = filepath.Join(filepath.Base(current), remainder)
		current = parent
	}
}

// URL canonicalizes a URL for comparison: lowercased scheme and host, default
// port removed, path cleaned.
func URL(raw string) (string, error) {
	if raw == "" {
		return "", ErrEmpty
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("%w: URL needs a scheme and host", ErrInvalid)
	}

	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)

	// Strip the port when it is the scheme default, so https://x:443/ and
	// https://x/ do not compare as different origins.
	if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
		u.Host = u.Hostname()
	}

	// u.Path is already percent-decoded by url.Parse, so this catches %2e%2e too.
	if hasTraversal(u.Path) {
		return "", fmt.Errorf("%w: %q", ErrTraversal, raw)
	}
	if u.Path == "" {
		u.Path = "/"
	} else {
		u.Path = path.Clean(u.Path)
	}

	return u.String(), nil
}

// FileURIPath extracts and canonicalizes the filesystem path from a file:// URI.
//
// resources/read addresses resources by URI, and for file URIs the meaningful
// policy surface is the underlying path.
//
// A non-empty authority other than "localhost" is rejected rather than
// discarded: net/url splits it into u.Host and drops it from u.Path, but
// RFC 8089 file-URI parsing is inconsistent across implementations — some
// loose parsers reattach a non-empty authority to the path instead of
// erroring. Silently stripping it here would let mcpguard authorize a
// host-stripped path while whatever actually opens the resource resolves a
// different one, the same parser-differential class this package rejects
// for symlinks. Only an empty authority ("file:///path") or the literal
// "localhost" unambiguously denote the local filesystem.
func FileURIPath(raw string) (string, error) {
	if raw == "" {
		return "", ErrEmpty
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if strings.ToLower(u.Scheme) != "file" {
		return "", fmt.Errorf("%w: expected a file:// URI, got scheme %q", ErrInvalid, u.Scheme)
	}
	if u.Host != "" && strings.ToLower(u.Host) != "localhost" {
		return "", fmt.Errorf("%w: file URI has non-local authority %q", ErrInvalid, u.Host)
	}

	// url.Parse has already percent-decoded u.Path, so Path's traversal check
	// sees "%2e%2e" as "..".
	return Path(u.Path)
}
