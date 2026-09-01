package storage

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestStoreFileRejectsUnsafeClientCode covers the validation StoreFile does on
// its own arguments. Both callers validate the client code before handing it
// over, but StoreFile is exported and its signature promises nothing, so the
// check that turns the value into a path component lives next to that use.
func TestStoreFileRejectsUnsafeClientCode(t *testing.T) {
	s := NewStorage(t.TempDir(), 60)

	unsafe := []struct {
		name string
		code string
	}{
		{"traversal", ".."},
		{"traversal segment", "../etc"},
		{"traversal encoded in a longer code", "acme/../../etc"},
		{"slash", "acme/sub"},
		{"backslash", `acme\sub`},
		{"leading dot", ".acme"},
		{"newline", "acme\nx"},
		{"space", "acme corp"},
		{"too long", strings.Repeat("a", 17)},
	}

	for _, tt := range unsafe {
		t.Run(tt.name, func(t *testing.T) {
			info, err := s.StoreFile(strings.NewReader("payload"), "photo.jpg", tt.code)
			if err == nil {
				t.Fatalf("expected an error for client code %q, got path %q", tt.code, info.RelativePath)
			}
		})
	}
}

func TestStoreFileAcceptsValidClientCode(t *testing.T) {
	base := t.TempDir()
	s := NewStorage(base, 60)

	info, err := s.StoreFile(strings.NewReader("payload"), "photo.jpg", "ACME")
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}
	// Compare on a slash-normalised path with a trailing separator, so this
	// asserts a whole path segment: a bare "cli/ACME" prefix would also accept
	// "cli/ACMEX/...".
	if !strings.HasPrefix(filepath.ToSlash(info.RelativePath), "cli/ACME/") {
		t.Errorf("expected a cli/ACME/ prefix, got %q", info.RelativePath)
	}
	if !s.FileExists(info.RelativePath) {
		t.Errorf("stored file not found at %q", info.RelativePath)
	}
}

// A public upload passes an empty client code, which must stay allowed.
func TestStoreFileAllowsEmptyClientCode(t *testing.T) {
	s := NewStorage(t.TempDir(), 60)

	// The filename deliberately contains "cli" - a substring check would call
	// this a private upload.
	info, err := s.StoreFile(strings.NewReader("payload"), "client-photo.jpg", "")
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}
	// A prefix check, not a substring one: "cli" can legitimately occur inside
	// a filename, and that must not fail this test.
	if strings.HasPrefix(filepath.ToSlash(info.RelativePath), "cli/") {
		t.Errorf("public upload should not land under cli/, got %q", info.RelativePath)
	}
}

// The stored path must stay inside the base directory for every accepted input.
func TestStoreFileStaysInsideBase(t *testing.T) {
	base := t.TempDir()
	s := NewStorage(base, 60)

	info, err := s.StoreFile(strings.NewReader("payload"), "photo.jpg", "ACME")
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}
	full := s.GetFilePath(info.RelativePath)
	if !strings.HasPrefix(filepath.Clean(full), filepath.Clean(base)+string(filepath.Separator)) {
		t.Errorf("stored path escaped the base directory: %q not under %q", full, base)
	}
}
