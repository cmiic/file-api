package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStoreFileRejectsUnsafeClientCode covers the validation StoreFile does on
// its own arguments. Both callers validate the client code before handing it
// over, but StoreFile is exported and its signature promises nothing, so the
// check that turns the value into a path component lives next to that use.
func TestStoreFileRejectsUnsafeClientCode(t *testing.T) {
	s, err := NewStorage(t.TempDir(), 60)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	t.Cleanup(func() { s.Close() })

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
	s, err := NewStorage(base, 60)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	t.Cleanup(func() { s.Close() })

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
	s, err := NewStorage(t.TempDir(), 60)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	t.Cleanup(func() { s.Close() })

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

// TestNewStorageCreatesMissingBase pins that NewStorage provisions the
// directory it roots.
//
// os.OpenRoot requires an existing directory, so if this were left to the
// caller the service would fail at startup on any deployment whose BASE_PATH
// is not pre-created - and only depending on which line ran first.
func TestNewStorageCreatesMissingBase(t *testing.T) {
	fresh := filepath.Join(t.TempDir(), "does", "not", "exist", "yet")

	s, err := NewStorage(fresh, 60)
	if err != nil {
		t.Fatalf("NewStorage on a missing base: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	if _, err := s.StoreFile(strings.NewReader("payload"), "a.txt", ""); err != nil {
		t.Fatalf("StoreFile into a freshly created base: %v", err)
	}
}

// TestStorageRootContainsEscapes covers what os.Root buys over validating the
// string first: containment is enforced when the file is opened, so it holds
// for names no amount of inspection would catch.
func TestStorageRootContainsEscapes(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(filepath.Dir(base), "outside-"+filepath.Base(base)+".txt")
	if err := os.WriteFile(outside, []byte("SECRET"), 0o644); err != nil {
		t.Fatalf("plant file: %v", err)
	}
	t.Cleanup(func() { os.Remove(outside) })

	s, err := NewStorage(base, 60)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	// A stored file opens normally.
	info, err := s.StoreFile(strings.NewReader("payload"), "photo.jpg", "ACME")
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}
	f, err := s.Open(info.RelativePath)
	if err != nil {
		t.Fatalf("Open(%q): %v", info.RelativePath, err)
	}
	f.Close()

	// Traversal is refused by the root, not by a prior string check.
	for _, name := range []string{
		"../" + filepath.Base(outside),
		"../../etc/passwd",
		"cli/../../" + filepath.Base(outside),
	} {
		if f, err := s.Open(name); err == nil {
			f.Close()
			t.Errorf("Open(%q) succeeded; the root did not contain it", name)
		}
	}

	// The case a string check cannot see: a symlink inside the root pointing
	// out of it. The name is perfectly ordinary; only the open can tell.
	link := filepath.Join(base, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if f, err := s.Open("escape"); err == nil {
		buf := make([]byte, 6)
		n, _ := f.Read(buf)
		f.Close()
		t.Errorf("Open followed a symlink out of the root and read %q", string(buf[:n]))
	}
}
