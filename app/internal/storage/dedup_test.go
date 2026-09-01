package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDedupIsPerPathNotPerDigest documents that StoreFile deduplicates on the
// whole final path, not on the content digest.
//
// The final name is "{baseName}-{sha1}.{ext}", so the same bytes stored under
// a different uploader filename are a second file carrying the same hash. The
// operator alerts in internal/notifier identify files by that hash and tell
// the recipient the locator may match more than one path; this test is why
// that sentence is there.
func TestDedupIsPerPathNotPerDigest(t *testing.T) {
	base := t.TempDir()
	s := NewStorage(base, 60)

	const content = "identical bytes"

	first, err := s.StoreFile(strings.NewReader(content), "invoice.pdf", "")
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}
	renamed, err := s.StoreFile(strings.NewReader(content), "renamed.pdf", "")
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}
	same, err := s.StoreFile(strings.NewReader(content), "invoice.pdf", "")
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}

	if first.SHA1 != renamed.SHA1 {
		t.Fatalf("same content should hash alike: %s vs %s", first.SHA1, renamed.SHA1)
	}
	if renamed.IsDuplicate {
		t.Error("a different filename is not deduplicated, but was reported as a duplicate")
	}
	if !same.IsDuplicate {
		t.Error("re-storing identical content under the same filename should deduplicate")
	}
	if first.RelativePath == renamed.RelativePath {
		t.Error("expected two distinct paths for the two filenames")
	}

	var matches []string
	err = filepath.Walk(base, func(p string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !fi.IsDir() && strings.Contains(p, first.SHA1) {
			matches = append(matches, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(matches) != 2 {
		t.Errorf("expected the hash to match 2 stored files, got %d: %v", len(matches), matches)
	}
}
