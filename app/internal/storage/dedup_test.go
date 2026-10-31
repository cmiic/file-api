package storage

import (
	"crypto/sha1"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	s, err := NewStorage(base, 60)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	t.Cleanup(func() { s.Close() })

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

// TestDedupRefusesDifferentBytesUnderTheSameName covers the dedup check on
// content. The final name encodes the SHA1, so a file already there normally
// holds the same bytes - but SHA1 collisions are constructible, and a stored
// file can be damaged. Either way the incoming bytes must not be reported as
// stored when what the path serves is something else. The existing file is
// planted directly, in place of a real collision.
func TestDedupRefusesDifferentBytesUnderTheSameName(t *testing.T) {
	base := t.TempDir()
	s, err := NewStorage(base, 60)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	const content = "the bytes being uploaded"
	sum := sha1.Sum([]byte(content))
	dir := filepath.Join(base, GenerateStorageDir(""))
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	planted := filepath.Join(dir, "photo-"+hex.EncodeToString(sum[:])+".jpg")
	if err := os.WriteFile(planted, []byte("the bytes being uploaded!"), 0644); err != nil {
		t.Fatalf("plant: %v", err)
	}

	info, err := s.StoreFile(strings.NewReader(content), "photo.jpg", "")
	if err == nil {
		t.Fatalf("expected a refusal, got %+v", info)
	}
	if got, _ := os.ReadFile(planted); string(got) != "the bytes being uploaded!" {
		t.Errorf("the stored file was replaced: %q", got)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temp file left behind: %d entries in %s", len(entries), dir)
	}
}

// TestDedupReportsTheStoredSize pins that a deduplicated response describes
// the stored file rather than the upload: with identical bytes the two agree,
// and the content check above is what keeps it that way.
func TestDedupReportsTheStoredSize(t *testing.T) {
	s, err := NewStorage(t.TempDir(), 60)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	first, err := s.StoreFile(strings.NewReader("same bytes"), "a.bin", "")
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}
	again, err := s.StoreFile(strings.NewReader("same bytes"), "a.bin", "")
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}
	if !again.IsDuplicate || again.Size != first.Size || again.RelativePath != first.RelativePath {
		t.Errorf("dedup response %+v does not describe the stored file %+v", again, first)
	}
}

// TestDedupKeepsFirstUploadMtime pins the property the DELETE endpoint's age
// window depends on: a deduplicated re-upload leaves the existing file
// untouched, so its mtime stays the time of the first upload rather than
// being refreshed by every later identical upload.
func TestDedupKeepsFirstUploadMtime(t *testing.T) {
	base := t.TempDir()
	s, err := NewStorage(base, 60)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	first, err := s.StoreFile(strings.NewReader("same bytes"), "photo.jpg", "")
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}
	abs := filepath.Join(base, first.RelativePath)
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(abs, old, old); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	again, err := s.StoreFile(strings.NewReader("same bytes"), "photo.jpg", "")
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}
	if !again.IsDuplicate || again.RelativePath != first.RelativePath {
		t.Fatalf("expected a dedup hit on %q, got %+v", first.RelativePath, again)
	}

	info, err := s.Stat(first.RelativePath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.ModTime().After(old.Add(time.Second)) {
		t.Errorf("dedup refreshed mtime to %s; expected it to stay near %s", info.ModTime(), old)
	}
}
