package moderation

import (
	"path/filepath"
	"testing"
)

// TestServiceWithoutScannerIsSafe covers a Service built without a scanner -
// the metadata-only shape the handler tests construct, and what main.go would
// produce if the scanner wiring ever changed.
//
// Enabled() dereferenced s.scanner unconditionally, so this panicked. The
// queue processor was also started regardless, which meant a goroutine that
// would reach into dependencies that were never supplied once its ticker
// fired - five minutes after construction, long after any test had finished.
func TestServiceWithoutScannerIsSafe(t *testing.T) {
	s := NewService(nil, nil, t.TempDir(), t.TempDir(), nil, nil)

	if s.Enabled() {
		t.Error("a Service with no scanner reported itself enabled")
	}

	// Must be a no-op rather than a panic.
	s.ProcessUpload("2026/9/photo.jpg", "", "da39a3ee", true)
}

// TestMarkDeletedKeepsScanResults checks that marking a file deleted changes
// status and completion time but preserves what the scanners had found.
func TestMarkDeletedKeepsScanResults(t *testing.T) {
	base := t.TempDir()
	svc := NewService(nil, nil, filepath.Join(base, "meta"), filepath.Join(base, "queue"), nil, nil)

	before := &Metadata{
		Status:     StatusFlagged,
		NSFWResult: &NSFWInfo{Unsafe: true, Confidence: 0.9},
	}
	if err := svc.saveMetadata("2026/1/x.jpg", before); err != nil {
		t.Fatalf("saveMetadata: %v", err)
	}

	if err := svc.MarkDeleted("2026/1/x.jpg"); err != nil {
		t.Fatalf("MarkDeleted: %v", err)
	}
	after, err := svc.GetMetadata("2026/1/x.jpg")
	if err != nil || after == nil {
		t.Fatalf("GetMetadata: %v, %+v", err, after)
	}
	if after.Status != StatusDeleted {
		t.Errorf("status %q, want %q", after.Status, StatusDeleted)
	}
	if after.CompletedAt == nil {
		t.Error("CompletedAt not set")
	}
	if after.NSFWResult == nil || !after.NSFWResult.Unsafe {
		t.Error("NSFW result lost")
	}
}

// TestMarkDeletedWithoutPriorMetadata covers a private upload (never scanned)
// or an upload made while moderation was off: there is no record yet, and
// MarkDeleted creates one rather than failing.
func TestMarkDeletedWithoutPriorMetadata(t *testing.T) {
	base := t.TempDir()
	svc := NewService(nil, nil, filepath.Join(base, "meta"), filepath.Join(base, "queue"), nil, nil)

	if err := svc.MarkDeleted("cli/ACME/2026/1/y.pdf"); err != nil {
		t.Fatalf("MarkDeleted: %v", err)
	}
	meta, err := svc.GetMetadata("cli/ACME/2026/1/y.pdf")
	if err != nil || meta == nil {
		t.Fatalf("GetMetadata: %v, %+v", err, meta)
	}
	if meta.Status != StatusDeleted {
		t.Errorf("status %q, want %q", meta.Status, StatusDeleted)
	}
}

// TestSaveScanResultKeepsDeletedTombstone is the regression test for a scan
// that finishes after the file was deleted: whatever it concluded (clean, an
// error from the second scanner failing to open the vanished file, a flag)
// must not replace the deleted record, and the caller must learn that it did
// not, so it does not queue a retry for a file that is gone.
func TestSaveScanResultKeepsDeletedTombstone(t *testing.T) {
	base := t.TempDir()
	svc := NewService(nil, nil, filepath.Join(base, "meta"), filepath.Join(base, "queue"), nil, nil)
	const path = "2026/1/gone.jpg"

	if err := svc.MarkDeleted(path); err != nil {
		t.Fatalf("MarkDeleted: %v", err)
	}

	errStr := "nsfw scan: open for nsfw scan: file does not exist"
	for name, late := range map[string]*Metadata{
		"clean":   {Status: StatusClean},
		"error":   {Status: StatusError, Error: &errStr},
		"flagged": {Status: StatusFlagged, NSFWResult: &NSFWInfo{Unsafe: true}},
	} {
		if svc.saveScanResult(path, late) {
			t.Errorf("%s: late scan result reported as written over a deleted record", name)
		}
		meta, err := svc.GetMetadata(path)
		if err != nil || meta == nil {
			t.Fatalf("%s: GetMetadata: %v, %+v", name, err, meta)
		}
		if meta.Status != StatusDeleted {
			t.Errorf("%s: tombstone replaced by %q", name, meta.Status)
		}
	}
}

func TestSaveScanResultWritesWhenNotDeleted(t *testing.T) {
	base := t.TempDir()
	svc := NewService(nil, nil, filepath.Join(base, "meta"), filepath.Join(base, "queue"), nil, nil)
	const path = "2026/1/live.jpg"

	if !svc.saveScanResult(path, &Metadata{Status: StatusError}) {
		t.Fatal("first write refused")
	}
	if !svc.saveScanResult(path, &Metadata{Status: StatusClean}) {
		t.Fatal("overwrite of a non-deleted record refused")
	}
	meta, err := svc.GetMetadata(path)
	if err != nil || meta == nil || meta.Status != StatusClean {
		t.Fatalf("expected clean, got %+v (%v)", meta, err)
	}
}

// TestStoredClearsDeletedTombstoneOnly covers the path being stored again
// after a delete: identical bytes under the same filename in the same month
// land on the same relative path, and the tombstone must go. A record with
// any other status belongs to a file that was present (a dedup hit) and is
// kept.
func TestStoredClearsDeletedTombstoneOnly(t *testing.T) {
	base := t.TempDir()
	svc := NewService(nil, nil, filepath.Join(base, "meta"), filepath.Join(base, "queue"), nil, nil)

	if err := svc.MarkDeleted("2026/1/again.jpg"); err != nil {
		t.Fatalf("MarkDeleted: %v", err)
	}
	if err := svc.saveMetadata("2026/1/kept.jpg", &Metadata{Status: StatusFlagged}); err != nil {
		t.Fatalf("saveMetadata: %v", err)
	}

	svc.Stored("2026/1/again.jpg")
	svc.Stored("2026/1/kept.jpg")
	svc.Stored("2026/1/never-seen.jpg") // no record: must be a no-op, not an error

	if meta, err := svc.GetMetadata("2026/1/again.jpg"); err != nil || meta != nil {
		t.Errorf("tombstone survived re-store: %+v (%v)", meta, err)
	}
	if meta, err := svc.GetMetadata("2026/1/kept.jpg"); err != nil || meta == nil || meta.Status != StatusFlagged {
		t.Errorf("non-deleted record was touched: %+v (%v)", meta, err)
	}
}

// TestProcessUploadClearsTombstoneWithoutScanner pins that the clearing
// happens before the Enabled and isPublic checks: a private re-upload is
// never scanned, and a deployment without scanners never scans at all, yet
// both must still shed the tombstone.
func TestProcessUploadClearsTombstoneWithoutScanner(t *testing.T) {
	base := t.TempDir()
	svc := NewService(nil, nil, filepath.Join(base, "meta"), filepath.Join(base, "queue"), nil, nil)
	const private = "cli/ACME/2026/1/again.pdf"

	if err := svc.MarkDeleted(private); err != nil {
		t.Fatalf("MarkDeleted: %v", err)
	}
	svc.ProcessUpload(private, "ACME", "", false)

	if meta, err := svc.GetMetadata(private); err != nil || meta != nil {
		t.Errorf("tombstone survived ProcessUpload: %+v (%v)", meta, err)
	}
}
