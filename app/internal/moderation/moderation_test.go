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
