package moderation

import "testing"

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
