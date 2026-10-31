package moderation

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"file-api/internal/scanner"
	"file-api/internal/storage"
)

// recordedAlerts captures the alerts a scan raises instead of mailing them.
type recordedAlerts struct {
	mu      sync.Mutex
	malware []string // "sha1|scope|name"
	nsfw    []string // "sha1|scope|classes"
}

func (r *recordedAlerts) MalwareAlert(sha1, scope, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.malware = append(r.malware, sha1+"|"+scope+"|"+name)
	return nil
}

func (r *recordedAlerts) NSFWAlert(sha1, scope string, _ float64, classes []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nsfw = append(r.nsfw, sha1+"|"+scope+"|"+strings.Join(classes, ","))
	return nil
}

// fakeScanner answers one scanner endpoint and counts its calls. A nil
// handler leaves that scanner disabled.
type fakeScanner struct {
	calls   atomic.Int32
	handler http.HandlerFunc
}

func (f *fakeScanner) url(t *testing.T) string {
	if f == nil || f.handler == nil {
		return ""
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		f.handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func answer(v any) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}
}

func failWith(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "scanner down", status) }
}

var (
	cleanMalware = scanner.MalwareScanResult{Infected: false, ScanTimeMS: 1}
	safeNSFW     = scanner.NSFWResult{Unsafe: false, Confidence: 0.1}
)

// scanFixture is a Service with real storage, fake scanners and recorded
// alerts, and one stored public file to scan.
type scanFixture struct {
	svc       *Service
	store     *storage.Storage
	alerts    *recordedAlerts
	queuePath string
	path      string
	sha1      string
}

func newScanFixture(t *testing.T, malware, nsfw *fakeScanner) *scanFixture {
	t.Helper()
	base := t.TempDir()
	store, err := storage.NewStorage(filepath.Join(base, "files"), 60)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	info, err := store.StoreFile(strings.NewReader("uploaded bytes"), "upload.jpg", "")
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}

	queuePath := filepath.Join(base, "queue")
	// Built by hand rather than with NewService, so no background queue
	// processor runs alongside the test.
	svc := &Service{
		scanner:    scanner.NewClient(malware.url(t), nsfw.url(t), 5000),
		metaPath:   filepath.Join(base, "meta"),
		queuePath:  queuePath,
		deleteFile: store.DeleteFile,
		openFile:   store.Open,
		processing: make(map[string]bool),
	}
	alerts := &recordedAlerts{}
	svc.notifier = alerts
	if err := os.MkdirAll(queuePath, 0755); err != nil {
		t.Fatalf("mkdir queue: %v", err)
	}
	return &scanFixture{svc: svc, store: store, alerts: alerts, queuePath: queuePath, path: info.RelativePath, sha1: info.SHA1}
}

func (f *scanFixture) scan() { f.svc.scan(f.path, "", f.sha1, true) }

func (f *scanFixture) meta(t *testing.T) *Metadata {
	t.Helper()
	m, err := f.svc.GetMetadata(f.path)
	if err != nil || m == nil {
		t.Fatalf("GetMetadata: %v, %+v", err, m)
	}
	return m
}

func (f *scanFixture) queued() bool {
	_, err := os.Stat(filepath.Join(f.queuePath, filepath.Base(f.path)+".json"))
	return err == nil
}

func TestScanClean(t *testing.T) {
	malware, nsfw := &fakeScanner{handler: answer(cleanMalware)}, &fakeScanner{handler: answer(safeNSFW)}
	f := newScanFixture(t, malware, nsfw)
	f.scan()

	m := f.meta(t)
	if m.Status != StatusClean || m.CompletedAt == nil || m.MalwareResult == nil || m.NSFWResult == nil {
		t.Errorf("unexpected record %+v", m)
	}
	if malware.calls.Load() != 1 || nsfw.calls.Load() != 1 {
		t.Errorf("scanner calls malware=%d nsfw=%d, want 1 each", malware.calls.Load(), nsfw.calls.Load())
	}
	if len(f.alerts.malware)+len(f.alerts.nsfw) != 0 || f.queued() || !f.store.FileExists(f.path) {
		t.Errorf("a clean file must stay, unalerted and unqueued: alerts=%+v queued=%v", f.alerts, f.queued())
	}
}

func TestScanInfectedDeletesRecordsAndAlerts(t *testing.T) {
	name := "Eicar-Test-Signature"
	malware := &fakeScanner{handler: answer(scanner.MalwareScanResult{Infected: true, MalwareName: &name})}
	nsfw := &fakeScanner{handler: answer(safeNSFW)}
	f := newScanFixture(t, malware, nsfw)
	f.scan()

	if f.store.FileExists(f.path) {
		t.Error("infected file still stored")
	}
	if m := f.meta(t); m.Status != StatusMalware || m.CompletedAt == nil || m.MalwareResult == nil || !m.MalwareResult.Infected {
		t.Errorf("unexpected record %+v", m)
	}
	if want := f.sha1 + "|public|" + name; len(f.alerts.malware) != 1 || f.alerts.malware[0] != want {
		t.Errorf("malware alerts %v, want [%s]", f.alerts.malware, want)
	}
	if nsfw.calls.Load() != 0 {
		t.Error("an infected file must not go on to the media screener")
	}
}

func TestScanInfectedWithoutNameAlertsUnknown(t *testing.T) {
	f := newScanFixture(t, &fakeScanner{handler: answer(scanner.MalwareScanResult{Infected: true})}, nil)
	f.scan()

	if len(f.alerts.malware) != 1 || !strings.HasSuffix(f.alerts.malware[0], "|unknown") {
		t.Errorf("malware alerts %v, want one naming unknown", f.alerts.malware)
	}
}

func TestScanFlaggedKeepsFileRecordsAndAlerts(t *testing.T) {
	nsfw := &fakeScanner{handler: answer(scanner.NSFWResult{Unsafe: true, Confidence: 0.9, DetectedClasses: []string{"A", "B"}})}
	f := newScanFixture(t, &fakeScanner{handler: answer(cleanMalware)}, nsfw)
	f.scan()

	if !f.store.FileExists(f.path) {
		t.Error("a flagged file is kept for review, not deleted")
	}
	if m := f.meta(t); m.Status != StatusFlagged || m.CompletedAt == nil || m.NSFWResult == nil || !m.NSFWResult.Unsafe {
		t.Errorf("unexpected record %+v", m)
	}
	if want := f.sha1 + "|public|A,B"; len(f.alerts.nsfw) != 1 || f.alerts.nsfw[0] != want {
		t.Errorf("nsfw alerts %v, want [%s]", f.alerts.nsfw, want)
	}
}

func TestScanMalwareScannerErrorQueuesRetryAndSkipsScreener(t *testing.T) {
	nsfw := &fakeScanner{handler: answer(safeNSFW)}
	f := newScanFixture(t, &fakeScanner{handler: failWith(http.StatusServiceUnavailable)}, nsfw)
	f.scan()

	m := f.meta(t)
	if m.Status != StatusError || m.Error == nil || !strings.HasPrefix(*m.Error, "malware scan:") {
		t.Errorf("unexpected record %+v", m)
	}
	if !f.queued() {
		t.Error("a failed scan must be queued for retry")
	}
	if nsfw.calls.Load() != 0 {
		t.Error("after a malware scan error the media screener is not asked")
	}
}

func TestScanScreenerErrorQueuesRetry(t *testing.T) {
	f := newScanFixture(t, &fakeScanner{handler: answer(cleanMalware)}, &fakeScanner{handler: failWith(http.StatusInternalServerError)})
	f.scan()

	if m := f.meta(t); m.Status != StatusError || m.Error == nil || !strings.HasPrefix(*m.Error, "nsfw scan:") {
		t.Errorf("unexpected record %+v", m)
	}
	if !f.queued() {
		t.Error("a failed scan must be queued for retry")
	}
}

func TestScanFileDeletedMidScanKeepsTombstoneAndQueuesNothing(t *testing.T) {
	// The file is deleted through the DELETE endpoint while the malware scan
	// runs; the media screener then cannot open it. Whatever the scan
	// concludes must not replace the deleted record or queue a retry.
	var f *scanFixture
	malware := &fakeScanner{handler: func(w http.ResponseWriter, r *http.Request) {
		if err := f.store.DeleteFile(f.path); err != nil {
			t.Errorf("DeleteFile: %v", err)
		}
		if err := f.svc.MarkDeleted(f.path); err != nil {
			t.Errorf("MarkDeleted: %v", err)
		}
		answer(cleanMalware)(w, r)
	}}
	f = newScanFixture(t, malware, &fakeScanner{handler: answer(safeNSFW)})
	f.scan()

	if m := f.meta(t); m.Status != StatusDeleted {
		t.Errorf("deleted record replaced by %q", m.Status)
	}
	if f.queued() {
		t.Error("a retry was queued for a file that is gone")
	}
}

func TestScanRecoversMissingHashForAlerts(t *testing.T) {
	name := "X"
	f := newScanFixture(t, &fakeScanner{handler: answer(scanner.MalwareScanResult{Infected: true, MalwareName: &name})}, nil)
	f.svc.scan(f.path, "", "", true) // a queue entry written before alerts carried hashes

	sum := sha1.Sum([]byte("uploaded bytes"))
	if want := hex.EncodeToString(sum[:]) + "|public|X"; len(f.alerts.malware) != 1 || f.alerts.malware[0] != want {
		t.Errorf("malware alerts %v, want [%s]", f.alerts.malware, want)
	}
}

func TestScanLeavesAFileAlreadyBeingScannedToThatScan(t *testing.T) {
	malware := &fakeScanner{handler: answer(cleanMalware)}
	f := newScanFixture(t, malware, nil)
	f.svc.processing[f.path] = true
	f.scan()

	if malware.calls.Load() != 0 {
		t.Error("a second scan of the same path ran concurrently")
	}
	next, ok := f.svc.releaseOrNext(f.path)
	if !ok || next.path != f.path || next.sha1 != f.sha1 || !next.isPublic {
		t.Errorf("the running scan must find the job left for it, got %+v, %v", next, ok)
	}
	if _, ok := f.svc.releaseOrNext(f.path); ok || f.svc.processing[f.path] {
		t.Error("after the last job the claim must be released")
	}
}

// TestScanRescansAFileStoredAgainMidScan is the race that left malware
// served: the first scan deletes the file as infected, an identical upload
// recreates the path before the scan releases its claim, and that upload's
// scan request finds the path claimed. The recreated file must be scanned -
// and deleted - too.
func TestScanRescansAFileStoredAgainMidScan(t *testing.T) {
	name := "Eicar-Test-Signature"
	malware := &fakeScanner{handler: answer(scanner.MalwareScanResult{Infected: true, MalwareName: &name})}
	f := newScanFixture(t, malware, nil)
	restored := false
	f.svc.deleteFile = func(p string) error {
		if err := f.store.DeleteFile(p); err != nil {
			return err
		}
		if !restored {
			restored = true
			// The concurrent upload: identical bytes under the same name
			// land on the same path, and its scan finds the path claimed.
			if _, err := f.store.StoreFile(strings.NewReader("uploaded bytes"), "upload.jpg", ""); err != nil {
				t.Fatalf("re-store: %v", err)
			}
			f.scan()
		}
		return nil
	}
	f.scan()

	if malware.calls.Load() != 2 {
		t.Errorf("scanner calls %d, want 2: the re-stored file must be scanned again", malware.calls.Load())
	}
	if f.store.FileExists(f.path) {
		t.Error("the re-stored malware is still stored")
	}
	if m := f.meta(t); m.Status != StatusMalware {
		t.Errorf("record %q, want malware", m.Status)
	}
	if f.svc.processing[f.path] || len(f.svc.pending) != 0 {
		t.Error("claim or pending job left behind")
	}
}

// TestScanSkipsFollowUpForAFileDeletedAsMalware is the other order: the
// identical upload is deduplicated against the file while it is being
// scanned, and the scan then deletes it as malware. The follow-up has nothing
// to scan and must not replace the malware record with an open error.
func TestScanSkipsFollowUpForAFileDeletedAsMalware(t *testing.T) {
	var f *scanFixture
	name := "Eicar-Test-Signature"
	malware := &fakeScanner{handler: func(w http.ResponseWriter, r *http.Request) {
		f.scan() // the deduplicated upload's scan request, while the scanner is busy
		answer(scanner.MalwareScanResult{Infected: true, MalwareName: &name})(w, r)
	}}
	f = newScanFixture(t, malware, nil)
	f.scan()

	if malware.calls.Load() != 1 {
		t.Errorf("scanner calls %d, want 1: there is no file left to scan", malware.calls.Load())
	}
	if m := f.meta(t); m.Status != StatusMalware {
		t.Errorf("record %q, want the malware verdict kept", m.Status)
	}
	if f.queued() {
		t.Error("a retry was queued for a file that is gone")
	}
	if f.svc.processing[f.path] || len(f.svc.pending) != 0 {
		t.Error("claim or pending job left behind")
	}
}

func TestScanWithOnlyOneScannerEnabled(t *testing.T) {
	f := newScanFixture(t, nil, &fakeScanner{handler: answer(safeNSFW)})
	f.scan()

	if m := f.meta(t); m.Status != StatusClean || m.MalwareResult != nil {
		t.Errorf("unexpected record %+v", m)
	}
}

func TestScanInfectedStillRecordsAndAlertsWhenDeleteFails(t *testing.T) {
	name := "X"
	f := newScanFixture(t, &fakeScanner{handler: answer(scanner.MalwareScanResult{Infected: true, MalwareName: &name})}, nil)
	f.svc.deleteFile = func(string) error { return errors.New("read-only file system") }
	f.scan()

	if m := f.meta(t); m.Status != StatusMalware {
		t.Errorf("record %q, want malware even though the delete failed", m.Status)
	}
	if len(f.alerts.malware) != 1 {
		t.Errorf("malware alerts %v, want one", f.alerts.malware)
	}
}

func TestEnsureSHA1(t *testing.T) {
	f := newScanFixture(t, nil, nil)
	if got := f.svc.ensureSHA1(f.path, "given"); got != "given" {
		t.Errorf("a given hash is kept, got %q", got)
	}
	if got := f.svc.ensureSHA1(f.path, ""); got != f.sha1 {
		t.Errorf("recomputed %q, want %q", got, f.sha1)
	}
	if got := f.svc.ensureSHA1("2026/1/missing.jpg", ""); got != "" {
		t.Errorf("a file that cannot be opened leaves the hash empty, got %q", got)
	}
}
