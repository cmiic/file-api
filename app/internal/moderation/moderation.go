// Package moderation orchestrates file scanning and metadata management.
package moderation

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"file-api/internal/notifier"
	"file-api/internal/scanner"
)

// Status represents the scan status of a file.
type Status string

const (
	StatusPending Status = "pending"
	StatusClean   Status = "clean"
	StatusFlagged Status = "flagged"
	StatusMalware Status = "malware"
	StatusError   Status = "error"
	// StatusDeleted marks a file removed through the DELETE endpoint. Written
	// so that a consumer polling for a verdict before persisting its own
	// record sees that the file is gone rather than a stale "clean".
	StatusDeleted Status = "deleted"
)

// Metadata contains scan results for a file.
type Metadata struct {
	Status        Status       `json:"status"`
	RequestedAt   time.Time    `json:"requested_at"`
	CompletedAt   *time.Time   `json:"completed_at,omitempty"`
	MalwareResult *MalwareInfo `json:"malware,omitempty"`
	NSFWResult    *NSFWInfo    `json:"nsfw,omitempty"`
	Error         *string      `json:"error,omitempty"`
}

// MalwareInfo contains malware scan details.
type MalwareInfo struct {
	Infected    bool    `json:"infected"`
	MalwareName *string `json:"malware_name,omitempty"`
	ScanTimeMS  float64 `json:"scan_time_ms"`
}

// NSFWInfo contains NSFW scan details.
type NSFWInfo struct {
	Unsafe          bool     `json:"unsafe"`
	Confidence      float64  `json:"confidence"`
	DetectedClasses []string `json:"detected_classes,omitempty"`
	ScanTimeMS      float64  `json:"scan_time_ms,omitempty"`
}

// QueueEntry represents a scan job in the retry queue.
type QueueEntry struct {
	RelativePath string `json:"relative_path"`
	// AbsolutePath is retained so queue files written by earlier versions
	// still unmarshal. Nothing reads it: scanning opens through the storage
	// root by relative path now.
	AbsolutePath string    `json:"abs_path,omitempty"`
	ClientCode   string    `json:"client_code"`
	SHA1         string    `json:"sha1,omitempty"`
	IsPublic     bool      `json:"is_public"`
	QueuedAt     time.Time `json:"queued_at"`
	Retries      int       `json:"retries"`
	LastError    string    `json:"last_error,omitempty"`
}

// fileSHA1 hashes the stored file. Used when a scan job carries no hash of its
// own, which is the case for queue entries written before alerts identified
// files by hash: their JSON has no sha1 field, so it unmarshals empty.
//
// Recomputed from content rather than parsed out of the stored filename. The
// filename would be the cheaper source - it ends in "-{sha1}.{ext}" - but it
// is the uploader's, and pulling the hash back out of it would put that value
// on the path to the alert again, which is the whole thing this indirection
// exists to avoid.
func fileSHA1(r io.Reader) (string, error) {
	h := sha1.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// scopeOf renders the public/private distinction for an operator alert. It is
// derived from a bool rather than from any request value, so it carries no
// uploader-supplied text into the message.
func scopeOf(isPublic bool) string {
	if isPublic {
		return "public"
	}
	return "private (client upload)"
}

// alerter is what the scan needs from the notifier: one alert per verdict that
// needs a human. An interface rather than *notifier.Notifier so tests can
// record the alerts a scan raises.
type alerter interface {
	MalwareAlert(sha1, scope, malwareName string) error
	NSFWAlert(sha1, scope string, confidence float64, classes []string) error
}

// noAlerts stands in when no notifier is supplied, so a Service built without
// one never dereferences a nil pointer.
type noAlerts struct{}

func (noAlerts) MalwareAlert(string, string, string) error         { return nil }
func (noAlerts) NSFWAlert(string, string, float64, []string) error { return nil }

// DeleteFunc is a function type for deleting files.
type DeleteFunc func(relativePath string) error

// OpenFunc opens a stored file by its path relative to the storage root.
// Injected the same way DeleteFunc is, so this package never holds an
// absolute path and never opens one itself - the open happens inside the
// storage root, which is what keeps it contained.
type OpenFunc func(relativePath string) (*os.File, error)

// Service orchestrates scanning, metadata storage, and notifications.
type Service struct {
	scanner    *scanner.Client
	notifier   alerter
	metaPath   string
	queuePath  string
	deleteFile DeleteFunc
	openFile   OpenFunc

	// Background processing
	mu         sync.Mutex
	processing map[string]bool // tracks files currently being processed

	// metaMu serializes every read-then-write of a metadata record: scan
	// results, the deleted tombstone, and its removal on re-upload. Without
	// it a scan finishing concurrently with a DELETE could read "no record",
	// then write "clean" over the tombstone the handler had just written.
	metaMu sync.Mutex
}

// NewService creates a new moderation service.
func NewService(
	scannerClient *scanner.Client,
	notifier *notifier.Notifier,
	metaPath, queuePath string,
	deleteFile DeleteFunc,
	openFile OpenFunc,
) *Service {
	// Ensure directories exist
	if err := os.MkdirAll(metaPath, 0755); err != nil {
		log.Printf("Warning: failed to create scan-meta directory: %v", err)
	}
	if err := os.MkdirAll(queuePath, 0755); err != nil {
		log.Printf("Warning: failed to create scan-queue directory: %v", err)
	}

	s := &Service{
		scanner:    scannerClient,
		metaPath:   metaPath,
		queuePath:  queuePath,
		deleteFile: deleteFile,
		openFile:   openFile,
		processing: make(map[string]bool),
	}
	// A nil *notifier.Notifier stored in the interface would be a non-nil
	// interface holding a nil pointer, so it is checked before assignment.
	if notifier != nil {
		s.notifier = notifier
	} else {
		s.notifier = noAlerts{}
	}

	// Start the background queue processor only when there is something to
	// retry with. A Service built without a scanner has nothing to do, and
	// starting the goroutine regardless means it eventually calls into
	// dependencies that were never supplied.
	if s.Enabled() {
		go s.processQueue()
	}

	return s
}

// Enabled returns true if any scanning is configured.
func (s *Service) Enabled() bool {
	// No scanner means not enabled - that is the honest answer, and it keeps
	// a partially constructed Service (metadata-only, as the handler tests
	// build) from panicking here rather than reporting what it can do.
	if s.scanner == nil {
		return false
	}
	return s.scanner.MalwareEnabled() || s.scanner.NSFWEnabled()
}

// ProcessUpload triggers async scanning for a newly uploaded file.
// This is non-blocking and runs in a goroutine.
func (s *Service) ProcessUpload(relativePath, clientCode, sha1 string, isPublic bool) {
	// Before anything else, and regardless of whether scanning runs: the
	// path may have been deleted and is now stored again (identical bytes
	// under the same filename in the same month land on the same path), and
	// the tombstone from that deletion must not outlive the file's return.
	s.Stored(relativePath)

	if !s.Enabled() {
		return
	}

	// Only scan public files automatically
	if !isPublic {
		return
	}

	go s.scan(relativePath, clientCode, sha1, isPublic)
}

// scanJob is one file to scan and what an alert about it may say.
type scanJob struct {
	path       string
	clientCode string
	sha1       string
	isPublic   bool
}

// scan runs the configured scanners over one stored file and records the
// verdict (called async). Malware goes first: it is the faster check and the
// one that removes the file. The media screener runs only on a file the
// malware scan cleared. A scanner error records the failure and queues a
// retry; a file already being scanned is left to that scan.
func (s *Service) scan(relativePath, clientCode, sha1 string, isPublic bool) {
	if !s.claim(relativePath) {
		return
	}
	defer s.release(relativePath)

	job := scanJob{path: relativePath, clientCode: clientCode, isPublic: isPublic}
	job.sha1 = s.ensureSHA1(relativePath, sha1)

	log.Printf("Starting scan for: %q", relativePath)
	meta := &Metadata{Status: StatusPending, RequestedAt: time.Now()}

	if done, err := s.checkMalware(job, meta); done || err != nil {
		if err != nil {
			s.recordScanError(job, meta, err)
		}
		return
	}
	if done, err := s.checkNSFW(job, meta); done || err != nil {
		if err != nil {
			s.recordScanError(job, meta, err)
		}
		return
	}
	s.recordClean(job, meta)
}

// claim marks relativePath as being scanned, or reports that another scan of
// it is already running.
func (s *Service) claim(relativePath string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.processing[relativePath] {
		return false
	}
	s.processing[relativePath] = true
	return true
}

func (s *Service) release(relativePath string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.processing, relativePath)
}

// ensureSHA1 returns sha1, or recomputes it from the stored file when it is
// empty. A job queued before alerts carried hashes has none, and without this
// an alert raised on retry would carry an empty hash and a locator matching
// every stored file. A failure is logged and leaves the hash empty.
func (s *Service) ensureSHA1(relativePath, sha1 string) string {
	if sha1 != "" {
		return sha1
	}
	f, err := s.openFile(relativePath)
	if err != nil {
		log.Printf("Could not open %q to hash it for alerting: %v", relativePath, err)
		return ""
	}
	defer f.Close()
	h, err := fileSHA1(f)
	if err != nil {
		log.Printf("Could not hash %q for alerting: %v", relativePath, err)
		return ""
	}
	return h
}

// checkMalware runs the malware scan, if configured, and adds its result to
// meta. done reports a final verdict: the file was infected and has been
// deleted, recorded and alerted.
func (s *Service) checkMalware(job scanJob, meta *Metadata) (done bool, err error) {
	if !s.scanner.MalwareEnabled() {
		return false, nil
	}
	result, err := s.scanMalware(job.path)
	if err != nil {
		log.Printf("Malware scan failed for %q: %v", job.path, err)
		return false, fmt.Errorf("malware scan: %w", err)
	}
	if result == nil {
		return false, nil
	}
	meta.MalwareResult = &MalwareInfo{
		Infected:    result.Infected,
		MalwareName: result.MalwareName,
		ScanTimeMS:  result.ScanTimeMS,
	}
	if !result.Infected {
		return false, nil
	}
	s.handleInfected(job, meta, malwareName(result))
	return true, nil
}

// malwareName is the scanner's name for what it found, or "unknown": the name
// is optional in the scanner's response.
func malwareName(result *scanner.MalwareScanResult) string {
	if result.MalwareName == nil {
		return "unknown"
	}
	return *result.MalwareName
}

// handleInfected deletes an infected file immediately, records the verdict
// and alerts the operators.
func (s *Service) handleInfected(job scanJob, meta *Metadata, name string) {
	complete(meta, StatusMalware)
	if err := s.deleteFile(job.path); err != nil {
		log.Printf("Failed to delete malware file %q: %v", job.path, err)
	} else {
		log.Printf("Deleted malware file: %q (%q)", job.path, name)
	}
	s.saveScanResult(job.path, meta)
	s.notifier.MalwareAlert(job.sha1, scopeOf(job.isPublic), name)
}

// checkNSFW runs the media screener, if configured, and adds its result to
// meta. done reports a final verdict: the file was flagged, recorded and
// alerted. A flagged file is kept for review, not deleted.
func (s *Service) checkNSFW(job scanJob, meta *Metadata) (done bool, err error) {
	if !s.scanner.NSFWEnabled() {
		return false, nil
	}
	result, err := s.scanNSFW(job.path)
	if err != nil {
		log.Printf("NSFW scan failed for %q: %v", job.path, err)
		return false, fmt.Errorf("nsfw scan: %w", err)
	}
	if result == nil {
		return false, nil
	}
	meta.NSFWResult = &NSFWInfo{
		Unsafe:          result.Unsafe,
		Confidence:      result.Confidence,
		DetectedClasses: result.DetectedClasses,
	}
	if !result.Unsafe {
		return false, nil
	}
	complete(meta, StatusFlagged)
	log.Printf("NSFW content flagged: %q (confidence: %.2f)", job.path, result.Confidence)
	s.saveScanResult(job.path, meta)
	s.notifier.NSFWAlert(job.sha1, scopeOf(job.isPublic), result.Confidence, result.DetectedClasses)
	return true, nil
}

// recordScanError records a failed scan and queues it for retry. A failure
// caused by the file having been deleted mid-scan is not retried: the record
// is already the deleted one and saveScanResult refuses to replace it.
func (s *Service) recordScanError(job scanJob, meta *Metadata, scanErr error) {
	errStr := scanErr.Error()
	meta.Status = StatusError
	meta.Error = &errStr
	if s.saveScanResult(job.path, meta) {
		s.queueForRetry(job.path, job.clientCode, job.sha1, job.isPublic, errStr)
	}
}

func (s *Service) recordClean(job scanJob, meta *Metadata) {
	complete(meta, StatusClean)
	if s.saveScanResult(job.path, meta) {
		log.Printf("Scan complete (clean): %q", job.path)
	}
}

// complete sets the final status and its completion time.
func complete(meta *Metadata, status Status) {
	now := time.Now()
	meta.Status = status
	meta.CompletedAt = &now
}

// saveScanResult writes a scan outcome unless the file was deleted while the
// scan ran. The scanners hold the file open, so a scan can finish, flag, or
// fail on bytes that are no longer stored; whatever it concluded must not
// replace the deleted record MarkDeleted left, or a consumer polling for a
// verdict would be told "clean" (or "error", and see a retry queued) about a
// file that is gone. Returns whether the write happened.
func (s *Service) saveScanResult(relativePath string, meta *Metadata) bool {
	s.metaMu.Lock()
	defer s.metaMu.Unlock()

	existing, err := s.GetMetadata(relativePath)
	if err != nil {
		log.Printf("Could not read existing metadata for %q, writing scan result anyway: %v", relativePath, err)
	} else if existing != nil && existing.Status == StatusDeleted {
		log.Printf("Scan finished after deletion, keeping deleted record: %q", relativePath)
		return false
	}
	if err := s.saveMetadata(relativePath, meta); err != nil {
		log.Printf("Failed to save metadata for %q: %v", relativePath, err)
	}
	return true
}

// MarkDeleted records that the file was removed through the DELETE endpoint.
// Existing scan results are kept alongside the new status so the record still
// says what was known about the file; only status and completion time change.
// A file that never had metadata (moderation off at upload time, or a private
// upload, which is not scanned) gets a fresh record so the metadata endpoint
// answers consistently.
//
// The record is only written while the file is confirmed absent. Identical
// bytes under the same filename land on the same path, so an upload that
// completes between the handler's Remove and this call has already put a
// file back; its Stored call, queued behind the same lock, would find no
// record yet and the one written here would then describe a present file
// forever (private uploads are never scanned, and scans refuse to overwrite
// a deleted record). The check and the write happen under one lock, and
// Stored takes that lock after the file is in place, so either order of the
// two ends without a stale record.
func (s *Service) MarkDeleted(relativePath string) error {
	s.metaMu.Lock()
	defer s.metaMu.Unlock()

	if present, known := s.filePresent(relativePath); known && present {
		log.Printf("File was stored again before its deleted record was written, leaving no record: %q", relativePath)
		return nil
	}

	meta, err := s.GetMetadata(relativePath)
	if err != nil {
		return err
	}
	now := time.Now()
	if meta == nil {
		meta = &Metadata{RequestedAt: now}
	}
	meta.Status = StatusDeleted
	meta.CompletedAt = &now
	return s.saveMetadata(relativePath, meta)
}

// filePresent reports whether a file is present at relativePath. known is
// false when the Service has no opener (a metadata-only Service, as the
// handler tests build) or the open failed for a reason other than absence;
// callers then proceed as they would without the check rather than guess.
func (s *Service) filePresent(relativePath string) (present, known bool) {
	if s.openFile == nil {
		return false, false
	}
	f, err := s.openFile(relativePath)
	if err != nil {
		return false, os.IsNotExist(err)
	}
	f.Close()
	return true, true
}

// Stored is called whenever a file has been written at relativePath. If a
// deleted tombstone sits there from an earlier incarnation of the same path,
// it is removed: the record described a file that no longer existed, and
// now one does. Any other record is left alone; a deduplicated re-upload
// found the file present, so its verdict still stands.
//
// The mirror of MarkDeleted's check: a DELETE that lands between the
// caller's StoreFile and this call has removed the file again and written
// the record this would clear, so the record is only removed while the file
// is confirmed present. Both checks run under metaMu, so the two paths see
// each other's writes in order.
func (s *Service) Stored(relativePath string) {
	s.metaMu.Lock()
	defer s.metaMu.Unlock()

	existing, err := s.GetMetadata(relativePath)
	if err != nil || existing == nil || existing.Status != StatusDeleted {
		return
	}
	if present, known := s.filePresent(relativePath); known && !present {
		log.Printf("File was deleted again before its re-store was recorded, keeping deleted record: %q", relativePath)
		return
	}
	if err := os.Remove(s.metadataPath(relativePath)); err != nil && !os.IsNotExist(err) {
		log.Printf("Could not clear deleted record for re-stored %q: %v", relativePath, err)
		return
	}
	log.Printf("Cleared deleted record for re-stored file: %q", relativePath)
}

// scanMalware and scanNSFW open the stored file through the storage root and
// stream it to the scanner. Kept together so the open/close pairing lives in
// one place rather than twice inside scan().
func (s *Service) scanMalware(relativePath string) (*scanner.MalwareScanResult, error) {
	f, err := s.openFile(relativePath)
	if err != nil {
		// No path in the message: every caller logs it alongside, and this
		// error also lands in the metadata JSON and the retry queue, where a
		// second copy of the uploader's filename earns nothing.
		return nil, fmt.Errorf("open for malware scan: %w", err)
	}
	defer f.Close()
	return s.scanner.ScanMalware(relativePath, f)
}

func (s *Service) scanNSFW(relativePath string) (*scanner.NSFWResult, error) {
	f, err := s.openFile(relativePath)
	if err != nil {
		return nil, fmt.Errorf("open for nsfw scan: %w", err)
	}
	defer f.Close()
	return s.scanner.ScanNSFW(relativePath, f)
}

// GetMetadata reads the metadata for a file.
func (s *Service) GetMetadata(relativePath string) (*Metadata, error) {
	metaFile := s.metadataPath(relativePath)

	data, err := os.ReadFile(metaFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var meta Metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}

	return &meta, nil
}

// saveMetadata atomically writes metadata to disk.
func (s *Service) saveMetadata(relativePath string, meta *Metadata) error {
	metaFile := s.metadataPath(relativePath)

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(metaFile), 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}

	// Write atomically
	tmpFile := metaFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return err
	}

	return os.Rename(tmpFile, metaFile)
}

// metadataPath returns the filesystem path for a metadata file.
func (s *Service) metadataPath(relativePath string) string {
	return filepath.Join(s.metaPath, relativePath+".json")
}

// queueForRetry adds a failed scan to the retry queue.
func (s *Service) queueForRetry(relativePath, clientCode, sha1 string, isPublic bool, lastError string) {
	entry := QueueEntry{
		RelativePath: relativePath,
		ClientCode:   clientCode,
		SHA1:         sha1,
		IsPublic:     isPublic,
		QueuedAt:     time.Now(),
		Retries:      0,
		LastError:    lastError,
	}

	queueFile := filepath.Join(s.queuePath, filepath.Base(relativePath)+".json")

	// Check if already queued
	if existing, err := os.ReadFile(queueFile); err == nil {
		var existingEntry QueueEntry
		if json.Unmarshal(existing, &existingEntry) == nil {
			entry.Retries = existingEntry.Retries + 1
			entry.QueuedAt = existingEntry.QueuedAt
		}
	}

	data, _ := json.MarshalIndent(entry, "", "  ")
	os.WriteFile(queueFile, data, 0644)

	log.Printf("Queued for retry: %q (attempt %d)", relativePath, entry.Retries+1)
}

// processQueue runs in the background and retries failed scans.
func (s *Service) processQueue() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.processQueueOnce()
	}
}

func (s *Service) processQueueOnce() {
	entries, err := os.ReadDir(s.queuePath)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		queueFile := filepath.Join(s.queuePath, entry.Name())
		data, err := os.ReadFile(queueFile)
		if err != nil {
			continue
		}

		var qe QueueEntry
		if err := json.Unmarshal(data, &qe); err != nil {
			continue
		}

		// Max 5 retries with exponential backoff
		if qe.Retries >= 5 {
			log.Printf("Max retries reached for %s, giving up", qe.RelativePath)
			os.Remove(queueFile)
			continue
		}

		// Exponential backoff: 5min, 10min, 20min, 40min, 80min
		backoff := time.Duration(1<<qe.Retries) * 5 * time.Minute
		if time.Since(qe.QueuedAt) < backoff {
			continue
		}

		// Check the file still exists, through the storage root. Only a
		// confirmed-missing file drops the job: a transient failure such as a
		// permission change or descriptor exhaustion must leave it queued, or
		// a pending malware scan is silently abandoned along with its alert.
		f, err := s.openFile(qe.RelativePath)
		if err != nil {
			if os.IsNotExist(err) {
				os.Remove(queueFile)
			} else {
				log.Printf("Could not open queued file %q, leaving it queued: %v", qe.RelativePath, err)
			}
			continue
		}
		f.Close()

		log.Printf("Retrying scan for %q (attempt %d)", qe.RelativePath, qe.Retries+1)

		// Remove from queue before retry (will be re-added if fails again)
		os.Remove(queueFile)

		// Retry scan
		s.scan(qe.RelativePath, qe.ClientCode, qe.SHA1, qe.IsPublic)
	}
}
