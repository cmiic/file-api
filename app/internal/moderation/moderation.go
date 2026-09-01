// Package moderation orchestrates file scanning and metadata management.
package moderation

import (
	"encoding/json"
	"fmt"
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
	RelativePath string    `json:"relative_path"`
	AbsolutePath string    `json:"abs_path"`
	ClientCode   string    `json:"client_code"`
	SHA1         string    `json:"sha1,omitempty"`
	IsPublic     bool      `json:"is_public"`
	QueuedAt     time.Time `json:"queued_at"`
	Retries      int       `json:"retries"`
	LastError    string    `json:"last_error,omitempty"`
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

// DeleteFunc is a function type for deleting files.
type DeleteFunc func(relativePath string) error

// Service orchestrates scanning, metadata storage, and notifications.
type Service struct {
	scanner    *scanner.Client
	notifier   *notifier.Notifier
	metaPath   string
	queuePath  string
	deleteFile DeleteFunc

	// Background processing
	mu         sync.Mutex
	processing map[string]bool // tracks files currently being processed
}

// NewService creates a new moderation service.
func NewService(
	scannerClient *scanner.Client,
	notifier *notifier.Notifier,
	metaPath, queuePath string,
	deleteFile DeleteFunc,
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
		notifier:   notifier,
		metaPath:   metaPath,
		queuePath:  queuePath,
		deleteFile: deleteFile,
		processing: make(map[string]bool),
	}

	// Start background queue processor
	go s.processQueue()

	return s
}

// Enabled returns true if any scanning is configured.
func (s *Service) Enabled() bool {
	return s.scanner.MalwareEnabled() || s.scanner.NSFWEnabled()
}

// ProcessUpload triggers async scanning for a newly uploaded file.
// This is non-blocking and runs in a goroutine.
func (s *Service) ProcessUpload(relativePath, absPath, clientCode, sha1 string, isPublic bool) {
	if !s.Enabled() {
		return
	}

	// Only scan public files automatically
	if !isPublic {
		return
	}

	go s.scan(relativePath, absPath, clientCode, sha1, isPublic)
}

// scan performs the actual scanning (called async).
func (s *Service) scan(relativePath, absPath, clientCode, sha1 string, isPublic bool) {
	// Prevent duplicate processing
	s.mu.Lock()
	if s.processing[relativePath] {
		s.mu.Unlock()
		return
	}
	s.processing[relativePath] = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.processing, relativePath)
		s.mu.Unlock()
	}()

	log.Printf("Starting scan for: %s", relativePath)

	meta := &Metadata{
		Status:      StatusPending,
		RequestedAt: time.Now(),
	}

	var scanErr error

	// 1. Malware scan first (faster, security-critical)
	if s.scanner.MalwareEnabled() {
		result, err := s.scanner.ScanMalware(absPath)
		if err != nil {
			scanErr = fmt.Errorf("malware scan: %w", err)
			log.Printf("Malware scan failed for %s: %v", relativePath, err)
		} else if result != nil {
			meta.MalwareResult = &MalwareInfo{
				Infected:    result.Infected,
				MalwareName: result.MalwareName,
				ScanTimeMS:  result.ScanTimeMS,
			}

			if result.Infected {
				meta.Status = StatusMalware
				now := time.Now()
				meta.CompletedAt = &now

				// Delete the file immediately
				if err := s.deleteFile(relativePath); err != nil {
					log.Printf("Failed to delete malware file %s: %v", relativePath, err)
				} else {
					log.Printf("Deleted malware file: %s (%s)", relativePath, *result.MalwareName)
				}

				// Save metadata and notify
				s.saveMetadata(relativePath, meta)
				malwareName := "unknown"
				if result.MalwareName != nil {
					malwareName = *result.MalwareName
				}
				s.notifier.MalwareAlert(sha1, scopeOf(isPublic), malwareName)
				return // Don't continue with NSFW scan
			}
		}
	}

	// 2. NSFW scan (if malware clean and scanner enabled)
	if scanErr == nil && s.scanner.NSFWEnabled() {
		result, err := s.scanner.ScanNSFW(absPath)
		if err != nil {
			scanErr = fmt.Errorf("nsfw scan: %w", err)
			log.Printf("NSFW scan failed for %s: %v", relativePath, err)
		} else if result != nil {
			meta.NSFWResult = &NSFWInfo{
				Unsafe:          result.Unsafe,
				Confidence:      result.Confidence,
				DetectedClasses: result.DetectedClasses,
			}

			if result.Unsafe {
				meta.Status = StatusFlagged
				now := time.Now()
				meta.CompletedAt = &now

				// Don't delete, just flag
				log.Printf("NSFW content flagged: %s (confidence: %.2f)", relativePath, result.Confidence)

				s.saveMetadata(relativePath, meta)
				s.notifier.NSFWAlert(sha1, scopeOf(isPublic), result.Confidence, result.DetectedClasses)
				return
			}
		}
	}

	// Handle errors - queue for retry
	if scanErr != nil {
		errStr := scanErr.Error()
		meta.Status = StatusError
		meta.Error = &errStr
		s.saveMetadata(relativePath, meta)
		s.queueForRetry(relativePath, absPath, clientCode, sha1, isPublic, errStr)
		return
	}

	// All clean
	meta.Status = StatusClean
	now := time.Now()
	meta.CompletedAt = &now
	s.saveMetadata(relativePath, meta)
	log.Printf("Scan complete (clean): %s", relativePath)
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
func (s *Service) queueForRetry(relativePath, absPath, clientCode, sha1 string, isPublic bool, lastError string) {
	entry := QueueEntry{
		RelativePath: relativePath,
		AbsolutePath: absPath,
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

	log.Printf("Queued for retry: %s (attempt %d)", relativePath, entry.Retries+1)
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

		// Check if file still exists
		if _, err := os.Stat(qe.AbsolutePath); os.IsNotExist(err) {
			os.Remove(queueFile)
			continue
		}

		log.Printf("Retrying scan for %s (attempt %d)", qe.RelativePath, qe.Retries+1)

		// Remove from queue before retry (will be re-added if fails again)
		os.Remove(queueFile)

		// Retry scan
		s.scan(qe.RelativePath, qe.AbsolutePath, qe.ClientCode, qe.SHA1, qe.IsPublic)
	}
}
