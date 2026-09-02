package storage

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"file-api/internal/util"
)

// FileInfo contains metadata about a stored file.
type FileInfo struct {
	RelativePath string // Path relative to base (e.g., "2026/1/photo-{sha1}.jpg")
	Size         int64  // File size in bytes
	IsDuplicate  bool   // True if file already existed (deduplication)
	// SHA1 of the stored content, hex encoded. Identifies the file without
	// naming it: the relative path embeds the uploader's own filename, which
	// is not something every consumer should receive.
	SHA1 string
}

// Storage handles file operations.
//
// Every filesystem operation goes through root, an *os.Root anchored at the
// base directory. Root refuses any name that resolves outside it - including
// through a symlink - so containment is enforced by the kernel-facing API
// rather than by inspecting the string first. The validation in StoreFile and
// the handlers stays as the fast, legible rejection; this is what makes it
// true even if one of those is bypassed or forgotten.
type Storage struct {
	BasePath       string
	MaxFilenameLen int

	root *os.Root
}

// NewStorage opens basePath as a storage root. The directory must exist.
func NewStorage(basePath string, maxFilenameLen int) (*Storage, error) {
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("create storage base %q: %w", basePath, err)
	}
	root, err := os.OpenRoot(basePath)
	if err != nil {
		return nil, fmt.Errorf("open storage root %q: %w", basePath, err)
	}
	return &Storage{
		BasePath:       basePath,
		MaxFilenameLen: maxFilenameLen,
		root:           root,
	}, nil
}

// Close releases the storage root.
func (s *Storage) Close() error { return s.root.Close() }

// StoreFile stores a file from an io.Reader, computing SHA1 for deduplication.
// Returns FileInfo with the relative path and metadata.
func (s *Storage) StoreFile(r io.Reader, originalFilename, clientCode string) (*FileInfo, error) {
	// Sanitize the filename
	sanitized := util.SanitizeFilename(originalFilename, s.MaxFilenameLen)
	if sanitized == "" || !util.IsValidFilename(sanitized) {
		return nil, fmt.Errorf("invalid filename after sanitization")
	}

	// Validate the client code here, where it becomes a path component,
	// rather than trusting whoever called us to have done it. Both current
	// callers do, but this function is exported and nothing in its signature
	// says the argument has to be safe.
	if strings.Contains(clientCode, "..") {
		return nil, fmt.Errorf("invalid client code")
	}
	if clientCode != "" && !util.IsValidClientCode(clientCode) {
		return nil, fmt.Errorf("invalid client code")
	}

	// Extract base name and extension
	baseName := util.ExtractBaseName(sanitized)
	ext := util.ExtractExtension(sanitized)
	if ext == "" {
		ext = "bin" // Default extension for unknown types
	}

	// Directory for this upload, relative to the root, computed once so a
	// request crossing a month boundary cannot land its temp file and its
	// final file in different directories.
	storageDir := GenerateStorageDir(clientCode)

	// Ensure directory exists
	if err := s.root.MkdirAll(storageDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	// Generate temporary filename with random suffix
	randomBytes := make([]byte, 6)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	tempName := fmt.Sprintf("%s-%s.%s", baseName, hex.EncodeToString(randomBytes), ext)
	tempPath := filepath.Join(storageDir, tempName)

	// Create temporary file
	tempFile, err := s.root.Create(tempPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	// Compute SHA1 while writing to temp file
	hash := sha1.New()
	writer := io.MultiWriter(tempFile, hash)

	size, err := io.Copy(writer, r)
	if err != nil {
		tempFile.Close()
		s.root.Remove(tempPath)
		return nil, fmt.Errorf("failed to write file: %w", err)
	}
	tempFile.Close()

	// Generate final filename with SHA1
	sha1Hex := hex.EncodeToString(hash.Sum(nil))
	finalName := fmt.Sprintf("%s-%s.%s", baseName, sha1Hex, ext)
	finalPath := filepath.Join(storageDir, finalName)

	// Check for deduplication
	if _, err := s.root.Stat(finalPath); err == nil {
		// File already exists - deduplicate
		s.root.Remove(tempPath)
		return &FileInfo{
			RelativePath: finalPath,
			Size:         size,
			IsDuplicate:  true,
			SHA1:         sha1Hex,
		}, nil
	}

	// Rename temp file to final path
	if err := s.root.Rename(tempPath, finalPath); err != nil {
		s.root.Remove(tempPath)
		return nil, fmt.Errorf("failed to rename file: %w", err)
	}

	return &FileInfo{
		RelativePath: finalPath,
		Size:         size,
		IsDuplicate:  false,
		SHA1:         sha1Hex,
	}, nil
}

// Open opens a stored file for reading. The name is resolved inside the
// storage root, so a path escaping it fails here rather than reading whatever
// it pointed at.
//
// Callers get a *os.File rather than a path on purpose: handing out an
// absolute path would move the open outside the root and give up the
// guarantee.
func (s *Storage) Open(relativePath string) (*os.File, error) {
	return s.root.Open(relativePath)
}

// Stat reports the FileInfo of a stored file.
func (s *Storage) Stat(relativePath string) (os.FileInfo, error) {
	return s.root.Stat(relativePath)
}

// FileExists checks if a file exists at the given relative path.
func (s *Storage) FileExists(relativePath string) bool {
	_, err := s.root.Stat(relativePath)
	return err == nil
}

// GetFileSize returns the size of a file at the given relative path.
func (s *Storage) GetFileSize(relativePath string) (int64, error) {
	info, err := s.root.Stat(relativePath)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// DeleteFile removes a file at the given relative path.
func (s *Storage) DeleteFile(relativePath string) error {
	return s.root.Remove(relativePath)
}

// SanitizeRequestPath cleans and validates a path from an HTTP request.
// Returns the sanitized path or an error if invalid.
func SanitizeRequestPath(path string) (string, error) {
	// Remove /files/ prefix if present
	path = strings.TrimPrefix(path, "/files/")
	path = strings.TrimPrefix(path, "files/")

	// Normalize path separators
	path = filepath.ToSlash(path)

	// Clean the path to remove . and .. components
	path = filepath.Clean(path)

	// Validate the cleaned path
	if !util.IsValidRelativePath(path) {
		return "", fmt.Errorf("invalid path")
	}

	return path, nil
}
