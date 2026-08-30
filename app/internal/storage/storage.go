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
}

// Storage handles file operations.
type Storage struct {
	BasePath       string
	MaxFilenameLen int
}

// NewStorage creates a new Storage instance.
func NewStorage(basePath string, maxFilenameLen int) *Storage {
	return &Storage{
		BasePath:       basePath,
		MaxFilenameLen: maxFilenameLen,
	}
}

// StoreFile stores a file from an io.Reader, computing SHA1 for deduplication.
// Returns FileInfo with the relative path and metadata.
func (s *Storage) StoreFile(r io.Reader, originalFilename, clientCode string) (*FileInfo, error) {
	// Sanitize the filename
	sanitized := util.SanitizeFilename(originalFilename, s.MaxFilenameLen)
	if sanitized == "" || !util.IsValidFilename(sanitized) {
		return nil, fmt.Errorf("invalid filename after sanitization")
	}

	// Extract base name and extension
	baseName := util.ExtractBaseName(sanitized)
	ext := util.ExtractExtension(sanitized)
	if ext == "" {
		ext = "bin" // Default extension for unknown types
	}

	// Generate storage directory path
	storageDir := GenerateStoragePath(s.BasePath, clientCode)

	// Ensure directory exists
	if err := os.MkdirAll(storageDir, 0755); err != nil {
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
	tempFile, err := os.Create(tempPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	// Compute SHA1 while writing to temp file
	hash := sha1.New()
	writer := io.MultiWriter(tempFile, hash)

	size, err := io.Copy(writer, r)
	if err != nil {
		tempFile.Close()
		os.Remove(tempPath)
		return nil, fmt.Errorf("failed to write file: %w", err)
	}
	tempFile.Close()

	// Generate final filename with SHA1
	sha1Hex := hex.EncodeToString(hash.Sum(nil))
	finalName := fmt.Sprintf("%s-%s.%s", baseName, sha1Hex, ext)
	finalPath := filepath.Join(storageDir, finalName)

	// Check for deduplication
	if _, err := os.Stat(finalPath); err == nil {
		// File already exists - deduplicate
		os.Remove(tempPath)
		return &FileInfo{
			RelativePath: GenerateRelativePath(clientCode, finalName),
			Size:         size,
			IsDuplicate:  true,
		}, nil
	}

	// Rename temp file to final path
	if err := os.Rename(tempPath, finalPath); err != nil {
		os.Remove(tempPath)
		return nil, fmt.Errorf("failed to rename file: %w", err)
	}

	return &FileInfo{
		RelativePath: GenerateRelativePath(clientCode, finalName),
		Size:         size,
		IsDuplicate:  false,
	}, nil
}

// GetFilePath returns the full filesystem path for a relative file path.
func (s *Storage) GetFilePath(relativePath string) string {
	return filepath.Join(s.BasePath, relativePath)
}

// FileExists checks if a file exists at the given relative path.
func (s *Storage) FileExists(relativePath string) bool {
	fullPath := s.GetFilePath(relativePath)
	_, err := os.Stat(fullPath)
	return err == nil
}

// GetFileSize returns the size of a file at the given relative path.
func (s *Storage) GetFileSize(relativePath string) (int64, error) {
	fullPath := s.GetFilePath(relativePath)
	info, err := os.Stat(fullPath)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// DeleteFile removes a file at the given relative path.
func (s *Storage) DeleteFile(relativePath string) error {
	fullPath := s.GetFilePath(relativePath)
	return os.Remove(fullPath)
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
