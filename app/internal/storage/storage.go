package storage

import (
	"bytes"
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

// NewStorage creates basePath if it is missing and opens it as a storage root.
//
// It creates the directory itself rather than relying on a caller to do it
// first: os.OpenRoot requires an existing directory, so leaving that to
// call-ordering makes a fresh deployment fail at startup depending on which
// line runs first.
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
// Returns FileInfo with the relative path and metadata. It is Stage followed
// by Commit, for a caller that has nothing to check between the two.
func (s *Storage) StoreFile(r io.Reader, originalFilename, clientCode string) (*FileInfo, error) {
	staged, err := s.Stage(r, originalFilename, clientCode)
	if err != nil {
		return nil, err
	}
	return staged.Commit()
}

// Staged is a file written to the storage volume under a temporary name,
// hashed, and not yet at the path it will be served from. Commit publishes
// it; Discard removes it. One of the two must be called.
type Staged struct {
	s         *Storage
	tempPath  string
	finalPath string
	size      int64
	sha1Hex   string
	done      bool
}

// Stage writes the reader to a temporary file in the directory the final
// file will live in, computing its SHA1 on the way. Nothing is visible under
// the final path until Commit: a caller that has more of the request to read
// after the bytes - and may yet refuse it - can stage first and publish only
// once the whole request is good, without the file ever having been served
// or seen by a deduplicating upload in between.
func (s *Storage) Stage(r io.Reader, originalFilename, clientCode string) (*Staged, error) {
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
	if err := tempFile.Close(); err != nil {
		s.root.Remove(tempPath)
		return nil, fmt.Errorf("failed to write file: %w", err)
	}

	// Generate final filename with SHA1
	sha1Hex := hex.EncodeToString(hash.Sum(nil))
	finalName := fmt.Sprintf("%s-%s.%s", baseName, sha1Hex, ext)
	return &Staged{
		s:         s,
		tempPath:  tempPath,
		finalPath: filepath.Join(storageDir, finalName),
		size:      size,
		sha1Hex:   sha1Hex,
	}, nil
}

// Commit publishes the staged file under its final path, or drops it in
// favour of an identical file already there. The temporary file is gone
// either way, also on error.
func (st *Staged) Commit() (*FileInfo, error) {
	if st.done {
		return nil, fmt.Errorf("staged file already committed or discarded")
	}
	st.done = true
	s := st.s

	// Check for deduplication. The name encodes the hash, so a file already
	// there has the same SHA1 - which is not the same as the same bytes: SHA1
	// collisions are constructible. The bytes are compared before the upload
	// is dropped in favour of what is stored, and the size reported is the
	// stored file's, so the response (and the meta_token signing it) always
	// describes the file that the path actually serves.
	if existing, err := s.root.Stat(st.finalPath); err == nil {
		same, err := s.sameContent(st.tempPath, st.finalPath)
		s.root.Remove(st.tempPath)
		if err != nil {
			return nil, fmt.Errorf("failed to compare with stored file: %w", err)
		}
		if !same {
			return nil, fmt.Errorf("a different file is already stored under this name and hash")
		}
		return &FileInfo{
			RelativePath: st.finalPath,
			Size:         existing.Size(),
			IsDuplicate:  true,
			SHA1:         st.sha1Hex,
		}, nil
	}

	// Rename temp file to final path
	if err := s.root.Rename(st.tempPath, st.finalPath); err != nil {
		s.root.Remove(st.tempPath)
		return nil, fmt.Errorf("failed to rename file: %w", err)
	}

	return &FileInfo{
		RelativePath: st.finalPath,
		Size:         st.size,
		IsDuplicate:  false,
		SHA1:         st.sha1Hex,
	}, nil
}

// Discard removes a staged file that will not be published.
func (st *Staged) Discard() {
	if st.done {
		return
	}
	st.done = true
	st.s.root.Remove(st.tempPath)
}

// sameContent reports whether the two stored files hold identical bytes. A
// size difference settles it without reading; otherwise both are streamed and
// compared chunk by chunk, so a dedup hit costs one read of the stored file.
func (s *Storage) sameContent(pathA, pathB string) (bool, error) {
	a, err := s.root.Open(pathA)
	if err != nil {
		return false, err
	}
	defer a.Close()
	b, err := s.root.Open(pathB)
	if err != nil {
		return false, err
	}
	defer b.Close()

	infoA, err := a.Stat()
	if err != nil {
		return false, err
	}
	infoB, err := b.Stat()
	if err != nil {
		return false, err
	}
	if infoA.Size() != infoB.Size() {
		return false, nil
	}

	bufA, bufB := make([]byte, 32*1024), make([]byte, 32*1024)
	for {
		nA, errA := io.ReadFull(a, bufA)
		nB, errB := io.ReadFull(b, bufB)
		if nA != nB || !bytes.Equal(bufA[:nA], bufB[:nB]) {
			return false, nil
		}
		if errA == io.EOF || errA == io.ErrUnexpectedEOF {
			if errB == io.EOF || errB == io.ErrUnexpectedEOF {
				return true, nil
			}
			return false, nil
		}
		if errA != nil {
			return false, errA
		}
		if errB != nil {
			return false, errB
		}
	}
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
