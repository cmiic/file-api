// Package storage handles file storage operations including path generation,
// SHA1 hashing, and deduplication.
package storage

import (
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// GenerateStoragePath creates the directory path for storing a file.
// Public files:  {basePath}/{year}/{month}/
// Private files: {basePath}/cli/{clientCode}/{year}/{month}/
func GenerateStoragePath(basePath, clientCode string) string {
	now := time.Now()
	year := strconv.Itoa(now.Year())
	month := strconv.Itoa(int(now.Month()))

	if clientCode != "" {
		return filepath.Join(basePath, "cli", clientCode, year, month)
	}
	return filepath.Join(basePath, year, month)
}

// GenerateRelativePath creates the relative path (from basePath) for a stored file.
// This is what gets returned in the API response and stored in the database.
// Public files:  {year}/{month}/{filename}
// Private files: cli/{clientCode}/{year}/{month}/{filename}
func GenerateRelativePath(clientCode, filename string) string {
	now := time.Now()
	year := strconv.Itoa(now.Year())
	month := strconv.Itoa(int(now.Month()))

	if clientCode != "" {
		return filepath.Join("cli", clientCode, year, month, filename)
	}
	return filepath.Join(year, month, filename)
}

// IsPrivatePath checks if a URL path is for private files.
// Private paths start with /files/cli/ - the segment immediately after /files/ must be "cli".
func IsPrivatePath(urlPath string) bool {
	// Normalize to forward slashes for consistent checking
	normalized := filepath.ToSlash(urlPath)
	// Remove /files/ prefix and check if remainder starts with cli/
	trimmed := strings.TrimPrefix(normalized, "/files/")
	return strings.HasPrefix(trimmed, "cli/")
}

// ExtractClientCode extracts the client code from a private path.
// Returns empty string if not a private path.
// Path format: cli/{clientCode}/...
func ExtractClientCode(path string) string {
	// Normalize path separators
	path = filepath.ToSlash(path)

	// Remove leading slash if present
	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}

	// Check for cli/ prefix
	if len(path) < 4 || path[:4] != "cli/" {
		return ""
	}

	// Find the client code (between cli/ and next /)
	rest := path[4:]
	for i, c := range rest {
		if c == '/' {
			return rest[:i]
		}
	}

	return rest
}
