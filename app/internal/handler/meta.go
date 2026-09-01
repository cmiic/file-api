package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"file-api/internal/middleware"
	"file-api/internal/moderation"
	"file-api/internal/storage"
)

// MetaHandler handles scan metadata requests.
type MetaHandler struct {
	moderation *moderation.Service
}

// NewMetaHandler creates a new MetaHandler.
func NewMetaHandler(mod *moderation.Service) *MetaHandler {
	return &MetaHandler{
		moderation: mod,
	}
}

// ServeHTTP handles GET /meta/files/{relative_path}
func (h *MetaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check for scan:read scope
	claims := middleware.GetClaims(r)
	if claims == nil || !claims.HasScope("scan:read") {
		http.Error(w, "Forbidden: scan:read scope required", http.StatusForbidden)
		return
	}

	// Extract relative path from URL
	// /meta/files/2026/1/file.jpg -> 2026/1/file.jpg
	rawPath := strings.TrimPrefix(r.URL.Path, "/meta/files/")
	if rawPath == "" {
		http.Error(w, "File path required", http.StatusBadRequest)
		return
	}

	// Clean and validate before the path reaches the filesystem.
	// http.ServeMux only canonicalizes the *escaped* path, so a
	// percent-encoded traversal (%2e%2e%2f) survives routing and
	// arrives here decoded in r.URL.Path. Same sanitizer the /files/
	// handler uses.
	relativePath, err := storage.SanitizeRequestPath(rawPath)
	if err != nil {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// Check if moderation is enabled
	if h.moderation == nil {
		http.Error(w, "Moderation not enabled", http.StatusServiceUnavailable)
		return
	}

	// Get metadata
	meta, err := h.moderation.GetMetadata(relativePath)
	if err != nil {
		// The underlying error carries absolute filesystem paths -
		// log it, don't hand it to the caller.
		log.Printf("[meta] read metadata %s: %v", relativePath, err)
		http.Error(w, "Failed to read metadata", http.StatusInternalServerError)
		return
	}

	if meta == nil {
		http.Error(w, "Metadata not found", http.StatusNotFound)
		return
	}

	// Return metadata
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	json.NewEncoder(w).Encode(meta)
}
