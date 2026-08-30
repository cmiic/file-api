package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"file-api/internal/middleware"
	"file-api/internal/moderation"
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
	relativePath := strings.TrimPrefix(r.URL.Path, "/meta/files/")
	if relativePath == "" {
		http.Error(w, "File path required", http.StatusBadRequest)
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
		http.Error(w, "Failed to read metadata: "+err.Error(), http.StatusInternalServerError)
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
