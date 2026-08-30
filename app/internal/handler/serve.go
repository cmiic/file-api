package handler

import (
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"file-api/internal/middleware"
	"file-api/internal/storage"
)

// Safe content types that can be rendered inline (images, video, audio, PDF)
var safeInlineTypes = map[string]bool{
	"image/jpeg":      true,
	"image/png":       true,
	"image/gif":       true,
	"image/webp":      true,
	"image/svg+xml":   false, // SVG can contain scripts - force download
	"video/mp4":       true,
	"video/webm":      true,
	"audio/mpeg":      true,
	"audio/wav":       true,
	"application/pdf": true,
}

// ServeHandler handles file serving requests.
type ServeHandler struct {
	storage *storage.Storage
}

// NewServeHandler creates a new ServeHandler.
func NewServeHandler(s *storage.Storage) *ServeHandler {
	return &ServeHandler{storage: s}
}

// ServeHTTP handles GET /files/* requests.
func (h *ServeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Security headers for all responses
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'")
	w.Header().Set("X-Frame-Options", "DENY")

	// Extract and sanitize the file path
	path := strings.TrimPrefix(r.URL.Path, "/files/")
	path = strings.TrimPrefix(path, "/files")

	// Sanitize path
	sanitizedPath, err := storage.SanitizeRequestPath(path)
	if err != nil {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// Check if this is a private path
	isPrivate := storage.IsPrivatePath(sanitizedPath)
	if isPrivate {
		// Require JWT authentication
		claims := middleware.GetClaims(r)
		if claims == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Extract and verify client code
		requestedClientCode := storage.ExtractClientCode(sanitizedPath)
		if requestedClientCode != "" && claims.ClientCode != requestedClientCode {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}

	// Get full file path
	fullPath := h.storage.GetFilePath(sanitizedPath)

	// Check if file exists before setting cache headers
	info, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Not Found", http.StatusNotFound)
		} else {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	// Don't serve directories
	if info.IsDir() {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Set cache headers only after confirming file exists
	if isPrivate {
		w.Header().Set("Cache-Control", "private, no-store")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}

	// Set content type based on extension
	ext := filepath.Ext(fullPath)
	contentType := mime.TypeByExtension(ext)
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}

	// Force download for non-safe content types to prevent XSS
	// Safe types (images, video, audio, PDF) can render inline
	if !safeInlineTypes[contentType] {
		filename := filepath.Base(fullPath)
		w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	}

	// Serve the file
	http.ServeFile(w, r, fullPath)
}

// HealthHandler provides a health check endpoint.
type HealthHandler struct{}

// NewHealthHandler creates a new HealthHandler.
func NewHealthHandler() *HealthHandler {
	return &HealthHandler{}
}

// ServeHTTP returns a simple OK response for health checks.
func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
