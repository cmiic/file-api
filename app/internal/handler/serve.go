package handler

import (
	"mime"
	"net/http"
	"path/filepath"

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

// ServeHTTP handles GET and HEAD /files/* requests.
func (h *ServeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Security headers for all responses
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'")
	w.Header().Set("X-Frame-Options", "DENY")

	path, ok := requestFilePath(r.URL.Path)
	if !ok {
		http.Error(w, msgInvalidPath, http.StatusBadRequest)
		return
	}
	if status := authorizeClientPath(middleware.GetClaims(r), path); status != 0 {
		http.Error(w, http.StatusText(status), status)
		return
	}

	// Open through the storage root: a name that escapes it fails here rather
	// than reaching the filesystem. The headers below are set only once the
	// file is open, so an error response never carries the year-long public
	// cache header.
	f, info, ok := openRegularFile(w, h.storage, path, "[serve]")
	if !ok {
		return
	}
	defer f.Close()
	setContentHeaders(w, path, storage.IsPrivatePath(path))

	// ServeContent rather than ServeFile: ServeFile takes a path and opens it
	// itself, outside the root, which would give up the guarantee this handler
	// just established by opening through it. ServeContent takes the open
	// file and still provides Range and conditional-request handling.
	http.ServeContent(w, r, path, info.ModTime(), f)
}

// setContentHeaders sets caching, type and disposition for a file that exists
// and is about to be served. Only called once the file is known to exist, so a
// 404 never carries a year-long public cache header.
func setContentHeaders(w http.ResponseWriter, path string, private bool) {
	if private {
		w.Header().Set("Cache-Control", "private, no-store")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}

	contentType := mime.TypeByExtension(filepath.Ext(path))
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}

	// Force download for non-safe content types to prevent XSS. Safe types
	// (images, video, audio, PDF) can render inline.
	if !safeInlineTypes[contentType] {
		w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(path)+"\"")
	}
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
