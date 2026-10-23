package handler

import (
	"log"
	"net/http"
	"time"

	"file-api/internal/middleware"
	"file-api/internal/moderation"
	"file-api/internal/storage"
)

// DeleteHandler removes a stored file on behalf of the application that
// uploaded it.
//
// The store is otherwise write-once: URLs are shared across applications and
// embedded in places (newsletters, public pages) that cannot be updated once
// sent. Deletion exists for the accidental upload that is noticed shortly
// after it happens, and the handler is shaped around that single use:
//
//   - the token needs a dedicated "delete" scope, so an upload token that
//     leaks or is minted too broadly cannot remove anything;
//   - private paths require the token's client code to match, as for upload;
//   - the file must be younger than maxAge. Its mtime is the first upload
//     time (rename preserves it and a deduplicated re-upload never touches
//     the existing file), so an old file cannot be removed even with a valid
//     token. That bounds what a wrong token can do to the archive.
//
// What this handler does not promise: the bytes may remain in reverse-proxy
// and image caches until they expire there, and two uploaders of identical
// content within the window share one path, so a delete by either removes
// it for both.
type DeleteHandler struct {
	storage    *storage.Storage
	moderation *moderation.Service
	maxAge     time.Duration
}

// NewDeleteHandler creates a DeleteHandler. mod may be nil when moderation is
// disabled; maxAge must be positive, which main.go guarantees by not
// registering the route otherwise.
func NewDeleteHandler(s *storage.Storage, mod *moderation.Service, maxAge time.Duration) *DeleteHandler {
	return &DeleteHandler{storage: s, moderation: mod, maxAge: maxAge}
}

// ServeHTTP handles DELETE /files/{path} and DELETE /files/cli/{code}/{path}.
func (h *DeleteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	claims := middleware.GetClaims(r)
	if claims == nil || !claims.HasScope("delete") {
		http.Error(w, "Forbidden: delete scope required", http.StatusForbidden)
		return
	}

	// Same path resolution and client check as the serve handler, so a path
	// that cannot be read cannot be deleted either.
	path, ok := requestFilePath(r.URL.Path)
	if !ok {
		http.Error(w, msgInvalidPath, http.StatusBadRequest)
		return
	}
	if status := authorizeClientPath(claims, path); status != 0 {
		http.Error(w, http.StatusText(status), status)
		return
	}

	info, ok := statRegularFile(w, h.storage, path, "[delete]")
	if !ok {
		return
	}

	// 403 rather than 404 or 410: the caller holds a delete token and already
	// knows the path, so confirming that the file exists tells them nothing
	// new, and a distinct answer lets the application explain to its user why
	// the file stays.
	if time.Since(info.ModTime()) > h.maxAge {
		http.Error(w, "Forbidden: deletion window elapsed", http.StatusForbidden)
		return
	}

	// A file that vanished between Stat and Remove answers 404: the outcome
	// the caller asked for is true, but it was not this request's doing.
	if err := h.storage.DeleteFile(path); err != nil {
		writeFileError(w, err, "[delete]", "remove", path)
		return
	}

	if h.moderation != nil {
		if err := h.moderation.MarkDeleted(path); err != nil {
			// The file is gone either way; a stale metadata record is worth
			// a log line, not a failed response.
			log.Printf("[delete] mark metadata deleted %q: %v", path, err)
		}
	}

	log.Printf("[delete] removed %q (age %s)", path, time.Since(info.ModTime()).Round(time.Second))
	w.WriteHeader(http.StatusNoContent)
}
