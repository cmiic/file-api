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
// sent. Deletion is therefore opt-in and narrow, whether it serves the
// accidental upload noticed shortly after it happens or an application that
// keeps track of what it stored:
//
//   - the token needs a dedicated "delete" scope, so an upload token that
//     leaks or is minted too broadly cannot remove anything;
//   - private paths require the token's client code to match, as for upload;
//   - the token's delete_path claim must name exactly this file, so a token
//     removes one file and a shared session cookie removes none. The scope
//     stays required alongside it: the meta_token returned by an upload is
//     signed with the same secret and also names a path, but has no scopes;
//   - the file must be younger than the window for its class of file, public
//     or private. Its mtime is the first upload time (rename preserves it and
//     a deduplicated re-upload never touches the existing file), so under a
//     finite window an old file cannot be removed even with a valid token.
//     That bounds what a wrong token can do to the archive. An operator can
//     lift the bound per class by configuring it as unlimited.
//
// What this handler does not promise: the bytes may remain in reverse-proxy
// and image caches until they expire there, and uploaders of identical content
// under the same filename in the same month share one path, so a delete by
// any of them removes it for all.
type DeleteHandler struct {
	storage       *storage.Storage
	moderation    *moderation.Service
	publicMaxAge  time.Duration
	privateMaxAge time.Duration
}

// NewDeleteHandler creates a DeleteHandler. mod may be nil when moderation is
// disabled. A zero window disables deletion for that class of file; main.go
// does not register the route when both are zero.
func NewDeleteHandler(s *storage.Storage, mod *moderation.Service, publicMaxAge, privateMaxAge time.Duration) *DeleteHandler {
	return &DeleteHandler{storage: s, moderation: mod, publicMaxAge: publicMaxAge, privateMaxAge: privateMaxAge}
}

// maxAgeFor returns the window for a cleaned path. It has to be decided here
// rather than by routing: the mux matches the escaped path, so an encoded
// slash in "cli%2FACME%2F..." would reach a route for public files.
func (h *DeleteHandler) maxAgeFor(path string) time.Duration {
	if storage.IsPrivatePath(path) {
		return h.privateMaxAge
	}
	return h.publicMaxAge
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

	// With a window for only one class of file the route exists, so this is
	// the handler's answer rather than the mux's. Same status, same meaning:
	// deletion is not offered for this file.
	maxAge := h.maxAgeFor(path)
	if maxAge == 0 {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if status := authorizeClientPath(claims, path); status != 0 {
		http.Error(w, http.StatusText(status), status)
		return
	}

	// An exact match against the cleaned path, the same form an upload returns
	// as orig.name. Checked before the file is touched, so a token for another
	// file learns nothing about whether this one exists.
	if claims.DeletePath != path {
		http.Error(w, "Forbidden: token is not bound to this file", http.StatusForbidden)
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
	if time.Since(info.ModTime()) > maxAge {
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
