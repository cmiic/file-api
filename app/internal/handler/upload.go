// Package handler provides HTTP handlers for the file API.
package handler

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"

	"file-api/internal/auth"
	"file-api/internal/image"
	"file-api/internal/middleware"
	"file-api/internal/moderation"
	"file-api/internal/storage"
	"file-api/internal/util"
)

// UploadHandler handles file upload requests.
type UploadHandler struct {
	storage       *storage.Storage
	moderation    *moderation.Service
	maxUploadSize int64
	// jwtSecret is the shared HMAC key for the meta-token file-api
	// hands back to callers. Same secret used by JWTAuth for upload
	// verification — downstream backends already know it.
	jwtSecret []byte
}

// NewUploadHandler creates a new UploadHandler.
func NewUploadHandler(s *storage.Storage, mod *moderation.Service, maxUploadSize int64, jwtSecret string) *UploadHandler {
	return &UploadHandler{
		storage:       s,
		moderation:    mod,
		maxUploadSize: maxUploadSize,
		jwtSecret:     []byte(jwtSecret),
	}
}

// UploadResponse is the JSON response for successful uploads.
type UploadResponse struct {
	Orig OrigInfo `json:"orig"`
	// MetaToken is a short-lived (5 min) HMAC-signed JWT covering
	// the path + size + dims file-api just resolved. Downstream
	// backends verify it to defend against in-flight tampering by
	// the browser. Minted for every successful upload regardless
	// of MIME type — for non-image uploads the dims claim is 0/0,
	// but the path + size are still signed and worth verifying.
	// `omitempty` only suppresses the field on signing errors (the
	// handler logs them and ships an unsigned response so the
	// caller can decide whether to accept).
	MetaToken string `json:"meta_token,omitempty"`
}

// OrigInfo contains information about the stored original file.
type OrigInfo struct {
	Name string `json:"name"` // Relative path to the file
	Size int64  `json:"size"` // File size in bytes
	// OrigWidth/OrigHeight are now probed server-side from the
	// stored bytes. If a probe fails (unrecognised format / corrupt
	// header) the values fall back to whatever the caller posted in
	// the `orig_width` / `orig_height` form fields, preserving the
	// pre-Phase-19.1 contract for clients that supplied them.
	OrigWidth  int `json:"orig_width,omitempty"`
	OrigHeight int `json:"orig_height,omitempty"`
	// Thumb dims remain pure pass-through — file-api has never had
	// thumbnail info; callers that resize for themselves carry the
	// values opaquely so the upload row records them in one trip.
	ThumbWidth  int `json:"thumb_width,omitempty"`
	ThumbHeight int `json:"thumb_height,omitempty"`
}

// ServeHTTP handles POST /file-upload and POST /file-upload/cli/{code}
func (h *UploadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Enforce upload size limit before reading body
	r.Body = http.MaxBytesReader(w, r.Body, h.maxUploadSize)

	// Check for upload scope
	claims := middleware.GetClaims(r)
	if claims == nil || !claims.HasScope("upload") {
		http.Error(w, "Forbidden: upload scope required", http.StatusForbidden)
		return
	}

	// Extract client code from path if present
	clientCode := extractClientCode(r.URL.Path, "/file-upload")

	// Validate client code if present
	if clientCode != "" {
		if !util.IsValidClientCode(clientCode) {
			http.Error(w, "Der Pfad/Client Code muss alphanumerisch sein", http.StatusBadRequest)
			return
		}
		// Verify JWT allows access to this client
		if claims.ClientCode != clientCode {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}

	// Parse multipart form
	if err := r.ParseMultipartForm(32 << 20); err != nil { // 32MB max memory
		// Check if error is due to size limit
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "File too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Failed to parse multipart form", http.StatusBadRequest)
		return
	}

	// Get the file from the form
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "No file provided", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Fallback dimensions from form fields. These remain the source
	// of truth ONLY when the server-side probe can't recognise the
	// format (e.g. a brand-new image type stdlib doesn't decode).
	// Clients that don't supply them simply get 0/0 in that case.
	formOrigWidth, _ := strconv.Atoi(r.FormValue("orig_width"))
	formOrigHeight, _ := strconv.Atoi(r.FormValue("orig_height"))
	thumbWidth, _ := strconv.Atoi(r.FormValue("thumb_width"))
	thumbHeight, _ := strconv.Atoi(r.FormValue("thumb_height"))

	// Store the file
	info, err := h.storage.StoreFile(file, header.Filename, clientCode)
	if err != nil {
		http.Error(w, "Failed to store file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Probe dims server-side from the persisted bytes. Probe errors
	// only get logged — they never fail the upload, and the form
	// fallback covers the response.
	origWidth, origHeight := formOrigWidth, formOrigHeight
	absPath := h.storage.GetFilePath(info.RelativePath)
	pw, ph, perr := image.ProbeDims(absPath)
	if perr != nil {
		log.Printf("[upload] probe %s: %v", info.RelativePath, perr)
	}
	if pw > 0 && ph > 0 {
		origWidth, origHeight = pw, ph
	}

	// Mint the meta_token so downstream backends can verify the
	// dims weren't tampered with after they left this process.
	// Errors are logged + the response goes out without the field;
	// strict backends (e.g. web-api) will then 400.
	metaToken, mErr := auth.Mint(h.jwtSecret, info.RelativePath, info.Size, origWidth, origHeight)
	if mErr != nil {
		log.Printf("[upload] mint meta_token: %v", mErr)
	}

	// Trigger async moderation scan for public uploads
	isPublic := clientCode == ""
	if h.moderation != nil {
		h.moderation.ProcessUpload(info.RelativePath, absPath, clientCode, info.SHA1, isPublic)
	}

	// Build response
	response := UploadResponse{
		Orig: OrigInfo{
			Name:        info.RelativePath,
			Size:        info.Size,
			OrigWidth:   origWidth,
			OrigHeight:  origHeight,
			ThumbWidth:  thumbWidth,
			ThumbHeight: thumbHeight,
		},
		MetaToken: metaToken,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// extractClientCode extracts the client code from a URL path.
// For paths like /file-upload/cli/{code} or /file-resize/cli/{code}
func extractClientCode(path, prefix string) string {
	// Check if path has /cli/ after the prefix
	if len(path) <= len(prefix)+5 { // prefix + "/cli/"
		return ""
	}

	rest := path[len(prefix):]
	if len(rest) < 5 || rest[:5] != "/cli/" {
		return ""
	}

	// Extract the client code
	code := rest[5:]
	// Remove trailing path components if any
	for i, c := range code {
		if c == '/' {
			return code[:i]
		}
	}
	return code
}
