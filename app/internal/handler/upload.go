// Package handler provides HTTP handlers for the file API.
package handler

import (
	"errors"
	"io"
	"net/http"
	"net/url"

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

	// A declared length over the limit is refused before a byte is read.
	// MaxBytesReader below is the enforcement for bodies of unknown or
	// understated length; this only spares the volume the partial write.
	if r.ContentLength > h.maxUploadSize {
		http.Error(w, "File too large", http.StatusRequestEntityTooLarge)
		return
	}

	info, fields, refusal := h.storeMultipart(r, clientCode)
	if refusal != nil {
		http.Error(w, refusal.msg, refusal.status)
		return
	}

	// Dimensions posted with the upload: a fallback for formats the probe
	// cannot read, and pass-through thumbnail values.
	dims := dimsFromValues(fields.Get)

	// Probe dims server-side from the persisted bytes; the form values only
	// stand in when the format is not recognised.
	dims.origWidth, dims.origHeight = probeStoredDims(h.storage, info.RelativePath, dims.origWidth, dims.origHeight, "[upload]")

	// Trigger async moderation scan for public uploads
	if h.moderation != nil {
		h.moderation.ProcessUpload(info.RelativePath, clientCode, info.SHA1, clientCode == "")
	}

	writeStoredResponse(w, h.jwtSecret, info, dims, "[upload]")
}

// uploadFieldLimit bounds a non-file part of the upload form. The fields the
// handler reads are four small integers; a longer value is not one of them.
const uploadFieldLimit = 1 << 10

// storeMultipart reads the multipart body part by part and streams the file
// part into storage as it arrives, returning the stored file and the other
// form fields.
//
// ParseMultipartForm would first write a file part over its memory budget to
// a temp file under os.TempDir and hand that file to StoreFile: every upload
// above the budget crossed the disk twice and needed as much temp space as it
// was large, on a path that is not the data volume. The bytes now go once,
// straight to the volume the file ends up on, and nothing about the upload
// limit has to be mirrored in the size of a temp directory.
//
// The first part named "file" that carries a filename is the upload, as
// FormFile chose it; a second one is drained and ignored. The other fields may
// precede or follow the file part, as the client orders them, so they are
// collected until the body ends and read only then.
func (h *UploadHandler) storeMultipart(r *http.Request, clientCode string) (*storage.FileInfo, url.Values, *httpError) {
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, nil, &httpError{http.StatusBadRequest, "Failed to parse multipart form"}
	}
	fields := url.Values{}
	var info *storage.FileInfo
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, multipartRefusal(err)
		}
		switch {
		case part.FormName() != "file" || part.FileName() == "":
			value, err := io.ReadAll(io.LimitReader(part, uploadFieldLimit+1))
			if err != nil {
				return nil, nil, multipartRefusal(err)
			}
			if len(value) > uploadFieldLimit {
				return nil, nil, &httpError{http.StatusBadRequest, "Form field too long"}
			}
			fields.Add(part.FormName(), string(value))
		case info != nil:
			if _, err := io.Copy(io.Discard, part); err != nil {
				return nil, nil, multipartRefusal(err)
			}
		default:
			info, err = h.storage.StoreFile(part, part.FileName(), clientCode)
			if err != nil {
				var maxBytesErr *http.MaxBytesError
				if errors.As(err, &maxBytesErr) {
					return nil, nil, &httpError{http.StatusRequestEntityTooLarge, "File too large"}
				}
				return nil, nil, &httpError{http.StatusInternalServerError, "Failed to store file: " + err.Error()}
			}
		}
		part.Close()
	}
	if info == nil {
		return nil, nil, &httpError{http.StatusBadRequest, "No file provided"}
	}
	return info, fields, nil
}

// multipartRefusal maps an error from reading the multipart body: the body
// limit is a 413, anything else a malformed body.
func multipartRefusal(err error) *httpError {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		return &httpError{http.StatusRequestEntityTooLarge, "File too large"}
	}
	return &httpError{http.StatusBadRequest, "Failed to parse multipart form"}
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
