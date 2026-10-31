// Package handler provides HTTP handlers for the file API.
package handler

import (
	"errors"
	"io"
	"mime/multipart"
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
	// The MaxBytesReader set above is the enforcement for bodies of unknown
	// or understated length; this only spares the volume the partial write.
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
	// cannot read, and pass-through thumbnail values. A body field wins over
	// the same name in the URL query, as FormValue had it; the query is kept
	// as the fallback it always was.
	query := r.URL.Query()
	dims := dimsFromValues(func(field string) string {
		if v := fields.Get(field); v != "" {
			return v
		}
		return query.Get(field)
	})

	// Probe dims server-side from the persisted bytes; the form values only
	// stand in when the format is not recognised.
	dims.origWidth, dims.origHeight = probeStoredDims(h.storage, info.RelativePath, dims.origWidth, dims.origHeight, "[upload]")

	// Trigger async moderation scan for public uploads
	if h.moderation != nil {
		h.moderation.ProcessUpload(info.RelativePath, clientCode, info.SHA1, clientCode == "")
	}

	writeStoredResponse(w, h.jwtSecret, info, dims, "[upload]")
}

// uploadFieldLimit bounds a form field the handler reads. The fields are
// four small integers; a longer value is not one of them.
const uploadFieldLimit = 1 << 10

// uploadFields are the form fields the handler reads. Only these are kept,
// first value each; every other part is drained and forgotten, so a body full
// of small parts costs reading it and nothing more. ParseMultipartForm kept
// every field and bounded them in aggregate; this keeps four.
var uploadFields = map[string]bool{"orig_width": true, "orig_height": true, "thumb_width": true, "thumb_height": true}

// storeMultipart reads the multipart body part by part, streams the file
// part onto the storage volume as it arrives, and publishes it once the whole
// body has been read and found good. It returns the stored file and the form
// fields it reads.
//
// ParseMultipartForm would first write a file part over its memory budget to
// a temp file under os.TempDir and hand that file to StoreFile: every upload
// above the budget crossed the disk twice and needed as much temp space as it
// was large, on a path that is not the data volume. The bytes now go once,
// straight to the volume the file ends up on, and nothing about the upload
// limit has to be mirrored in the size of a temp directory.
//
// The file is staged, not stored, while the parts after it are read. Until
// Commit nothing exists under the final path: a request refused after its
// file part - an overlong field, a body cut off before its closing boundary -
// publishes nothing, so there is no window in which the file is served before
// the moderation that an accepted upload gets, and no published file to take
// back from a concurrent upload that may already have deduplicated onto it.
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
	staged, refusal := h.readParts(mr, clientCode, fields)
	if refusal != nil {
		if staged != nil {
			staged.Discard()
		}
		return nil, nil, refusal
	}
	if staged == nil {
		return nil, nil, &httpError{http.StatusBadRequest, "No file provided"}
	}
	info, err := staged.Commit()
	if err != nil {
		return nil, nil, &httpError{http.StatusInternalServerError, "Failed to store file: " + err.Error()}
	}
	return info, fields, nil
}

// readParts walks the parts to the end of the body. It returns the staged
// file, if a file part was reached, alongside any refusal, so that the caller
// can discard it.
func (h *UploadHandler) readParts(mr *multipart.Reader, clientCode string, fields url.Values) (*storage.Staged, *httpError) {
	var staged *storage.Staged
	for {
		part, err := mr.NextPart()
		// The reader's clean end is the bare io.EOF. A body cut off before
		// its closing boundary surfaces as a wrapped EOF, which errors.Is
		// would take for the same thing; it is a malformed body.
		if err == io.EOF {
			return staged, nil
		}
		if err != nil {
			return staged, multipartRefusal(err)
		}
		var refusal *httpError
		switch {
		case part.FormName() != "file" || part.FileName() == "":
			refusal = readField(part, fields)
		case staged != nil:
			if _, err := io.Copy(io.Discard, part); err != nil {
				refusal = multipartRefusal(err)
			}
		default:
			staged, refusal = h.stageFilePart(part, clientCode)
		}
		part.Close()
		if refusal != nil {
			return staged, refusal
		}
	}
}

// readField keeps the first value of a field the handler reads and drains
// any other part.
func readField(part *multipart.Part, fields url.Values) *httpError {
	name := part.FormName()
	if !uploadFields[name] || fields.Has(name) {
		if _, err := io.Copy(io.Discard, part); err != nil {
			return multipartRefusal(err)
		}
		return nil
	}
	value, err := io.ReadAll(io.LimitReader(part, uploadFieldLimit+1))
	if err != nil {
		return multipartRefusal(err)
	}
	if len(value) > uploadFieldLimit {
		return &httpError{http.StatusBadRequest, "Form field too long"}
	}
	fields.Set(name, string(value))
	return nil
}

// stageFilePart streams the part onto the storage volume. A failure to read
// the part is the client's body ending early or the body limit, and is
// answered as such; only a failure with the part read cleanly is the
// storage's.
func (h *UploadHandler) stageFilePart(part *multipart.Part, clientCode string) (*storage.Staged, *httpError) {
	src := &readTracker{Reader: part}
	staged, err := h.storage.Stage(src, part.FileName(), clientCode)
	if err != nil {
		if src.err != nil {
			return nil, multipartRefusal(src.err)
		}
		return nil, &httpError{http.StatusInternalServerError, "Failed to store file: " + err.Error()}
	}
	return staged, nil
}

// readTracker remembers the first error, other than a clean end, that the
// wrapped reader returned, so that it can be told apart from an error of
// whatever consumed the reader.
type readTracker struct {
	io.Reader
	err error
}

func (t *readTracker) Read(p []byte) (int, error) {
	n, err := t.Reader.Read(p)
	if err != nil && err != io.EOF && t.err == nil {
		t.err = err
	}
	return n, err
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
