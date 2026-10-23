package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"file-api/internal/auth"
	"file-api/internal/image"
	"file-api/internal/middleware"
	"file-api/internal/storage"
)

// Response texts used by more than one handler.
const (
	msgNotFound      = "Not Found"
	msgInternalError = "Internal Server Error"
	msgForbidden     = "Forbidden"
	msgInvalidPath   = "Invalid path"
)

// requestFilePath turns the URL path of a /files/ request into a path relative
// to the storage root, or reports that the request names no valid file.
//
// SanitizeRequestPath cleans the path and refuses traversal, but lets a leading
// slash through: an encoded "%2fetc%2fpasswd" arrives decoded as "/etc/passwd".
// The storage root would refuse that too, with a containment error rather than
// not-exist, which the callers would report as a 500. An absolute path is
// simply not a valid request, so it is refused here, before storage is touched.
func requestFilePath(urlPath string) (string, bool) {
	p := strings.TrimPrefix(urlPath, "/files/")
	p = strings.TrimPrefix(p, "/files")
	clean, err := storage.SanitizeRequestPath(p)
	if err != nil || strings.HasPrefix(clean, "/") {
		return "", false
	}
	return clean, true
}

// authorizeClientPath decides whether claims may act on path. Public paths need
// nothing. A private path (cli/{code}/...) needs a token whose client code
// matches the path's: 401 without a token, 403 with a token for another client.
// It returns 0 when access is allowed, otherwise the status to answer with.
func authorizeClientPath(claims *middleware.Claims, path string) int {
	if !storage.IsPrivatePath(path) {
		return 0
	}
	if claims == nil {
		return http.StatusUnauthorized
	}
	code := storage.ExtractClientCode(path)
	if code == "" || claims.ClientCode != code {
		return http.StatusForbidden
	}
	return 0
}

// writeFileError answers a failed storage operation on path: 404 when the file
// is not there, otherwise a logged 500. The underlying error is logged, never
// sent, because it can carry absolute filesystem paths.
func writeFileError(w http.ResponseWriter, err error, logPrefix, op, path string) {
	if os.IsNotExist(err) {
		http.Error(w, msgNotFound, http.StatusNotFound)
		return
	}
	log.Printf("%s %s %q: %v", logPrefix, op, path, err)
	http.Error(w, msgInternalError, http.StatusInternalServerError)
}

// statRegularFile stats path and answers the request itself unless it names a
// regular file: 404 for a missing file or a directory, a logged 500 otherwise.
// ok reports whether the caller should carry on.
func statRegularFile(w http.ResponseWriter, s *storage.Storage, path, logPrefix string) (info os.FileInfo, ok bool) {
	info, err := s.Stat(path)
	if err != nil {
		writeFileError(w, err, logPrefix, "stat", path)
		return nil, false
	}
	if info.IsDir() {
		http.Error(w, msgNotFound, http.StatusNotFound)
		return nil, false
	}
	return info, true
}

// openRegularFile opens path for serving and answers the request itself unless
// it is a regular file: 404 for a missing file or a directory, a logged 500
// otherwise. It stats the open file rather than the path, so the checks and
// the bytes served come from one lookup: a file removed concurrently is a
// clean 404 before the caller has set any header. The caller closes f.
func openRegularFile(w http.ResponseWriter, s *storage.Storage, path, logPrefix string) (f *os.File, info os.FileInfo, ok bool) {
	f, err := s.Open(path)
	if err != nil {
		writeFileError(w, err, logPrefix, "open", path)
		return nil, nil, false
	}
	info, err = f.Stat()
	if err != nil {
		f.Close()
		writeFileError(w, err, logPrefix, "stat", path)
		return nil, nil, false
	}
	if info.IsDir() {
		f.Close()
		http.Error(w, msgNotFound, http.StatusNotFound)
		return nil, nil, false
	}
	return f, info, true
}

// formDims are the dimensions a client may post alongside an upload or fetch.
// The original's are only a fallback for formats the server-side probe cannot
// read; the thumbnail's are passed through untouched, as they always were.
type formDims struct {
	origWidth, origHeight   int
	thumbWidth, thumbHeight int
}

// readFormDims reads the optional dimension form fields. A missing or
// malformed value counts as 0, which is what clients have always relied on.
func readFormDims(r *http.Request) formDims {
	atoi := func(field string) int {
		v, _ := strconv.Atoi(r.FormValue(field))
		return v
	}
	return formDims{
		origWidth:   atoi("orig_width"),
		origHeight:  atoi("orig_height"),
		thumbWidth:  atoi("thumb_width"),
		thumbHeight: atoi("thumb_height"),
	}
}

// probeStoredDims reads the dimensions of a stored file from its bytes. The
// probe wins whenever it recognises the format; otherwise the client's fallback
// values are returned unchanged. Probe failures are logged and never fail the
// request.
func probeStoredDims(s *storage.Storage, path string, fallbackWidth, fallbackHeight int, logPrefix string) (int, int) {
	f, err := s.Open(path)
	if err != nil {
		log.Printf("%s open for probe %q: %v", logPrefix, path, err)
		return fallbackWidth, fallbackHeight
	}
	defer f.Close()
	width, height, err := image.ProbeDims(f)
	if err != nil {
		log.Printf("%s probe %q: %v", logPrefix, path, err)
	}
	if width > 0 && height > 0 {
		return width, height
	}
	return fallbackWidth, fallbackHeight
}

// writeStoredResponse answers a successful upload or fetch: the stored file's
// name, size and dimensions, and a meta_token signing them so a downstream
// backend can tell they were not altered in the browser. A signing failure is
// logged and the response goes out without the token, leaving it to the
// backend whether to accept that.
func writeStoredResponse(w http.ResponseWriter, secret []byte, info *storage.FileInfo, dims formDims, logPrefix string) {
	width, height := dims.origWidth, dims.origHeight
	metaToken, err := auth.Mint(secret, info.RelativePath, info.Size, width, height)
	if err != nil {
		log.Printf("%s mint meta_token: %v", logPrefix, err)
	}
	response := UploadResponse{
		Orig: OrigInfo{
			Name:        info.RelativePath,
			Size:        info.Size,
			OrigWidth:   width,
			OrigHeight:  height,
			ThumbWidth:  dims.thumbWidth,
			ThumbHeight: dims.thumbHeight,
		},
		MetaToken: metaToken,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("%s write response: %v", logPrefix, err)
	}
}
