package handler

import (
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"file-api/internal/middleware"
	"file-api/internal/moderation"
	"file-api/internal/storage"
	"file-api/internal/util"
)

// FetchHandler handles URL fetch requests (legacy /file-resize endpoint).
// Despite the name, this no longer resizes - it only fetches and stores the original.
type FetchHandler struct {
	storage       *storage.Storage
	moderation    *moderation.Service // may be nil when moderation is disabled
	maxUploadSize int64
	httpClient    *http.Client
	// jwtSecret is the shared HMAC key for the meta-token. Same
	// secret JWTAuth uses to verify incoming bearers.
	jwtSecret []byte
}

// NewFetchHandler creates a new FetchHandler.
func NewFetchHandler(s *storage.Storage, mod *moderation.Service, maxUploadSize int64, jwtSecret string) *FetchHandler {
	h := &FetchHandler{
		storage:       s,
		moderation:    mod,
		maxUploadSize: maxUploadSize,
		jwtSecret:     []byte(jwtSecret),
	}

	// The SSRF boundary is the dial guard, not the URL string checks. It runs
	// after name resolution on every hop, so it sees the address actually being
	// connected to - which is the only thing a hostname, an unusual IP spelling
	// or a rebinding DNS answer cannot lie about. Cloned from DefaultTransport
	// so HTTP/2, connection pooling and its timeouts are unchanged.
	//
	// Proxying is disabled deliberately. DefaultTransport honours HTTP_PROXY
	// and HTTPS_PROXY, and with a proxy in play every request dials the proxy
	// instead of the target: the guard would approve the proxy's public address
	// while the proxy went on to resolve and connect to whatever the caller
	// asked for. That is the whole bypass back again, switched on by an
	// environment variable. Nothing here needs an egress proxy, so the guard
	// stays the boundary unconditionally. If one is ever required, the
	// destination filtering has to move to the proxy - it cannot be done here.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   util.SafeDialControl,
	}).DialContext

	h.httpClient = &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			// Cheap pre-filter on the redirect target. The dial guard is what
			// actually enforces it; this keeps the failure legible.
			if !util.IsValidURL(req.URL.String()) {
				return fmt.Errorf("redirect to disallowed URL: %s", req.URL.Host)
			}
			return nil
		},
	}

	return h
}

// URL extraction pattern - matches /url/ followed by the URL
var urlPattern = regexp.MustCompile(`/url/(.+)$`)

// ServeHTTP handles POST /file-resize and POST /file-resize/cli/{code}
// URL format: /file-resize/url/{url} or /file-resize/cli/{code}/url/{url}
func (h *FetchHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	claims := middleware.GetClaims(r)
	if claims == nil || !claims.HasScope("upload") {
		http.Error(w, "Forbidden: upload scope required", http.StatusForbidden)
		return
	}

	clientCode, refusal := fetchClientCode(r.URL.Path, claims)
	if refusal != nil {
		http.Error(w, refusal.msg, refusal.status)
		return
	}

	fetchURL, err := extractURL(r.URL.Path)
	if err != nil || !util.IsValidURL(fetchURL) {
		http.Error(w, "No url or not a valid url", http.StatusBadRequest)
		return
	}

	// Dimensions posted with the request, kept for legacy clients: a fallback
	// for formats the probe cannot read, and pass-through thumbnail values.
	dims := readFormDims(r)

	resp, err := h.download(fetchURL)
	if err != nil {
		http.Error(w, "This file cannot be downloaded", http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	// Store the fetched content, bounded by the same size limit as an upload.
	filename := extractFilenameFromResponse(resp, fetchURL)
	info, err := h.storage.StoreFile(http.MaxBytesReader(w, resp.Body, h.maxUploadSize), filename, clientCode)
	if err != nil {
		http.Error(w, "Failed to store file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Fetched files are not scanned (see ProcessUpload's callers), but a
	// fetch can re-create a path that was deleted, and the deleted record
	// must not outlive the file's return.
	if h.moderation != nil {
		h.moderation.Stored(info.RelativePath)
	}

	// Same probe and response as an upload, see upload.go.
	dims.origWidth, dims.origHeight = probeStoredDims(h.storage, info.RelativePath, dims.origWidth, dims.origHeight, "[fetch]")
	writeStoredResponse(w, h.jwtSecret, info, dims, "[fetch]")
}

// httpError is a refusal a helper decided on and the handler writes.
type httpError struct {
	status int
	msg    string
}

// fetchClientCode returns the client code of a private fetch, "" for a public
// one, or the refusal to answer with. The code is looked for only in the API
// part of the path, before /url/, never in the destination URL that follows.
//
//	public:  /file-resize/url/{url}
//	private: /file-resize/cli/{code}/url/{url}
func fetchClientCode(path string, claims *middleware.Claims) (string, *httpError) {
	urlIdx := strings.Index(path, "/url/")
	if urlIdx <= 0 || !strings.Contains(path[:urlIdx], "/cli/") {
		return "", nil
	}
	code := extractClientCodeFromFetchPath(path[:urlIdx])
	switch {
	case code == "":
		return "", nil
	case !util.IsValidClientCode(code):
		return "", &httpError{http.StatusBadRequest, "Der Pfad/Client Code muss alphanumerisch sein"}
	case claims.ClientCode != code:
		return "", &httpError{http.StatusForbidden, msgForbidden}
	}
	return code, nil
}

// download GETs fetchURL through the guarded client. Anything but a 200 is an
// error, with the body already closed.
func (h *FetchHandler) download(fetchURL string) (*http.Response, error) {
	resp, err := h.httpClient.Get(fetchURL)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return resp, nil
}

// extractURL extracts the URL from the request path.
// Path format: /file-resize/url/{url} or /file-resize/cli/{code}/url/{url}
// The :/ in URLs is collapsed to :// by the browser/proxy
func extractURL(path string) (string, error) {
	matches := urlPattern.FindStringSubmatch(path)
	if len(matches) < 2 {
		return "", fmt.Errorf("no URL found in path")
	}

	url := matches[1]

	// Fix collapsed scheme: "https:/example.com" -> "https://example.com"
	// This happens because :// in URLs gets collapsed to :/ by some proxies
	if strings.Contains(url, ":/") && !strings.Contains(url, "://") {
		url = strings.Replace(url, ":/", "://", 1)
	}

	return url, nil
}

// extractClientCodeFromFetchPath extracts the client code from fetch paths.
// Path format: /file-resize/cli/{code}/url/{url}
func extractClientCodeFromFetchPath(path string) string {
	idx := strings.Index(path, "/cli/")
	if idx == -1 {
		return ""
	}

	rest := path[idx+5:]
	endIdx := strings.Index(rest, "/")
	if endIdx == -1 {
		return rest
	}
	return rest[:endIdx]
}

// extractFilenameFromResponse names a fetched file: from the response's
// Content-Disposition, else from the URL's last path segment, else from its
// Content-Type. The name is sanitised by StoreFile either way.
func extractFilenameFromResponse(resp *http.Response, rawURL string) string {
	if name := filenameFromDisposition(resp.Header.Get("Content-Disposition")); name != "" {
		return name
	}
	if name := filenameFromURL(rawURL); name != "" {
		return name
	}
	return defaultFilename(resp.Header.Get("Content-Type"))
}

// filenameFromDisposition returns the filename parameter of a
// Content-Disposition header, or "". mime.ParseMediaType handles quoting,
// further parameters after the filename, and the RFC 2231 encoded form, which
// it decodes into "filename":
//
//	attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf
func filenameFromDisposition(header string) string {
	if header == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(header)
	if err != nil {
		return ""
	}
	return params["filename"]
}

// filenameFromURL returns the last segment of the URL's path, without query or
// fragment, or "" when the path is empty or ends in a slash.
func filenameFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" || strings.HasSuffix(u.Path, "/") {
		return ""
	}
	return path.Base(u.Path)
}

// defaultNames picks a filename by content type when nothing better is known.
var defaultNames = []struct{ contentType, name string }{
	{"image/jpeg", "download.jpg"},
	{"image/png", "download.png"},
	{"image/gif", "download.gif"},
	{"image/webp", "download.webp"},
	{"application/pdf", "download.pdf"},
}

func defaultFilename(contentType string) string {
	for _, d := range defaultNames {
		if strings.Contains(contentType, d.contentType) {
			return d.name
		}
	}
	return "download.bin"
}
