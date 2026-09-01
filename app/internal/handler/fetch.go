package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"file-api/internal/auth"
	"file-api/internal/image"
	"file-api/internal/middleware"
	"file-api/internal/storage"
	"file-api/internal/util"
)

// FetchHandler handles URL fetch requests (legacy /file-resize endpoint).
// Despite the name, this no longer resizes - it only fetches and stores the original.
type FetchHandler struct {
	storage       *storage.Storage
	maxUploadSize int64
	httpClient    *http.Client
	// jwtSecret is the shared HMAC key for the meta-token. Same
	// secret JWTAuth uses to verify incoming bearers.
	jwtSecret []byte
}

// NewFetchHandler creates a new FetchHandler.
func NewFetchHandler(s *storage.Storage, maxUploadSize int64, jwtSecret string) *FetchHandler {
	h := &FetchHandler{
		storage:       s,
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

	// Check for upload scope
	claims := middleware.GetClaims(r)
	if claims == nil || !claims.HasScope("upload") {
		http.Error(w, "Forbidden: upload scope required", http.StatusForbidden)
		return
	}

	// Extract client code if present
	clientCode := ""
	path := r.URL.Path

	// Check for /cli/{code} in API path only (before /url/), not in the destination URL
	// Private path format: /file-resize/cli/{code}/url/{url}
	// Public path format: /file-resize/url/{url}
	urlIdx := strings.Index(path, "/url/")
	if urlIdx > 0 {
		apiPrefix := path[:urlIdx]
		if strings.Contains(apiPrefix, "/cli/") {
			clientCode = extractClientCodeFromFetchPath(apiPrefix)
			if clientCode != "" {
				if !util.IsValidClientCode(clientCode) {
					http.Error(w, "Der Pfad/Client Code muss alphanumerisch sein", http.StatusBadRequest)
					return
				}
				if claims.ClientCode != clientCode {
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}
		}
	}

	// Extract URL from path
	fetchURL, err := extractURL(path)
	if err != nil || !util.IsValidURL(fetchURL) {
		http.Error(w, "No url or not a valid url", http.StatusBadRequest)
		return
	}

	// Fallback dimensions from form fields (kept for backward compat
	// with legacy clients that don't read the new meta_token field).
	// The probe below overrides them when it recognises the format.
	formOrigWidth, _ := strconv.Atoi(r.FormValue("orig_width"))
	formOrigHeight, _ := strconv.Atoi(r.FormValue("orig_height"))
	thumbWidth, _ := strconv.Atoi(r.FormValue("thumb_width"))
	thumbHeight, _ := strconv.Atoi(r.FormValue("thumb_height"))

	// Fetch the file from URL
	resp, err := h.httpClient.Get(fetchURL)
	if err != nil {
		http.Error(w, "This file cannot be downloaded", http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, "This file cannot be downloaded", http.StatusBadRequest)
		return
	}

	// Extract filename from URL or Content-Disposition header
	filename := extractFilenameFromResponse(resp, fetchURL)

	// Enforce size limit on fetched content
	limitedBody := http.MaxBytesReader(w, resp.Body, h.maxUploadSize)

	// Store the file
	info, err := h.storage.StoreFile(limitedBody, filename, clientCode)
	if err != nil {
		http.Error(w, "Failed to store file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Probe dims server-side. See upload.go for the rationale —
	// same fallback rules: probe wins on a recognised format, form
	// fields win when the probe returns zero.
	origWidth, origHeight := formOrigWidth, formOrigHeight
	absPath := h.storage.GetFilePath(info.RelativePath)
	pw, ph, perr := image.ProbeDims(absPath)
	if perr != nil {
		log.Printf("[fetch] probe %s: %v", info.RelativePath, perr)
	}
	if pw > 0 && ph > 0 {
		origWidth, origHeight = pw, ph
	}

	metaToken, mErr := auth.Mint(h.jwtSecret, info.RelativePath, info.Size, origWidth, origHeight)
	if mErr != nil {
		log.Printf("[fetch] mint meta_token: %v", mErr)
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

// extractFilenameFromResponse extracts a filename from HTTP response or URL.
func extractFilenameFromResponse(resp *http.Response, url string) string {
	// Try Content-Disposition header first
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if strings.Contains(cd, "filename=") {
			// Extract filename from header
			parts := strings.Split(cd, "filename=")
			if len(parts) > 1 {
				filename := strings.Trim(parts[1], `"' `)
				if filename != "" {
					return filename
				}
			}
		}
	}

	// Extract from URL path
	lastSlash := strings.LastIndex(url, "/")
	if lastSlash >= 0 && lastSlash < len(url)-1 {
		filename := url[lastSlash+1:]
		// Remove query string if present
		if queryIdx := strings.Index(filename, "?"); queryIdx > 0 {
			filename = filename[:queryIdx]
		}
		if filename != "" {
			return filename
		}
	}

	// Default filename based on content type
	contentType := resp.Header.Get("Content-Type")
	switch {
	case strings.Contains(contentType, "image/jpeg"):
		return "download.jpg"
	case strings.Contains(contentType, "image/png"):
		return "download.png"
	case strings.Contains(contentType, "image/gif"):
		return "download.gif"
	case strings.Contains(contentType, "image/webp"):
		return "download.webp"
	case strings.Contains(contentType, "application/pdf"):
		return "download.pdf"
	default:
		return "download.bin"
	}
}
