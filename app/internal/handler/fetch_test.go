package handler

import (
	"bytes"
	"context"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"file-api/internal/middleware"
	"file-api/internal/moderation"
	"file-api/internal/scanner"
)

// TestFetchClientIgnoresEnvironmentProxy pins the reason transport.Proxy is
// nil. DefaultTransport honours HTTP_PROXY and HTTPS_PROXY, and a proxy would
// reopen the SSRF this handler's dial guard exists to close: every request
// would dial the proxy, the guard would approve the proxy's public address,
// and the proxy would then resolve and connect to whatever the caller asked
// for. Restoring the default transport, or dropping this assignment, must fail
// here rather than in production.
func TestFetchClientIgnoresEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.invalid:3128")
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:3128")

	h := NewFetchHandler(nil, nil, 1<<20, "test-secret")

	transport, ok := h.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected an *http.Transport, got %T", h.httpClient.Transport)
	}
	if transport.Proxy != nil {
		t.Error("fetch transport must not honour an environment proxy: a proxy dials the target itself, past the dial guard")
	}
	if transport.DialContext == nil {
		t.Error("fetch transport must install the guarded dialer")
	}
}

// newFetchTestHandler serves content from a local test server under a made-up
// public hostname. The URL pre-filter refuses a literal loopback address and
// the guarded client refuses to dial one, both by design and both with tests
// of their own, so the test client dials the server whatever the host.
func newFetchTestHandler(t *testing.T, handler http.HandlerFunc) (*FetchHandler, string) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	h := NewFetchHandler(newTestStorage(t), nil, 1<<20, testSecret)
	h.httpClient = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		},
	}}
	return h, "http://files.example.test"
}

func fetchRequest(target string, claims *middleware.Claims) *http.Request {
	return withClaims(httptest.NewRequest(http.MethodPost, target, nil), claims)
}

func TestFetchStoresProbesAndSigns(t *testing.T) {
	png := pngBytes(t, 24, 12)
	h, base := newFetchTestHandler(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Content-Disposition", `attachment; filename="photo.png"; size=123`)
		w.Write(png)
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, fetchRequest("/file-resize/url/"+base+"/img?x=1", &middleware.Claims{Scopes: []string{"upload"}}))

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	resp := decodeStored(t, rec)
	if !strings.Contains(resp.Orig.Name, "/photo-") || !strings.HasSuffix(resp.Orig.Name, ".png") {
		t.Errorf("filename from Content-Disposition not used: %q", resp.Orig.Name)
	}
	if resp.Orig.OrigWidth != 24 || resp.Orig.OrigHeight != 12 {
		t.Errorf("probe: got %dx%d", resp.Orig.OrigWidth, resp.Orig.OrigHeight)
	}
}

// TestFetchBoundsItsRequestBody pins the limit on the request body, which
// carries only the optional dimension fields. An oversized body - form-encoded
// or multipart - is refused with 413 before the download starts; a small one
// still delivers its fields.
func TestFetchBoundsItsRequestBody(t *testing.T) {
	var downloads atomic.Int32
	h, base := newFetchTestHandler(t, func(w http.ResponseWriter, r *http.Request) {
		downloads.Add(1)
		w.Write([]byte("fetched bytes"))
	})
	claims := &middleware.Claims{Scopes: []string{"upload"}}
	target := "/file-resize/url/" + base + "/a.bin"

	bigForm := strings.NewReader("thumb_width=8&pad=" + strings.Repeat("x", fetchFormLimit))
	req := withClaims(httptest.NewRequest(http.MethodPost, target, bigForm), claims)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized form: got %d, want 413", rec.Code)
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", "big.bin")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	part.Write(bytes.Repeat([]byte("x"), fetchFormLimit))
	mw.Close()
	req = withClaims(httptest.NewRequest(http.MethodPost, target, &body), claims)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized multipart: got %d, want 413", rec.Code)
	}
	if downloads.Load() != 0 {
		t.Error("a download started before the oversized request body was refused")
	}

	req = withClaims(httptest.NewRequest(http.MethodPost, target, strings.NewReader("thumb_width=8&thumb_height=6")), claims)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("small form: got %d: %s", rec.Code, rec.Body.String())
	}
	if resp := decodeStored(t, rec); resp.Orig.ThumbWidth != 8 || resp.Orig.ThumbHeight != 6 {
		t.Errorf("form fields lost: got %dx%d", resp.Orig.ThumbWidth, resp.Orig.ThumbHeight)
	}
}

// TestFetchModeratesLikeAnUpload pins that a fetched file goes through the
// same moderation as an uploaded one: a public fetch is scanned, a private
// fetch is not. Fetched bytes come from wherever the caller pointed, so
// leaving them out of scanning would make the fetch endpoint the way around it.
func TestFetchModeratesLikeAnUpload(t *testing.T) {
	var scans atomic.Int32
	scannerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scans.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"infected":false,"scan_time_ms":1}`))
	}))
	t.Cleanup(scannerSrv.Close)

	h, base := newFetchTestHandler(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("fetched bytes"))
	})
	dir := t.TempDir()
	h.moderation = moderation.NewService(scanner.NewClient(scannerSrv.URL, "", 5000), nil,
		filepath.Join(dir, "meta"), filepath.Join(dir, "queue"), h.storage.DeleteFile, h.storage.Open)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, fetchRequest("/file-resize/url/"+base+"/public.bin", &middleware.Claims{Scopes: []string{"upload"}}))
	if rec.Code != http.StatusOK {
		t.Fatalf("public fetch: got %d: %s", rec.Code, rec.Body.String())
	}
	public := decodeStored(t, rec).Orig.Name

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, fetchRequest("/file-resize/cli/ACME/url/"+base+"/private.bin", &middleware.Claims{Scopes: []string{"upload"}, ClientCode: "ACME"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("private fetch: got %d: %s", rec.Code, rec.Body.String())
	}
	private := decodeStored(t, rec).Orig.Name

	// The scan runs in the background; wait for its record.
	deadline := time.Now().Add(5 * time.Second)
	for {
		m, err := h.moderation.GetMetadata(public)
		if err == nil && m != nil && m.Status == moderation.StatusClean {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the public fetch was not scanned: record %+v, err %v", m, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if scans.Load() != 1 {
		t.Errorf("scanner calls %d, want 1: a private fetch is not scanned automatically", scans.Load())
	}
	if m, _ := h.moderation.GetMetadata(private); m != nil {
		t.Errorf("the private fetch got a scan record: %+v", m)
	}
}

func TestFetchRefusesFailedDownloads(t *testing.T) {
	h, base := newFetchTestHandler(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, fetchRequest("/file-resize/url/"+base+"/missing.png", &middleware.Claims{Scopes: []string{"upload"}}))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", rec.Code)
	}
}

func TestFetchRequiresUploadScopeAndValidURL(t *testing.T) {
	h, _ := newFetchTestHandler(t, func(http.ResponseWriter, *http.Request) {})
	cases := map[string]struct {
		target string
		claims *middleware.Claims
		want   int
	}{
		"no scope":     {"/file-resize/url/https://example.com/a.png", &middleware.Claims{}, http.StatusForbidden},
		"no url":       {"/file-resize", &middleware.Claims{Scopes: []string{"upload"}}, http.StatusBadRequest},
		"internal url": {"/file-resize/url/http://127.0.0.1/a.png", &middleware.Claims{Scopes: []string{"upload"}}, http.StatusBadRequest},
	}
	for name, tc := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, fetchRequest(tc.target, tc.claims))
		if rec.Code != tc.want {
			t.Errorf("%s: got %d, want %d", name, rec.Code, tc.want)
		}
	}
}

func TestFetchClientCode(t *testing.T) {
	acme := &middleware.Claims{ClientCode: "ACME"}
	cases := []struct {
		name       string
		path       string
		claims     *middleware.Claims
		wantCode   string
		wantStatus int
	}{
		{"public", "/file-resize/url/https://example.com/a.png", acme, "", 0},
		{"cli only inside the destination URL", "/file-resize/url/https://example.com/cli/X/a.png", acme, "", 0},
		{"own client", "/file-resize/cli/ACME/url/https://example.com/a.png", acme, "ACME", 0},
		{"other client", "/file-resize/cli/OTHER/url/https://example.com/a.png", acme, "", http.StatusForbidden},
		{"invalid code", "/file-resize/cli/A$B/url/https://example.com/a.png", acme, "", http.StatusBadRequest},
	}
	for _, tc := range cases {
		code, refusal := fetchClientCode(tc.path, tc.claims)
		status := 0
		if refusal != nil {
			status = refusal.status
		}
		if code != tc.wantCode || status != tc.wantStatus {
			t.Errorf("%s: got %q/%d, want %q/%d", tc.name, code, status, tc.wantCode, tc.wantStatus)
		}
	}
}

func TestExtractFilenameFromResponse(t *testing.T) {
	cases := []struct {
		name, disposition, contentType, url, want string
	}{
		{"quoted, with further parameters", `attachment; filename="report.pdf"; size=42`, "", "https://x.test/dl", "report.pdf"},
		{"RFC 2231 encoded", `attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf`, "", "https://x.test/dl", "résumé.pdf"},
		{"malformed header falls back to the URL", `attachment; filename=a b.pdf`, "", "https://x.test/files/a.pdf", "a.pdf"},
		{"URL without query and fragment", "", "", "https://x.test/img/cat.jpg?w=10#top", "cat.jpg"},
		{"trailing slash falls back to the type", "", "image/png", "https://x.test/img/", "download.png"},
		{"unknown type", "", "application/x-thing", "https://x.test/", "download.bin"},
	}
	for _, tc := range cases {
		resp := &http.Response{Header: http.Header{}}
		if tc.disposition != "" {
			resp.Header.Set("Content-Disposition", tc.disposition)
		}
		if tc.contentType != "" {
			resp.Header.Set("Content-Type", tc.contentType)
		}
		if got := extractFilenameFromResponse(resp, tc.url); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
