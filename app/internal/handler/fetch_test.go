package handler

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"file-api/internal/middleware"
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
