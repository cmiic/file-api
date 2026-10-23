package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"file-api/internal/middleware"
)

type serveFixture struct {
	mux     http.Handler
	public  string // a stored public PNG
	private string // a stored private PDF of client ACME
	text    string // a stored public text file
}

func newServeFixture(t *testing.T) *serveFixture {
	t.Helper()
	s := newTestStorage(t)
	store := func(content, name, client string) string {
		info, err := s.StoreFile(strings.NewReader(content), name, client)
		if err != nil {
			t.Fatalf("StoreFile: %v", err)
		}
		return info.RelativePath
	}
	mux := http.NewServeMux()
	mux.Handle("GET /files/", NewServeHandler(s))
	return &serveFixture{
		mux:     mux,
		public:  store(string(pngBytes(t, 4, 4)), "pic.png", ""),
		private: store("%PDF-1.4", "doc.pdf", "ACME"),
		text:    store("<script>alert(1)</script>", "page.html", ""),
	}
}

func (f *serveFixture) get(target string, claims *middleware.Claims) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if claims != nil {
		req = withClaims(req, claims)
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

func TestServePublicFile(t *testing.T) {
	f := newServeFixture(t)
	rec := f.get("/files/"+f.public, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Errorf("Cache-Control %q", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "image/png" {
		t.Errorf("Content-Type %q", got)
	}
	if got := rec.Header().Get("Content-Disposition"); got != "" {
		t.Errorf("an image is served inline, got Content-Disposition %q", got)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("security headers missing")
	}
}

func TestServeForcesDownloadForUnsafeTypes(t *testing.T) {
	f := newServeFixture(t)
	rec := f.get("/files/"+f.text, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Disposition"); !strings.HasPrefix(got, "attachment;") {
		t.Errorf("HTML must download, got Content-Disposition %q", got)
	}
}

func TestServePrivateFileChecksClientCode(t *testing.T) {
	f := newServeFixture(t)

	if rec := f.get("/files/"+f.private, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: got %d, want 401", rec.Code)
	}
	if rec := f.get("/files/"+f.private, &middleware.Claims{ClientCode: "OTHER"}); rec.Code != http.StatusForbidden {
		t.Errorf("other client: got %d, want 403", rec.Code)
	}
	rec := f.get("/files/"+f.private, &middleware.Claims{ClientCode: "ACME"})
	if rec.Code != http.StatusOK {
		t.Fatalf("owner: got %d", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Errorf("private Cache-Control %q", got)
	}
}

func TestServeMissingAndDirectoryAre404WithoutCacheHeaders(t *testing.T) {
	f := newServeFixture(t)
	for _, target := range []string{"/files/2026/1/missing.png", "/files/" + f.public[:strings.LastIndex(f.public, "/")]} {
		rec := f.get(target, nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404", target, rec.Code)
		}
		if rec.Header().Get("Cache-Control") != "" {
			t.Errorf("%s: a 404 must not carry a cache header", target)
		}
	}
}

func TestServeRejectsEncodedAbsoluteAndTraversalPaths(t *testing.T) {
	// The regression: an encoded absolute path used to reach the storage root
	// and come back as a 500.
	f := newServeFixture(t)
	for _, target := range []string{"/files/%2fetc%2fpasswd", "/files/%2Fetc/passwd", "/files/%2e%2e%2fsecret"} {
		if rec := f.get(target, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", target, rec.Code)
		}
	}
}

func TestServeRejectsOtherMethods(t *testing.T) {
	h := NewServeHandler(newTestStorage(t))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/files/x", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("got %d, want 405", rec.Code)
	}
}
