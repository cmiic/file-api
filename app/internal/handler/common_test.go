package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"file-api/internal/middleware"
)

func TestRequestFilePath(t *testing.T) {
	cases := []struct {
		urlPath string
		want    string
		ok      bool
	}{
		{"/files/2026/1/a.jpg", "2026/1/a.jpg", true},
		{"/files/cli/ACME/2026/1/a.pdf", "cli/ACME/2026/1/a.pdf", true},
		{"/files/../etc/passwd", "", false},
		{"/files//etc/passwd", "", false}, // decoded %2f: absolute
		// The bare prefix resolves to the storage root, which the handlers
		// stat as a directory and answer with 404.
		{"/files/", ".", true},
	}
	for _, tc := range cases {
		got, ok := requestFilePath(tc.urlPath)
		if got != tc.want || ok != tc.ok {
			t.Errorf("requestFilePath(%q) = %q, %v; want %q, %v", tc.urlPath, got, ok, tc.want, tc.ok)
		}
	}
}

func TestAuthorizeClientPath(t *testing.T) {
	acme := &middleware.Claims{ClientCode: "ACME"}
	cases := []struct {
		name   string
		claims *middleware.Claims
		path   string
		want   int
	}{
		{"public path needs nothing", nil, "2026/1/a.jpg", 0},
		{"private path without a token", nil, "cli/ACME/2026/1/a.pdf", http.StatusUnauthorized},
		{"private path for another client", &middleware.Claims{ClientCode: "OTHER"}, "cli/ACME/2026/1/a.pdf", http.StatusForbidden},
		{"private path with a token without client code", &middleware.Claims{}, "cli/ACME/2026/1/a.pdf", http.StatusForbidden},
		{"private path for its own client", acme, "cli/ACME/2026/1/a.pdf", 0},
	}
	for _, tc := range cases {
		if got := authorizeClientPath(tc.claims, tc.path); got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestWriteFileError(t *testing.T) {
	missing := httptest.NewRecorder()
	writeFileError(missing, os.ErrNotExist, "[test]", "stat", "a.jpg")
	if missing.Code != http.StatusNotFound {
		t.Errorf("not-exist: got %d, want 404", missing.Code)
	}

	broken := httptest.NewRecorder()
	writeFileError(broken, errors.New("openat /srv/data/a.jpg: permission denied"), "[test]", "stat", "a.jpg")
	if broken.Code != http.StatusInternalServerError {
		t.Errorf("other error: got %d, want 500", broken.Code)
	}
	if strings.Contains(broken.Body.String(), "/srv/data") {
		t.Errorf("the underlying error reached the client: %q", broken.Body.String())
	}
}

func TestStatRegularFile(t *testing.T) {
	s := newTestStorage(t)
	info, err := s.StoreFile(strings.NewReader("x"), "a.txt", "")
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}

	if _, ok := statRegularFile(httptest.NewRecorder(), s, info.RelativePath, "[test]"); !ok {
		t.Error("a stored file was refused")
	}
	for _, p := range []string{"2026", "nope.txt"} {
		rec := httptest.NewRecorder()
		if _, ok := statRegularFile(rec, s, p, "[test]"); ok || rec.Code != http.StatusNotFound {
			t.Errorf("%q: ok=%v code=%d, want refused with 404", p, ok, rec.Code)
		}
	}
}

func TestReadFormDims(t *testing.T) {
	form := url.Values{"orig_width": {"640"}, "orig_height": {"480"}, "thumb_width": {"64"}, "thumb_height": {"oops"}}
	r := httptest.NewRequest(http.MethodPost, "/file-upload", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	got := readFormDims(r)
	want := formDims{origWidth: 640, origHeight: 480, thumbWidth: 64, thumbHeight: 0}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestProbeStoredDims(t *testing.T) {
	s := newTestStorage(t)
	img, err := s.StoreFile(strings.NewReader(string(pngBytes(t, 32, 16))), "pic.png", "")
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}
	txt, err := s.StoreFile(strings.NewReader("not an image"), "notes.txt", "")
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}

	if w, h := probeStoredDims(s, img.RelativePath, 1, 1, "[test]"); w != 32 || h != 16 {
		t.Errorf("recognised image: got %dx%d, want the probed 32x16", w, h)
	}
	if w, h := probeStoredDims(s, txt.RelativePath, 7, 9, "[test]"); w != 7 || h != 9 {
		t.Errorf("unknown format: got %dx%d, want the fallback 7x9", w, h)
	}
	if w, h := probeStoredDims(s, "2026/1/missing.png", 7, 9, "[test]"); w != 7 || h != 9 {
		t.Errorf("missing file: got %dx%d, want the fallback 7x9", w, h)
	}
}

func TestOpenRegularFile(t *testing.T) {
	s := newTestStorage(t)
	info, err := s.StoreFile(strings.NewReader("x"), "a.txt", "")
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}

	rec := httptest.NewRecorder()
	f, fi, ok := openRegularFile(rec, s, info.RelativePath, "[test]")
	if !ok || f == nil || fi.Size() != 1 {
		t.Fatalf("a stored file was refused: ok=%v code=%d", ok, rec.Code)
	}
	f.Close()

	for _, p := range []string{"2026", "nope.txt"} {
		rec := httptest.NewRecorder()
		if _, _, ok := openRegularFile(rec, s, p, "[test]"); ok || rec.Code != http.StatusNotFound {
			t.Errorf("%q: ok=%v code=%d, want refused with 404", p, ok, rec.Code)
		}
		if rec.Header().Get("Cache-Control") != "" {
			t.Errorf("%q: the refusal carries a cache header", p)
		}
	}
}
