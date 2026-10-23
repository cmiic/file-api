package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// minimalPDF is a valid one-page PDF with a filled rectangle.
func minimalPDF() []byte {
	stream := "0.2 0.4 0.8 rg 20 20 160 60 re f"
	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 100] /Contents 4 0 R >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(stream), stream),
	}
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objs))
	for i, o := range objs {
		offsets[i] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, off := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xref)
	return out.Bytes()
}

// fileAPI is a stand-in for file-api that serves body with status for every path.
func fileAPI(t *testing.T, status int, body []byte) Config {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return Config{FileAPIBaseURL: srv.URL + "/files/", PathPrefix: "/files-rs", MaxWidth: 1920, MaxHeight: 1920}
}

func render(t *testing.T, cfg Config, target string) *httptest.ResponseRecorder {
	t.Helper()
	initResizePattern(cfg.PathPrefix)
	rec := httptest.NewRecorder()
	handlePDFResize(rec, httptest.NewRequest(http.MethodGet, target, nil), cfg)
	return rec
}

// assertPlaceholder checks a response is the uncacheable placeholder with
// exactly the given reason and nothing more in the error header.
func assertPlaceholder(t *testing.T, rec *httptest.ResponseRecorder, reason string) {
	t.Helper()
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), placeholderJPG) {
		t.Fatalf("want the placeholder with 200, got %d and %d bytes", rec.Code, rec.Body.Len())
	}
	if got := rec.Header().Get(headerPDFError); got != reason {
		t.Errorf("%s = %q, want exactly %q", headerPDFError, got, reason)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q: a cached placeholder would stay for a year", got)
	}
}

func TestServePlaceholderIsNeverCached(t *testing.T) {
	rec := httptest.NewRecorder()
	servePlaceholder(rec, "fetch-failed")
	assertPlaceholder(t, rec, "fetch-failed")
	if rec.Header().Get("Content-Type") != "image/jpeg" {
		t.Errorf("Content-Type %q", rec.Header().Get("Content-Type"))
	}
}

func TestUnparseablePathGetsPlaceholder(t *testing.T) {
	rec := render(t, fileAPI(t, http.StatusOK, minimalPDF()), "/files-rs/not-a-resize-url")
	assertPlaceholder(t, rec, "parse-failed")
}

func TestFetchFailureHidesInternalDetails(t *testing.T) {
	cfg := fileAPI(t, http.StatusNotFound, []byte("not found"))
	rec := render(t, cfg, "/files-rs/rs:fit:240/plain/2026/1/doc.pdf")
	assertPlaceholder(t, rec, "fetch-failed")

	host := strings.TrimPrefix(strings.TrimSuffix(cfg.FileAPIBaseURL, "/files/"), "http://")
	for name, values := range rec.Header() {
		for _, v := range values {
			if strings.Contains(v, host) || strings.Contains(v, "404") {
				t.Errorf("header %s leaks the internal error: %q", name, v)
			}
		}
	}
}

func TestUnreachableFileAPIGetsPlaceholder(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL
	srv.Close() // nothing listens there any more
	cfg := Config{FileAPIBaseURL: base + "/files/", PathPrefix: "/files-rs", MaxWidth: 1920, MaxHeight: 1920}
	assertPlaceholder(t, render(t, cfg, "/files-rs/rs:fit:240/plain/2026/1/doc.pdf"), "fetch-failed")
}

func TestUnrenderableContentGetsPlaceholder(t *testing.T) {
	// Fails in pdftocairo when it is installed, and in exec when it is not:
	// either way the request answers convert-failed.
	rec := render(t, fileAPI(t, http.StatusOK, []byte("this is not a PDF")), "/files-rs/rs:fit:240/plain/2026/1/doc.pdf")
	assertPlaceholder(t, rec, "convert-failed")
}

func TestRendersAPDF(t *testing.T) {
	if _, err := os.Stat(pdftocairoPath); err != nil {
		t.Skipf("%s not installed: %v", pdftocairoPath, err)
	}
	rec := render(t, fileAPI(t, http.StatusOK, minimalPDF()), "/files-rs/rs:fit:240/plain/2026/1/doc.pdf")

	if rec.Code != http.StatusOK || rec.Header().Get(headerPDFError) != "" {
		t.Fatalf("render failed: %d, %s=%q", rec.Code, headerPDFError, rec.Header().Get(headerPDFError))
	}
	if body := rec.Body.Bytes(); bytes.Equal(body, placeholderJPG) || !bytes.HasPrefix(body, []byte{0xFF, 0xD8, 0xFF}) {
		t.Errorf("want a rendered JPEG, got %d bytes (placeholder: %v)", len(body), bytes.Equal(body, placeholderJPG))
	}
}

func TestParseRequest(t *testing.T) {
	initResizePattern("/files-rs")
	cases := []struct {
		path     string
		typ      string
		w, h     int
		file     string
		wantFail bool
	}{
		{path: "/files-rs/rs:fit:240/plain/2026/1/a.pdf", typ: "fit", w: 240, h: 240, file: "2026/1/a.pdf"},
		{path: "/files-rs/rs:fill:300:200/g:ce/plain/2026/1/a.pdf", typ: "fill", w: 300, h: 200, file: "2026/1/a.pdf"},
		{path: "/files-rs/rs:fit:240/plain/cli/ACME/2026/1/a.pdf.jpg", typ: "fit", w: 240, h: 240, file: "cli/ACME/2026/1/a.pdf"},
		{path: "/files-rs/rs:crop:240/plain/a.pdf", wantFail: true},
		{path: "/other/rs:fit:240/plain/a.pdf", wantFail: true},
	}
	for _, tc := range cases {
		params, file, err := parseRequest(tc.path)
		if tc.wantFail {
			if err == nil {
				t.Errorf("%s: want an error", tc.path)
			}
			continue
		}
		if err != nil || params.Type != tc.typ || params.Width != tc.w || params.Height != tc.h || file != tc.file {
			t.Errorf("%s: got %+v %q %v", tc.path, params, file, err)
		}
	}
}
