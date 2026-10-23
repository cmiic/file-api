package handler

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"file-api/internal/middleware"
)

func uploadRequest(t *testing.T, target, filename string, content []byte, fields map[string]string, claims *middleware.Claims) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatalf("WriteField: %v", err)
		}
	}
	part, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	part.Write(content)
	mw.Close()
	req := httptest.NewRequest(http.MethodPost, target, &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return withClaims(req, claims)
}

func TestUploadProbesDimensionsAndSignsThem(t *testing.T) {
	h := NewUploadHandler(newTestStorage(t), nil, 1<<20, testSecret)
	req := uploadRequest(t, "/file-upload", "pic.png", pngBytes(t, 40, 30),
		map[string]string{"orig_width": "1", "orig_height": "1", "thumb_width": "8", "thumb_height": "6"},
		&middleware.Claims{Scopes: []string{"upload"}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	resp := decodeStored(t, rec)
	if resp.Orig.OrigWidth != 40 || resp.Orig.OrigHeight != 30 {
		t.Errorf("probe should win over the form: got %dx%d", resp.Orig.OrigWidth, resp.Orig.OrigHeight)
	}
	if resp.Orig.ThumbWidth != 8 || resp.Orig.ThumbHeight != 6 {
		t.Errorf("thumbnail dims are passed through: got %dx%d", resp.Orig.ThumbWidth, resp.Orig.ThumbHeight)
	}
}

func TestUploadFallsBackToFormDimensions(t *testing.T) {
	h := NewUploadHandler(newTestStorage(t), nil, 1<<20, testSecret)
	req := uploadRequest(t, "/file-upload", "notes.txt", []byte("text"),
		map[string]string{"orig_width": "320", "orig_height": "200"},
		&middleware.Claims{Scopes: []string{"upload"}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	if resp := decodeStored(t, rec); resp.Orig.OrigWidth != 320 || resp.Orig.OrigHeight != 200 {
		t.Errorf("unknown format keeps the form values: got %dx%d", resp.Orig.OrigWidth, resp.Orig.OrigHeight)
	}
}

func TestUploadPrivateChecksClientCode(t *testing.T) {
	h := NewUploadHandler(newTestStorage(t), nil, 1<<20, testSecret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, uploadRequest(t, "/file-upload/cli/ACME", "a.txt", []byte("x"), nil,
		&middleware.Claims{ClientCode: "OTHER", Scopes: []string{"upload"}}))
	if rec.Code != http.StatusForbidden {
		t.Errorf("other client: got %d, want 403", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, uploadRequest(t, "/file-upload/cli/ACME", "a.txt", []byte("x"), nil,
		&middleware.Claims{ClientCode: "ACME", Scopes: []string{"upload"}}))
	if rec.Code != http.StatusOK {
		t.Fatalf("owner: got %d: %s", rec.Code, rec.Body.String())
	}
	if resp := decodeStored(t, rec); resp.Orig.Name[:9] != "cli/ACME/" {
		t.Errorf("private upload stored at %q", resp.Orig.Name)
	}
}

func TestUploadRefusals(t *testing.T) {
	h := NewUploadHandler(newTestStorage(t), nil, 64, testSecret)
	scoped := &middleware.Claims{Scopes: []string{"upload"}}

	cases := map[string]struct {
		req  *http.Request
		want int
	}{
		"wrong method": {withClaims(httptest.NewRequest(http.MethodGet, "/file-upload", nil), scoped), http.StatusMethodNotAllowed},
		"no scope":     {uploadRequest(t, "/file-upload", "a.txt", []byte("x"), nil, &middleware.Claims{}), http.StatusForbidden},
		"too large":    {uploadRequest(t, "/file-upload", "a.txt", bytes.Repeat([]byte("x"), 1024), nil, scoped), http.StatusRequestEntityTooLarge},
		"no file field": {func() *http.Request {
			r := httptest.NewRequest(http.MethodPost, "/file-upload", strings.NewReader("a=b"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return withClaims(r, scoped)
		}(), http.StatusBadRequest},
	}
	for name, tc := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, tc.req)
		if rec.Code != tc.want {
			t.Errorf("%s: got %d, want %d: %s", name, rec.Code, tc.want, rec.Body.String())
		}
	}
}
