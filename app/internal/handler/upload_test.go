package handler

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"file-api/internal/middleware"
	"file-api/internal/storage"
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
	h := NewUploadHandler(newTestStorage(t), nil, 4096, testSecret)
	scoped := &middleware.Claims{Scopes: []string{"upload"}}

	cases := map[string]struct {
		req  *http.Request
		want int
	}{
		"wrong method": {withClaims(httptest.NewRequest(http.MethodGet, "/file-upload", nil), scoped), http.StatusMethodNotAllowed},
		"no scope":     {uploadRequest(t, "/file-upload", "a.txt", []byte("x"), nil, &middleware.Claims{}), http.StatusForbidden},
		"too large":    {uploadRequest(t, "/file-upload", "a.txt", bytes.Repeat([]byte("x"), 8192), nil, scoped), http.StatusRequestEntityTooLarge},
		"no file field": {func() *http.Request {
			r := httptest.NewRequest(http.MethodPost, "/file-upload", strings.NewReader("a=b"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return withClaims(r, scoped)
		}(), http.StatusBadRequest},
		"file field without a filename": {func() *http.Request {
			var body bytes.Buffer
			mw := multipart.NewWriter(&body)
			mw.WriteField("file", "x")
			mw.Close()
			r := httptest.NewRequest(http.MethodPost, "/file-upload", &body)
			r.Header.Set("Content-Type", mw.FormDataContentType())
			return withClaims(r, scoped)
		}(), http.StatusBadRequest},
		"form field too long": {uploadRequest(t, "/file-upload", "a.txt", []byte("x"),
			map[string]string{"orig_width": strings.Repeat("1", uploadFieldLimit+1)}, scoped), http.StatusBadRequest},
	}
	for name, tc := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, tc.req)
		if rec.Code != tc.want {
			t.Errorf("%s: got %d, want %d: %s", name, rec.Code, tc.want, rec.Body.String())
		}
	}
}

// storedFiles lists the regular files under dir, relative to it.
func storedFiles(t *testing.T, dir string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, _ := filepath.Rel(dir, path)
			files = append(files, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return files
}

// The file part goes straight into storage. Before, a part over the parser's
// memory budget was written to a temp file under os.TempDir first; the temp
// directory stayed as large as the biggest upload. Nothing may land there now.
func TestUploadStreamsTheFilePartWithoutATempFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	dir := t.TempDir()
	s, err := storage.NewStorage(dir, 60)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	defer s.Close()
	content := bytes.Repeat([]byte("over the in-memory budget "), (33<<20)/26)
	h := NewUploadHandler(s, nil, int64(len(content))+4096, testSecret)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, uploadRequest(t, "/file-upload", "big.bin", content, map[string]string{"thumb_width": "7"}, &middleware.Claims{Scopes: []string{"upload"}}))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	resp := decodeStored(t, rec)
	if resp.Orig.Size != int64(len(content)) || resp.Orig.ThumbWidth != 7 {
		t.Errorf("response %+v, want size %d and thumb_width 7", resp.Orig, len(content))
	}
	if files := storedFiles(t, tmp); len(files) != 0 {
		t.Errorf("temp dir holds %v, want nothing", files)
	}
	files := storedFiles(t, dir)
	if len(files) != 1 || files[0] != resp.Orig.Name {
		t.Fatalf("stored %v, want exactly %q", files, resp.Orig.Name)
	}
	if st, err := os.Stat(filepath.Join(dir, files[0])); err != nil || st.Size() != int64(len(content)) {
		t.Errorf("stored file: %v, size %d", err, st.Size())
	}
}

// Fields are read wherever the client put them, before or after the file
// part, and the first file part is the upload whatever follows it.
func TestUploadReadsFieldsAfterTheFilePart(t *testing.T) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, _ := mw.CreateFormFile("file", "first.bin")
	part.Write([]byte("first"))
	mw.WriteField("orig_width", "640")
	mw.WriteField("orig_height", "480")
	mw.WriteField("thumb_height", "9")
	part, _ = mw.CreateFormFile("file", "second.bin")
	part.Write([]byte("second, ignored"))
	mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/file-upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req = withClaims(req, &middleware.Claims{Scopes: []string{"upload"}})

	h := NewUploadHandler(newTestStorage(t), nil, 4096, testSecret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	resp := decodeStored(t, rec)
	if !strings.HasPrefix(filepath.Base(resp.Orig.Name), "first-") {
		t.Errorf("stored %q, want the first file part", resp.Orig.Name)
	}
	if resp.Orig.Size != int64(len("first")) || resp.Orig.OrigWidth != 640 || resp.Orig.OrigHeight != 480 || resp.Orig.ThumbHeight != 9 {
		t.Errorf("response %+v, want size 5, 640x480 fallback dims and thumb_height 9", resp.Orig)
	}
}

// A body of unknown length is cut off by the limit while it is being stored;
// the answer is 413 and the partial write does not stay on the volume.
func TestUploadRefusesAnOversizedBodyOfUnknownLength(t *testing.T) {
	dir := t.TempDir()
	s, err := storage.NewStorage(dir, 60)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	defer s.Close()
	h := NewUploadHandler(s, nil, 1024, testSecret)

	req := uploadRequest(t, "/file-upload", "a.bin", bytes.Repeat([]byte("x"), 4096), nil, &middleware.Claims{Scopes: []string{"upload"}})
	req.Body = io.NopCloser(struct{ io.Reader }{req.Body})
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	if files := storedFiles(t, dir); len(files) != 0 {
		t.Errorf("storage holds %v after a refused upload", files)
	}
}
