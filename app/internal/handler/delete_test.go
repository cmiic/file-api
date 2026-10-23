package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"file-api/internal/middleware"
	"file-api/internal/moderation"
	"file-api/internal/storage"
)

// deleteFixture is a DeleteHandler behind the same ServeMux pattern main.go
// registers, over a real storage root in a temp dir, so the tests exercise
// routing, sanitizing and the os.Root containment together.
type deleteFixture struct {
	mux      http.Handler
	store    *storage.Storage
	base     string
	metaPath string
	// window is the configured DELETE_MAX_AGE for this fixture.
	window time.Duration
}

func newDeleteFixture(t *testing.T, mod *moderation.Service, window time.Duration) *deleteFixture {
	t.Helper()
	base := t.TempDir()
	filesDir := filepath.Join(base, "files")
	store, err := storage.NewStorage(filesDir, 60)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	mux := http.NewServeMux()
	mux.Handle("DELETE /files/", NewDeleteHandler(store, mod, window))
	// The serve routes exist in main.go too; registering GET here makes the
	// "disabled" test below meaningful, since the mux only answers 405 for a
	// path some other method handles.
	mux.Handle("GET /files/", NewServeHandler(store))

	return &deleteFixture{mux: mux, store: store, base: filesDir, window: window}
}

// put stores content under the uploader filename and returns the relative
// path StoreFile produced.
func (f *deleteFixture) put(t *testing.T, content, filename, clientCode string) string {
	t.Helper()
	info, err := f.store.StoreFile(strings.NewReader(content), filename, clientCode)
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}
	return info.RelativePath
}

// age backdates a stored file's mtime so it falls outside the window.
func (f *deleteFixture) age(t *testing.T, relativePath string, by time.Duration) {
	t.Helper()
	old := time.Now().Add(-by)
	if err := os.Chtimes(filepath.Join(f.base, relativePath), old, old); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
}

func (f *deleteFixture) exists(relativePath string) bool {
	return f.store.FileExists(relativePath)
}

// withClaims stands in for the JWT middleware that wraps the handler in
// main.go. nil claims model a request the middleware let through without a
// token, which main.go never does but the handler must still refuse.
func withClaims(r *http.Request, claims *middleware.Claims) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), middleware.ClaimsKey, claims))
}

func deleteClaims(clientCode string, scopes ...string) *middleware.Claims {
	return &middleware.Claims{ClientCode: clientCode, Scopes: scopes}
}

func (f *deleteFixture) do(target string, claims *middleware.Claims) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, target, nil)
	if claims != nil {
		req = withClaims(req, claims)
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

func TestDeleteRemovesFreshPublicFile(t *testing.T) {
	f := newDeleteFixture(t, nil, time.Hour)
	rel := f.put(t, "oops", "wrong.txt", "")

	rec := f.do("/files/"+rel, deleteClaims("", "upload", "delete"))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
	if f.exists(rel) {
		t.Error("file still present after 204")
	}
}

func TestDeleteRequiresDeleteScope(t *testing.T) {
	f := newDeleteFixture(t, nil, time.Hour)
	rel := f.put(t, "keep", "keep.txt", "")

	cases := map[string]*middleware.Claims{
		"no claims":        nil,
		"upload only":      deleteClaims("", "upload"),
		"read and scan":    deleteClaims("", "read", "scan:read"),
		"empty scope list": deleteClaims(""),
	}
	for name, claims := range cases {
		rec := f.do("/files/"+rel, claims)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: expected 403, got %d: %s", name, rec.Code, rec.Body.String())
		}
	}
	if !f.exists(rel) {
		t.Error("a refused delete removed the file")
	}
}

func TestDeleteRefusesFileOlderThanWindow(t *testing.T) {
	f := newDeleteFixture(t, nil, time.Hour)
	rel := f.put(t, "archived", "old.txt", "")
	f.age(t, rel, 2*time.Hour)

	rec := f.do("/files/"+rel, deleteClaims("", "delete"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "window") {
		t.Errorf("expected the body to name the elapsed window, got %q", rec.Body.String())
	}
	if !f.exists(rel) {
		t.Error("an out-of-window delete removed the file")
	}
}

func TestDeleteWindowIsMeasuredFromFirstUpload(t *testing.T) {
	// A deduplicated re-upload must not refresh the clock: the second
	// uploader is handed the first uploader's path, and it is the first
	// upload's age that bounds what can be removed.
	f := newDeleteFixture(t, nil, time.Hour)
	rel := f.put(t, "shared bytes", "shared.txt", "")
	f.age(t, rel, 2*time.Hour)
	again := f.put(t, "shared bytes", "shared.txt", "")
	if again != rel {
		t.Fatalf("expected dedup to return the same path, got %q and %q", rel, again)
	}

	rec := f.do("/files/"+rel, deleteClaims("", "delete"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 after a dedup hit on an old file, got %d: %s", rec.Code, rec.Body.String())
	}
	if !f.exists(rel) {
		t.Error("dedup re-upload reopened the deletion window")
	}
}

func TestDeletePrivateFileChecksClientCode(t *testing.T) {
	f := newDeleteFixture(t, nil, time.Hour)
	rel := f.put(t, "private", "doc.pdf", "ACME")
	if !strings.HasPrefix(rel, "cli/ACME/") {
		t.Fatalf("unexpected private path %q", rel)
	}

	wrong := f.do("/files/"+rel, deleteClaims("OTHER", "delete"))
	if wrong.Code != http.StatusForbidden {
		t.Errorf("other client: expected 403, got %d: %s", wrong.Code, wrong.Body.String())
	}
	noCode := f.do("/files/"+rel, deleteClaims("", "delete"))
	if noCode.Code != http.StatusForbidden {
		t.Errorf("token without cli_code: expected 403, got %d: %s", noCode.Code, noCode.Body.String())
	}
	if !f.exists(rel) {
		t.Fatal("a refused private delete removed the file")
	}

	right := f.do("/files/"+rel, deleteClaims("ACME", "delete"))
	if right.Code != http.StatusNoContent {
		t.Fatalf("owner: expected 204, got %d: %s", right.Code, right.Body.String())
	}
	if f.exists(rel) {
		t.Error("owner's delete left the file in place")
	}
}

func TestDeleteUnknownPathIs404(t *testing.T) {
	f := newDeleteFixture(t, nil, time.Hour)

	rec := f.do("/files/2026/1/nothing-here.txt", deleteClaims("", "delete"))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteDirectoryIs404(t *testing.T) {
	f := newDeleteFixture(t, nil, time.Hour)
	rel := f.put(t, "x", "x.txt", "")
	dir := filepath.Dir(rel)

	rec := f.do("/files/"+dir, deleteClaims("", "delete"))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for a directory, got %d: %s", rec.Code, rec.Body.String())
	}
	if !f.exists(rel) {
		t.Error("deleting the directory path removed its contents")
	}
}

func TestDeleteRejectsEncodedTraversal(t *testing.T) {
	f := newDeleteFixture(t, nil, time.Hour)
	// A file one level above the storage root that a traversal would reach.
	victim := filepath.Join(filepath.Dir(f.base), "victim.txt")
	if err := os.WriteFile(victim, []byte("outside"), 0644); err != nil {
		t.Fatalf("write victim: %v", err)
	}

	targets := []string{
		"/files/%2e%2e%2fvictim.txt",
		"/files/%2e%2e/victim.txt",
		"/files/..%2fvictim.txt",
	}
	for _, target := range targets {
		rec := f.do(target, deleteClaims("", "delete"))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d: %s", target, rec.Code, rec.Body.String())
		}
	}
	if _, err := os.Stat(victim); err != nil {
		t.Errorf("traversal removed a file outside the storage root: %v", err)
	}
}

func TestDeleteMarksMetadataDeleted(t *testing.T) {
	base := t.TempDir()
	metaPath := filepath.Join(base, "meta")
	mod := moderation.NewService(nil, nil, metaPath, filepath.Join(base, "queue"), nil, nil)
	f := newDeleteFixture(t, mod, time.Hour)
	rel := f.put(t, "scanned", "scanned.jpg", "")

	// Simulate a completed scan the way the moderation service writes it.
	metaFile := filepath.Join(metaPath, rel+".json")
	if err := os.MkdirAll(filepath.Dir(metaFile), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(metaFile, []byte(`{"status":"clean","nsfw":{"unsafe":false,"confidence":0.1}}`), 0644); err != nil {
		t.Fatalf("write meta: %v", err)
	}

	rec := f.do("/files/"+rel, deleteClaims("", "delete"))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	meta, err := mod.GetMetadata(rel)
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}
	if meta == nil {
		t.Fatal("metadata vanished instead of being marked deleted")
	}
	if meta.Status != moderation.StatusDeleted {
		t.Errorf("expected status %q, got %q", moderation.StatusDeleted, meta.Status)
	}
	if meta.CompletedAt == nil {
		t.Error("expected CompletedAt to be set")
	}
	if meta.NSFWResult == nil {
		t.Error("earlier scan result was dropped from the deleted record")
	}
}

func TestDeleteWithoutModerationToleratesNilService(t *testing.T) {
	// main.go passes a nil *moderation.Service when no scanner is configured.
	var mod *moderation.Service
	f := newDeleteFixture(t, mod, time.Hour)
	rel := f.put(t, "unscanned", "u.txt", "")

	rec := f.do("/files/"+rel, deleteClaims("", "delete"))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteRouteAbsentAnswers405(t *testing.T) {
	// When DELETE_MAX_AGE is unset main.go does not register the DELETE
	// route at all. With only GET registered for the pattern, the mux must
	// answer 405 so a misconfigured client sees "not offered" rather than
	// "not found".
	base := t.TempDir()
	store, err := storage.NewStorage(base, 60)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	info, err := store.StoreFile(strings.NewReader("x"), "x.txt", "")
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /files/", NewServeHandler(store))

	req := withClaims(httptest.NewRequest(http.MethodDelete, "/files/"+info.RelativePath, nil), deleteClaims("", "delete"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d: %s", rec.Code, rec.Body.String())
	}
	if !store.FileExists(info.RelativePath) {
		t.Error("file removed although deletion is disabled")
	}
}

func TestReuploadAfterDeleteClearsTombstone(t *testing.T) {
	// End to end through the upload handler's moderation hook: delete, then
	// store identical bytes under the same filename. The path is identical,
	// so the deleted record must not describe the file that now exists.
	base := t.TempDir()
	mod := moderation.NewService(nil, nil, filepath.Join(base, "meta"), filepath.Join(base, "queue"), nil, nil)
	f := newDeleteFixture(t, mod, time.Hour)
	rel := f.put(t, "comeback", "again.txt", "")

	if rec := f.do("/files/"+rel, deleteClaims("", "delete")); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
	if meta, _ := mod.GetMetadata(rel); meta == nil || meta.Status != moderation.StatusDeleted {
		t.Fatalf("expected a deleted record after delete, got %+v", meta)
	}

	again := f.put(t, "comeback", "again.txt", "")
	if again != rel {
		t.Fatalf("expected the same path on re-upload, got %q and %q", rel, again)
	}
	// The upload handler calls this right after StoreFile.
	mod.ProcessUpload(again, "", "", true)

	meta, err := mod.GetMetadata(rel)
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}
	if meta != nil {
		t.Errorf("deleted record survived the re-upload: %+v", meta)
	}
	if !f.exists(rel) {
		t.Error("re-uploaded file missing")
	}
}
