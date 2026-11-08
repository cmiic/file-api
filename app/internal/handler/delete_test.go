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

	"github.com/golang-jwt/jwt/v5"

	"file-api/internal/auth"
	"file-api/internal/config"
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
	mod      *moderation.Service // nil unless the fixture was built moderated
	base     string
	metaPath string
}

// newDeleteFixture builds the fixture. With moderated set, a metadata-only
// moderation service is created over the same storage root (so its presence
// check sees the files the handler deletes) and exposed as f.mod; otherwise
// the handler gets the nil service main.go passes when no scanner is set.
func newDeleteFixture(t *testing.T, moderated bool, window time.Duration) *deleteFixture {
	t.Helper()
	return newDeleteFixtureWindows(t, moderated, window, window)
}

// newDeleteFixtureWindows is newDeleteFixture with a separate window for public
// and private files.
func newDeleteFixtureWindows(t *testing.T, moderated bool, publicMaxAge, privateMaxAge time.Duration) *deleteFixture {
	t.Helper()
	base := t.TempDir()
	filesDir := filepath.Join(base, "files")
	store, err := storage.NewStorage(filesDir, 60)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	var mod *moderation.Service
	metaPath := filepath.Join(base, "meta")
	if moderated {
		mod = moderation.NewService(nil, nil, metaPath, filepath.Join(base, "queue"), store.DeleteFile, store.Open)
	}

	mux := http.NewServeMux()
	mux.Handle("DELETE /files/", NewDeleteHandler(store, mod, publicMaxAge, privateMaxAge))
	// The serve routes exist in main.go too; registering GET here makes the
	// "disabled" test below meaningful, since the mux only answers 405 for a
	// path some other method handles.
	mux.Handle("GET /files/", NewServeHandler(store))

	return &deleteFixture{mux: mux, store: store, mod: mod, base: filesDir, metaPath: metaPath}
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

// boundClaims is deleteClaims plus the delete_path claim naming path, the form
// a delete token must have.
func boundClaims(path, clientCode string, scopes ...string) *middleware.Claims {
	claims := deleteClaims(clientCode, scopes...)
	claims.DeletePath = path
	return claims
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
	f := newDeleteFixture(t, false, time.Hour)
	rel := f.put(t, "oops", "wrong.txt", "")

	rec := f.do("/files/"+rel, boundClaims(rel, "", "upload", "delete"))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
	if f.exists(rel) {
		t.Error("file still present after 204")
	}
}

func TestDeleteRequiresDeleteScope(t *testing.T) {
	f := newDeleteFixture(t, false, time.Hour)
	rel := f.put(t, "keep", "keep.txt", "")

	cases := map[string]*middleware.Claims{
		"no claims":        nil,
		"upload only":      boundClaims(rel, "", "upload"),
		"read and scan":    boundClaims(rel, "", "read", "scan:read"),
		"empty scope list": boundClaims(rel, ""),
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

func TestDeleteRequiresTokenBoundToFile(t *testing.T) {
	f := newDeleteFixture(t, false, time.Hour)
	pub := f.put(t, "public", "pub.txt", "")
	other := f.put(t, "other", "other.txt", "")
	priv := f.put(t, "private", "priv.pdf", "ACME")

	refused := []struct {
		name   string
		path   string
		claims *middleware.Claims
	}{
		{"public, no claim", pub, deleteClaims("", "delete")},
		{"public, another file", pub, boundClaims(other, "", "delete")},
		{"public, URL form of the path", pub, boundClaims("/files/"+pub, "", "delete")},
		{"public, leading slash", pub, boundClaims("/"+pub, "", "delete")},
		{"public, directory of the file", pub, boundClaims(filepath.Dir(pub), "", "delete")},
		{"private, no claim", priv, deleteClaims("ACME", "delete")},
		{"private, another file", priv, boundClaims(pub, "ACME", "delete")},
	}
	for _, tc := range refused {
		rec := f.do("/files/"+tc.path, tc.claims)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: expected 403, got %d: %s", tc.name, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "not bound") {
			t.Errorf("%s: expected the body to name the binding, got %q", tc.name, rec.Body.String())
		}
		if !f.exists(tc.path) {
			t.Fatalf("%s: a refused delete removed the file", tc.name)
		}
	}

	for _, path := range []struct{ rel, code string }{{pub, ""}, {priv, "ACME"}} {
		if rec := f.do("/files/"+path.rel, boundClaims(path.rel, path.code, "delete")); rec.Code != http.StatusNoContent {
			t.Errorf("%s: expected 204, got %d: %s", path.rel, rec.Code, rec.Body.String())
		}
		if f.exists(path.rel) {
			t.Errorf("%s: still present after 204", path.rel)
		}
	}
}

func TestDeleteBindingDoesNotRevealExistence(t *testing.T) {
	// A token for one file gets the same answer about any other path, whether
	// or not something is stored there.
	f := newDeleteFixture(t, false, time.Hour)
	mine := f.put(t, "mine", "mine.txt", "")
	theirs := f.put(t, "theirs", "theirs.txt", "")

	present := f.do("/files/"+theirs, boundClaims(mine, "", "delete"))
	absent := f.do("/files/2026/1/nothing-here.txt", boundClaims(mine, "", "delete"))

	if present.Code != absent.Code || present.Body.String() != absent.Body.String() {
		t.Errorf("answers differ: %d %q and %d %q", present.Code, present.Body.String(), absent.Code, absent.Body.String())
	}
}

func TestDeleteBindingComparesCleanedPath(t *testing.T) {
	// Repeated slashes are one more spelling of the same file, and the claim
	// holds the path as an upload returned it.
	f := newDeleteFixture(t, false, time.Hour)
	rel := f.put(t, "spelled", "spelled.txt", "")
	target := "/files/" + filepath.Dir(rel) + "%2F%2F" + filepath.Base(rel)

	rec := f.do(target, boundClaims(rel, "", "delete"))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestDeleteThroughJWTMiddleware runs real tokens through the middleware that
// wraps the handler in main.go, including the two tokens that must not work
// although they are validly signed.
func TestDeleteThroughJWTMiddleware(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
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
	rel := info.RelativePath

	mux := http.NewServeMux()
	jwtAuth := middleware.NewJWTAuth(secret)
	mux.Handle("DELETE /files/", jwtAuth.Middleware(true)(NewDeleteHandler(store, nil, time.Hour, time.Hour)))

	sign := func(claims jwt.Claims) string {
		t.Helper()
		signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return signed
	}
	exp := jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))}
	send := func(mutate func(*http.Request)) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodDelete, "/files/"+rel, nil)
		mutate(req)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	metaToken, err := auth.Mint([]byte(secret), rel, 1, 0, 0)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if rec := send(func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+metaToken) }); rec.Code != http.StatusForbidden {
		t.Errorf("meta_token: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}

	session := sign(middleware.Claims{RegisteredClaims: exp, Scopes: []string{"upload", "read", "delete"}})
	if rec := send(func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "jwt_token", Value: session}) }); rec.Code != http.StatusForbidden {
		t.Errorf("session cookie: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if !store.FileExists(rel) {
		t.Fatal("a refused token removed the file")
	}

	bound := sign(middleware.Claims{RegisteredClaims: exp, Scopes: []string{"delete"}, DeletePath: rel})
	if rec := send(func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+bound) }); rec.Code != http.StatusNoContent {
		t.Errorf("bound token: expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
	if store.FileExists(rel) {
		t.Error("file still present after 204")
	}
}

func TestDeleteRefusesFileOlderThanWindow(t *testing.T) {
	f := newDeleteFixture(t, false, time.Hour)
	rel := f.put(t, "archived", "old.txt", "")
	f.age(t, rel, 2*time.Hour)

	rec := f.do("/files/"+rel, boundClaims(rel, "", "delete"))

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
	f := newDeleteFixture(t, false, time.Hour)
	rel := f.put(t, "shared bytes", "shared.txt", "")
	f.age(t, rel, 2*time.Hour)
	again := f.put(t, "shared bytes", "shared.txt", "")
	if again != rel {
		t.Fatalf("expected dedup to return the same path, got %q and %q", rel, again)
	}

	rec := f.do("/files/"+rel, boundClaims(rel, "", "delete"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 after a dedup hit on an old file, got %d: %s", rec.Code, rec.Body.String())
	}
	if !f.exists(rel) {
		t.Error("dedup re-upload reopened the deletion window")
	}
}

func TestDeletePrivateFileChecksClientCode(t *testing.T) {
	f := newDeleteFixture(t, false, time.Hour)
	rel := f.put(t, "private", "doc.pdf", "ACME")
	if !strings.HasPrefix(rel, "cli/ACME/") {
		t.Fatalf("unexpected private path %q", rel)
	}

	wrong := f.do("/files/"+rel, boundClaims(rel, "OTHER", "delete"))
	if wrong.Code != http.StatusForbidden {
		t.Errorf("other client: expected 403, got %d: %s", wrong.Code, wrong.Body.String())
	}
	noCode := f.do("/files/"+rel, boundClaims(rel, "", "delete"))
	if noCode.Code != http.StatusForbidden {
		t.Errorf("token without cli_code: expected 403, got %d: %s", noCode.Code, noCode.Body.String())
	}
	if !f.exists(rel) {
		t.Fatal("a refused private delete removed the file")
	}

	right := f.do("/files/"+rel, boundClaims(rel, "ACME", "delete"))
	if right.Code != http.StatusNoContent {
		t.Fatalf("owner: expected 204, got %d: %s", right.Code, right.Body.String())
	}
	if f.exists(rel) {
		t.Error("owner's delete left the file in place")
	}
}

func TestDeleteWindowsApplyPerClassOfFile(t *testing.T) {
	cases := []struct {
		name             string
		public, private  time.Duration
		wantPub, wantPrv int
	}{
		{"private unlimited, public finite", time.Hour, config.DeleteAnyAge, http.StatusForbidden, http.StatusNoContent},
		{"public unlimited, private finite", config.DeleteAnyAge, time.Hour, http.StatusNoContent, http.StatusForbidden},
		{"both unlimited", config.DeleteAnyAge, config.DeleteAnyAge, http.StatusNoContent, http.StatusNoContent},
		{"private only", 0, config.DeleteAnyAge, http.StatusMethodNotAllowed, http.StatusNoContent},
		{"public only", config.DeleteAnyAge, 0, http.StatusNoContent, http.StatusMethodNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newDeleteFixtureWindows(t, false, tc.public, tc.private)
			pub := f.put(t, "public", "pub.txt", "")
			prv := f.put(t, "private", "prv.txt", "ACME")
			// Decades old, as far past the finite windows as a file gets.
			f.age(t, pub, 30*365*24*time.Hour)
			f.age(t, prv, 30*365*24*time.Hour)

			if rec := f.do("/files/"+pub, boundClaims(pub, "", "delete")); rec.Code != tc.wantPub {
				t.Errorf("public: expected %d, got %d: %s", tc.wantPub, rec.Code, rec.Body.String())
			}
			if rec := f.do("/files/"+prv, boundClaims(prv, "ACME", "delete")); rec.Code != tc.wantPrv {
				t.Errorf("private: expected %d, got %d: %s", tc.wantPrv, rec.Code, rec.Body.String())
			}
			if got := f.exists(pub); got == (tc.wantPub == http.StatusNoContent) {
				t.Errorf("public: exists=%v after %d", got, tc.wantPub)
			}
			if got := f.exists(prv); got == (tc.wantPrv == http.StatusNoContent) {
				t.Errorf("private: exists=%v after %d", got, tc.wantPrv)
			}
		})
	}
}

func TestDeleteDisabledClassAnswers405WithAllow(t *testing.T) {
	f := newDeleteFixtureWindows(t, false, 0, config.DeleteAnyAge)
	pub := f.put(t, "public", "pub.txt", "")

	rec := f.do("/files/"+pub, boundClaims(pub, "", "delete"))

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d: %s", rec.Code, rec.Body.String())
	}
	if allow := rec.Header().Get("Allow"); allow != "GET, HEAD" {
		t.Errorf("expected Allow: GET, HEAD, got %q", allow)
	}
}

func TestDeleteWindowFollowsCleanedPathNotRoute(t *testing.T) {
	// An encoded slash leaves the path one segment for the mux, so the class
	// of file can only be told from the cleaned path. A private file spelled
	// this way must get the private window, and stay refused when private
	// deletion is off.
	f := newDeleteFixtureWindows(t, false, time.Hour, 2*time.Hour)
	rel := f.put(t, "private", "enc.txt", "ACME")
	target := "/files/" + strings.ReplaceAll(rel, "/", "%2F")

	f.age(t, rel, 90*time.Minute)
	if rec := f.do(target, boundClaims(rel, "ACME", "delete")); rec.Code != http.StatusNoContent {
		t.Fatalf("inside the private window: expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	strict := newDeleteFixtureWindows(t, false, time.Hour, 0)
	rel = strict.put(t, "private", "enc.txt", "ACME")
	target = "/files/" + strings.ReplaceAll(rel, "/", "%2F")
	if rec := strict.do(target, boundClaims(rel, "ACME", "delete")); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("private files off: expected 405, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strict.exists(rel) {
		t.Error("an encoded slash deleted a private file with private deletion off")
	}
}

func TestDeleteUnknownPathIs404(t *testing.T) {
	f := newDeleteFixture(t, false, time.Hour)

	const missing = "2026/1/nothing-here.txt"
	rec := f.do("/files/"+missing, boundClaims(missing, "", "delete"))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteDirectoryIs404(t *testing.T) {
	f := newDeleteFixture(t, false, time.Hour)
	rel := f.put(t, "x", "x.txt", "")
	dir := filepath.Dir(rel)

	rec := f.do("/files/"+dir, boundClaims(dir, "", "delete"))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for a directory, got %d: %s", rec.Code, rec.Body.String())
	}
	if !f.exists(rel) {
		t.Error("deleting the directory path removed its contents")
	}
}

func TestDeleteRejectsEncodedTraversal(t *testing.T) {
	f := newDeleteFixture(t, false, time.Hour)
	// A file one level above the storage root that a traversal would reach.
	victim := filepath.Join(filepath.Dir(f.base), "victim.txt")
	if err := os.WriteFile(victim, []byte("outside"), 0644); err != nil {
		t.Fatalf("write victim: %v", err)
	}

	targets := []string{
		"/files/%2e%2e%2fvictim.txt",
		"/files/%2e%2e/victim.txt",
		"/files/..%2fvictim.txt",
		// Stays inside the root once cleaned, and is refused anyway.
		"/files/x/..%2F2026/1/victim.txt",
		"/files/cli/ACME/..%2F..%2F2026/1/victim.txt",
		// Encoded absolute paths sanitize to a leading "/" and must be a 400
		// here, not the 500 the storage root's containment error would give.
		"/files/%2fetc%2fpasswd",
		"/files/%2Fetc/passwd",
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
	f := newDeleteFixture(t, true, time.Hour)
	mod := f.mod
	rel := f.put(t, "scanned", "scanned.jpg", "")

	// Simulate a completed scan the way the moderation service writes it.
	metaFile := filepath.Join(f.metaPath, rel+".json")
	if err := os.MkdirAll(filepath.Dir(metaFile), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(metaFile, []byte(`{"status":"clean","nsfw":{"unsafe":false,"confidence":0.1}}`), 0644); err != nil {
		t.Fatalf("write meta: %v", err)
	}

	rec := f.do("/files/"+rel, boundClaims(rel, "", "delete"))
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
	f := newDeleteFixture(t, false, time.Hour)
	rel := f.put(t, "unscanned", "u.txt", "")

	rec := f.do("/files/"+rel, boundClaims(rel, "", "delete"))

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
	f := newDeleteFixture(t, true, time.Hour)
	mod := f.mod
	rel := f.put(t, "comeback", "again.txt", "")

	if rec := f.do("/files/"+rel, boundClaims(rel, "", "delete")); rec.Code != http.StatusNoContent {
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
