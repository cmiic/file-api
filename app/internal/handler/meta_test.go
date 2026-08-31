package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"file-api/internal/middleware"
	"file-api/internal/moderation"
)

// newMetaTestServer builds a MetaHandler behind the same http.ServeMux
// pattern main.go registers, so the tests exercise the real routing.
// Returns the mux and the temp dir that holds meta/, queue/ and a
// secret.json placed *outside* meta/ as a traversal target.
func newMetaTestServer(t *testing.T) (http.Handler, string) {
	t.Helper()

	base := t.TempDir()
	metaPath := filepath.Join(base, "meta")
	queuePath := filepath.Join(base, "queue")

	// A file a traversal would reach: base/secret.json sits one level
	// above metaPath, so relative path "../secret" resolves onto it.
	if err := os.WriteFile(filepath.Join(base, "secret.json"), []byte(`{"status":"TOPSECRET"}`), 0644); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	svc := moderation.NewService(nil, nil, metaPath, queuePath, nil)

	// A legitimate metadata file inside metaPath.
	if err := os.MkdirAll(filepath.Join(metaPath, "2026", "1"), 0755); err != nil {
		t.Fatalf("mkdir meta: %v", err)
	}
	if err := os.WriteFile(filepath.Join(metaPath, "2026", "1", "photo.jpg.json"), []byte(`{"status":"clean"}`), 0644); err != nil {
		t.Fatalf("write meta: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /meta/files/", NewMetaHandler(svc))
	return mux, base
}

// authed attaches claims carrying the scan:read scope, standing in for
// the JWT middleware that wraps this handler in main.go.
func authed(r *http.Request) *http.Request {
	claims := &middleware.Claims{Scopes: []string{"scan:read"}}
	return r.WithContext(context.WithValue(r.Context(), middleware.ClaimsKey, claims))
}

func TestMetaHandlerServesValidPath(t *testing.T) {
	mux, _ := newMetaTestServer(t)

	req := authed(httptest.NewRequest(http.MethodGet, "/meta/files/2026/1/photo.jpg", nil))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for a valid path, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "clean") {
		t.Errorf("expected the stored metadata in the body, got %q", rec.Body.String())
	}
}

// TestMetaHandlerRejectsEncodedTraversal is the regression test for the
// path traversal on GET /meta/files/.
//
// http.ServeMux canonicalizes the *escaped* path, so it redirects a
// literal "../" but passes "%2e%2e%2f" straight through - and the
// handler then reads r.URL.Path, which is decoded. Without validation
// the traversal reached filepath.Join(metaPath, relativePath+".json")
// and read arbitrary .json files off the filesystem.
func TestMetaHandlerRejectsEncodedTraversal(t *testing.T) {
	mux, _ := newMetaTestServer(t)

	targets := []string{
		"/meta/files/%2e%2e%2fsecret",
		"/meta/files/%2e%2e/secret",
		"/meta/files/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
		"/meta/files/..%2fsecret",
	}

	for _, target := range targets {
		req := authed(httptest.NewRequest(http.MethodGet, target, nil))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d: %s", target, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "TOPSECRET") {
			t.Errorf("%s: traversal read a file outside the meta directory", target)
		}
	}
}

// TestMetaHandlerRedirectsLiteralTraversal documents the half the mux
// already handled: an unencoded "../" never reaches the handler.
func TestMetaHandlerRedirectsLiteralTraversal(t *testing.T) {
	mux, _ := newMetaTestServer(t)

	req := authed(httptest.NewRequest(http.MethodGet, "/meta/files/../../secret", nil))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMovedPermanently && rec.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected the mux to redirect a literal traversal, got %d", rec.Code)
	}
}

func TestMetaHandlerRequiresScope(t *testing.T) {
	mux, _ := newMetaTestServer(t)

	// No claims at all.
	req := httptest.NewRequest(http.MethodGet, "/meta/files/2026/1/photo.jpg", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 without claims, got %d", rec.Code)
	}

	// Claims without scan:read.
	claims := &middleware.Claims{Scopes: []string{"upload"}}
	req = httptest.NewRequest(http.MethodGet, "/meta/files/2026/1/photo.jpg", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.ClaimsKey, claims))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 with the wrong scope, got %d", rec.Code)
	}
}

func TestMetaHandlerMissingMetadataIs404(t *testing.T) {
	mux, _ := newMetaTestServer(t)

	req := authed(httptest.NewRequest(http.MethodGet, "/meta/files/2026/1/absent.jpg", nil))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for an unknown file, got %d: %s", rec.Code, rec.Body.String())
	}
}
