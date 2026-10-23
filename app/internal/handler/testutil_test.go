package handler

import (
	"bytes"
	"encoding/json"
	stdimage "image"
	"image/png"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"file-api/internal/auth"
	"file-api/internal/storage"
)

const testSecret = "test-secret-at-least-32-characters-long"

// newTestStorage is a real storage root in a temp dir.
func newTestStorage(t *testing.T) *storage.Storage {
	t.Helper()
	s, err := storage.NewStorage(t.TempDir(), 60)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// pngBytes is a real PNG of the given size, for the dimension probe.
func pngBytes(t *testing.T, width, height int) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, stdimage.NewRGBA(stdimage.Rect(0, 0, width, height))); err != nil {
		t.Fatalf("png.Encode: %v", err)
	}
	return buf.Bytes()
}

// decodeStored decodes an upload or fetch response and verifies its meta_token
// against the values in the body.
func decodeStored(t *testing.T, rec *httptest.ResponseRecorder) UploadResponse {
	t.Helper()
	var resp UploadResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	claims := &auth.MetaClaims{}
	if _, err := jwt.ParseWithClaims(resp.MetaToken, claims, func(*jwt.Token) (interface{}, error) {
		return []byte(testSecret), nil
	}); err != nil {
		t.Fatalf("meta_token does not verify: %v", err)
	}
	if claims.Path != resp.Orig.Name || claims.Size != resp.Orig.Size ||
		claims.OrigWidth != resp.Orig.OrigWidth || claims.OrigHeight != resp.Orig.OrigHeight {
		t.Errorf("meta_token %+v does not sign the response body %+v", claims, resp.Orig)
	}
	return resp
}
