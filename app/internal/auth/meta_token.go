// Package auth provides the file metadata token used to defend the
// trust hop between file-api and downstream backends.
//
// When a browser uploads a file to file-api, file-api stores the
// bytes, probes the image dimensions server-side, and returns the
// resolved values to the browser. The browser then notifies its
// own backend (e.g. web-api) about the upload so a domain row gets
// persisted. Without a signature on file-api's claim the browser
// can swap the dims in flight — the backend has no way to tell.
//
// The meta_token closes that gap: file-api HMAC-signs the resolved
// values with the same JWT_SECRET it uses to verify upload bearers.
// The backend already knows the secret (it mints the upload tokens
// in the first place), so it can verify the file-api claim locally
// with no extra round-trip.
//
// Token shape:
//
//	{
//	  "iss":         "file-api",
//	  "path":        "2026/05/<sha1>.jpg",   // RelativePath of the stored file
//	  "size":        12345,                   // bytes
//	  "orig_width":  1920,                    // 0 = unknown / not an image
//	  "orig_height": 1080,
//	  "iat":         1715000000,
//	  "exp":         1715000300               // iat + 5 min
//	}
//
// `thumb_width`/`thumb_height` stay unsigned — they're caller-owned
// and have always been pure pass-through.
package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// Issuer is the constant `iss` claim every meta-token carries.
	// Backends MUST verify it to prevent confusing a meta-token with
	// an upload bearer (both share the same secret but mean very
	// different things).
	Issuer = "file-api"

	// TTL is the lifetime of a freshly minted meta-token. Long enough
	// for the browser to make the follow-up notify call, short enough
	// that a token lifted off the wire isn't reusable hours later.
	TTL = 5 * time.Minute
)

// MetaClaims is the JWT payload describing one stored file.
type MetaClaims struct {
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	OrigWidth  int    `json:"orig_width"`
	OrigHeight int    `json:"orig_height"`
	jwt.RegisteredClaims
}

// Mint produces a signed meta_token for the given file metadata.
// secret is the shared file-api ↔ backend HMAC key — typically
// loaded from the `JWT_SECRET` env file-api already uses for upload
// verification.
func Mint(secret []byte, path string, size int64, origWidth, origHeight int) (string, error) {
	now := time.Now()
	claims := MetaClaims{
		Path:       path,
		Size:       size,
		OrigWidth:  origWidth,
		OrigHeight: origHeight,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   Issuer,
			IssuedAt: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(TTL)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(secret)
}
