package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testSecret = "shared-with-the-downstream-backend"

func verify(t *testing.T, token string, secret []byte) *MetaClaims {
	t.Helper()
	parsed, err := jwt.ParseWithClaims(token, &MetaClaims{}, func(t *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	c, ok := parsed.Claims.(*MetaClaims)
	if !ok || !parsed.Valid {
		t.Fatalf("invalid claims")
	}
	return c
}

func TestMint_Roundtrip(t *testing.T) {
	tok, err := Mint([]byte(testSecret), "2026/05/abc.jpg", 12345, 1920, 1080)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	c := verify(t, tok, []byte(testSecret))
	if c.Path != "2026/05/abc.jpg" || c.Size != 12345 || c.OrigWidth != 1920 || c.OrigHeight != 1080 {
		t.Fatalf("claim payload mismatch: %+v", c)
	}
	if c.Issuer != Issuer {
		t.Fatalf("iss = %q, want %q", c.Issuer, Issuer)
	}
	// exp is within TTL of iat
	if c.ExpiresAt.Sub(c.IssuedAt.Time) != TTL {
		t.Fatalf("ttl = %v, want %v", c.ExpiresAt.Sub(c.IssuedAt.Time), TTL)
	}
}

func TestMint_TamperedSignatureRejected(t *testing.T) {
	tok, _ := Mint([]byte(testSecret), "a/b/c", 1, 10, 20)
	_, err := jwt.ParseWithClaims(tok, &MetaClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte("not-the-secret"), nil
	})
	if err == nil {
		t.Fatalf("expected signature verification to fail with the wrong secret")
	}
}

func TestMint_ExpiredRejected(t *testing.T) {
	// Manually construct an already-expired token using the helpers so
	// we don't need to time-travel.
	claims := MetaClaims{
		Path:       "x",
		Size:       1,
		OrigWidth:  1,
		OrigHeight: 1,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-10 * time.Minute)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	_, err = jwt.ParseWithClaims(signed, &MetaClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(testSecret), nil
	})
	if err == nil {
		t.Fatalf("expected expiry verification to fail")
	}
}
