package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testSecret = "this-is-a-test-secret-with-32-chars!"

func createTestToken(claims *Claims, secret string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(secret))
	return tokenString
}

func TestJWTAuth_ValidToken(t *testing.T) {
	auth := NewJWTAuth(testSecret)

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		ClientCode: "TESTCLIENT",
		Scopes:     []string{"upload", "read"},
	}
	token := createTestToken(claims, testSecret)

	req := httptest.NewRequest("GET", "/files/test.jpg", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	var extractedClaims *Claims
	handler := auth.Middleware(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extractedClaims = GetClaims(r)
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
	if extractedClaims == nil {
		t.Fatal("Expected claims to be extracted")
	}
	if extractedClaims.ClientCode != "TESTCLIENT" {
		t.Errorf("Expected client code TESTCLIENT, got %s", extractedClaims.ClientCode)
	}
}

func TestJWTAuth_ExpiredToken(t *testing.T) {
	auth := NewJWTAuth(testSecret)

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)), // Expired
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
		Scopes: []string{"upload"},
	}
	token := createTestToken(claims, testSecret)

	req := httptest.NewRequest("GET", "/files/test.jpg", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler := auth.Middleware(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for expired token, got %d", rr.Code)
	}
}

func TestJWTAuth_WrongSecret(t *testing.T) {
	auth := NewJWTAuth(testSecret)

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Scopes: []string{"upload"},
	}
	token := createTestToken(claims, "wrong-secret-completely-different")

	req := httptest.NewRequest("GET", "/files/test.jpg", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler := auth.Middleware(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for wrong secret, got %d", rr.Code)
	}
}

func TestJWTAuth_NoToken_Required(t *testing.T) {
	auth := NewJWTAuth(testSecret)

	req := httptest.NewRequest("GET", "/files/test.jpg", nil)
	rr := httptest.NewRecorder()

	handler := auth.Middleware(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 when no token and required=true, got %d", rr.Code)
	}
}

func TestJWTAuth_NoToken_Optional(t *testing.T) {
	auth := NewJWTAuth(testSecret)

	req := httptest.NewRequest("GET", "/files/test.jpg", nil)
	rr := httptest.NewRecorder()

	var extractedClaims *Claims
	handler := auth.Middleware(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extractedClaims = GetClaims(r)
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 when no token and required=false, got %d", rr.Code)
	}
	if extractedClaims != nil {
		t.Error("Expected nil claims for anonymous access")
	}
}

func TestJWTAuth_CookieToken(t *testing.T) {
	auth := NewJWTAuth(testSecret)

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		ClientCode: "COOKIECLIENT",
		Scopes:     []string{"read"},
	}
	token := createTestToken(claims, testSecret)

	req := httptest.NewRequest("GET", "/files/test.jpg", nil)
	req.AddCookie(&http.Cookie{Name: "jwt_token", Value: token})
	rr := httptest.NewRecorder()

	var extractedClaims *Claims
	handler := auth.Middleware(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extractedClaims = GetClaims(r)
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 for cookie token, got %d", rr.Code)
	}
	if extractedClaims == nil || extractedClaims.ClientCode != "COOKIECLIENT" {
		t.Error("Expected claims to be extracted from cookie")
	}
}

func TestClaims_HasScope(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		check    string
		expected bool
	}{
		{"has upload", []string{"upload", "read"}, "upload", true},
		{"has read", []string{"upload", "read"}, "read", true},
		{"missing delete", []string{"upload", "read"}, "delete", false},
		{"empty scopes", []string{}, "upload", false},
		{"nil claims", nil, "upload", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var claims *Claims
			if tt.scopes != nil {
				claims = &Claims{Scopes: tt.scopes}
			}
			result := claims.HasScope(tt.check)
			if result != tt.expected {
				t.Errorf("HasScope(%q) = %v, want %v", tt.check, result, tt.expected)
			}
		})
	}
}
