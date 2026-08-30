// Package middleware provides HTTP middleware functions.
package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// ContextKey is a type for context keys to avoid collisions.
type ContextKey string

const (
	// ClaimsKey is the context key for JWT claims.
	ClaimsKey ContextKey = "claims"
)

// Claims represents the JWT claims we expect.
type Claims struct {
	jwt.RegisteredClaims
	ClientCode string   `json:"cli_code,omitempty"` // Client code for private file access
	Scopes     []string `json:"scopes,omitempty"`   // Permissions: "upload", "read", "delete"
}

// JWTAuth is middleware for validating JWT tokens.
type JWTAuth struct {
	secret []byte
}

// NewJWTAuth creates a new JWTAuth middleware with the given secret.
func NewJWTAuth(secret string) *JWTAuth {
	return &JWTAuth{
		secret: []byte(secret),
	}
}

// Middleware returns an HTTP middleware that validates JWT tokens.
// If required is true, requests without valid tokens are rejected.
// If required is false, the middleware extracts claims if present but allows anonymous access.
func (j *JWTAuth) Middleware(required bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := j.extractClaims(r)

			if err != nil && required {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Store claims in context (may be nil for anonymous access)
			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractClaims extracts and validates JWT claims from the request.
func (j *JWTAuth) extractClaims(r *http.Request) (*Claims, error) {
	// Get token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		// Also check for token in cookie (for backward compatibility)
		cookie, err := r.Cookie("jwt_token")
		if err != nil {
			return nil, errors.New("no token provided")
		}
		authHeader = "Bearer " + cookie.Value
	}

	// Parse Bearer token
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, errors.New("invalid authorization header format")
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return j.secret, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

// GetClaims retrieves JWT claims from the request context.
// Returns nil if no claims are present (anonymous access).
func GetClaims(r *http.Request) *Claims {
	claims, _ := r.Context().Value(ClaimsKey).(*Claims)
	return claims
}

// HasScope checks if the claims include a specific scope.
func (c *Claims) HasScope(scope string) bool {
	if c == nil {
		return false
	}
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// RequireClientCode is middleware that ensures the JWT client code matches
// the requested client code in the URL path.
func RequireClientCode(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := GetClaims(r)
		if claims == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Extract client code from path
		// Paths like: /files/cli/{code}/... or /file-upload/cli/{code}
		path := r.URL.Path
		requestedCode := extractClientCodeFromPath(path)

		if requestedCode == "" {
			// No client code in path - this is a public resource
			next.ServeHTTP(w, r)
			return
		}

		// Verify JWT client code matches requested client code
		if claims.ClientCode != requestedCode {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// extractClientCodeFromPath extracts the client code from URL paths containing /cli/{code}.
func extractClientCodeFromPath(path string) string {
	// Look for /cli/ in the path
	idx := strings.Index(path, "/cli/")
	if idx == -1 {
		return ""
	}

	// Extract the segment after /cli/
	rest := path[idx+5:] // Skip "/cli/"
	if rest == "" {
		return ""
	}

	// Find the end of the client code (next / or end of string)
	endIdx := strings.Index(rest, "/")
	if endIdx == -1 {
		return rest
	}
	return rest[:endIdx]
}
