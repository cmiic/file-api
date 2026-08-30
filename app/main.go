// Package main is the entry point for the file API server.
package main

import (
	"log"
	"net/http"
	"os"

	"file-api/internal/config"
	"file-api/internal/handler"
	"file-api/internal/middleware"
	"file-api/internal/moderation"
	"file-api/internal/notifier"
	"file-api/internal/scanner"
	"file-api/internal/storage"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Validate required configuration - fail fast if JWT_SECRET is missing
	if cfg.JWTSecret == "" {
		log.Fatal("FATAL: JWT_SECRET environment variable is required but not set")
	}

	// Initialize storage
	store := storage.NewStorage(cfg.BasePath, cfg.MaxFilenameLen)

	// Ensure base path exists
	if err := os.MkdirAll(cfg.BasePath, 0755); err != nil {
		log.Fatalf("Failed to create base path %s: %v", cfg.BasePath, err)
	}

	// Initialize moderation services (scanner + notifier)
	var moderationSvc *moderation.Service
	if cfg.MalwareScannerURL != "" || cfg.MediaScreenerURL != "" {
		scannerClient := scanner.NewClient(
			cfg.MalwareScannerURL,
			cfg.MediaScreenerURL,
			cfg.ScanTimeoutMS,
		)
		emailNotifier := notifier.NewNotifier(
			cfg.SMTPHost,
			cfg.SMTPPort,
			cfg.SMTPFrom,
			cfg.AlertEmails,
		)
		moderationSvc = moderation.NewService(
			scannerClient,
			emailNotifier,
			cfg.ScanMetaPath,
			cfg.ScanQueuePath,
			store.DeleteFile,
		)
		log.Printf("Moderation enabled: malware=%v, nsfw=%v",
			cfg.MalwareScannerURL != "", cfg.MediaScreenerURL != "")
	} else {
		log.Println("Moderation disabled (no scanner URLs configured)")
	}

	// Initialize JWT middleware
	jwtAuth := middleware.NewJWTAuth(cfg.JWTSecret)

	// Initialize handlers with size limits
	uploadHandler := handler.NewUploadHandler(store, moderationSvc, cfg.MaxUploadSize, cfg.JWTSecret)
	fetchHandler := handler.NewFetchHandler(store, cfg.MaxUploadSize, cfg.JWTSecret)
	serveHandler := handler.NewServeHandler(store)
	healthHandler := handler.NewHealthHandler()
	metaHandler := handler.NewMetaHandler(moderationSvc)

	// Create router using Go 1.22+ ServeMux with pattern matching
	mux := http.NewServeMux()

	// Health check endpoint (no auth)
	mux.Handle("GET /health", healthHandler)

	// Public file serving (no auth required)
	// Match /files/ but not /files/cli/
	mux.Handle("GET /files/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if this is a private path
		if storage.IsPrivatePath(r.URL.Path) {
			// Apply JWT middleware for private paths
			jwtAuth.Middleware(true)(serveHandler).ServeHTTP(w, r)
		} else {
			// No auth for public paths
			serveHandler.ServeHTTP(w, r)
		}
	}))
	mux.Handle("HEAD /files/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if storage.IsPrivatePath(r.URL.Path) {
			jwtAuth.Middleware(true)(serveHandler).ServeHTTP(w, r)
		} else {
			serveHandler.ServeHTTP(w, r)
		}
	}))

	// Upload endpoints (JWT required)
	// POST /file-upload - public upload
	// POST /file-upload/cli/{code} - private upload
	mux.Handle("POST /file-upload", jwtAuth.Middleware(true)(uploadHandler))
	mux.Handle("POST /file-upload/", jwtAuth.Middleware(true)(uploadHandler))

	// Fetch endpoints (JWT required)
	// POST /file-resize/url/{url} - public fetch
	// POST /file-resize/cli/{code}/url/{url} - private fetch
	mux.Handle("POST /file-resize", jwtAuth.Middleware(true)(fetchHandler))
	mux.Handle("POST /file-resize/", jwtAuth.Middleware(true)(fetchHandler))

	// Metadata endpoint (JWT required with scan:read scope)
	// GET /meta/files/{path...} - get scan metadata for a file
	mux.Handle("GET /meta/files/", jwtAuth.Middleware(true)(metaHandler))

	// Logging middleware
	loggedMux := loggingMiddleware(mux)

	// Start server
	addr := ":" + cfg.Port
	log.Printf("Starting file API server on %s", addr)
	log.Printf("Base path: %s", cfg.BasePath)
	log.Printf("Max upload size: %d bytes", cfg.MaxUploadSize)

	if err := http.ListenAndServe(addr, loggedMux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// loggingMiddleware logs all incoming requests.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}
