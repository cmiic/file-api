package main

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

//go:embed placeholder.jpg
var placeholderJPG []byte

// Config holds the service configuration from environment variables.
type Config struct {
	Port           string
	FileAPIBaseURL string
	PathPrefix     string
	ForwardHeaders []string
	MaxWidth       int
	MaxHeight      int
}

func loadConfig() Config {
	cfg := Config{
		Port:           getEnv("PORT", "8080"),
		FileAPIBaseURL: getEnv("FILE_API_BASE_URL", "http://localhost:8080/files/"),
		PathPrefix:     getEnv("PATH_PREFIX", "/files-rs"),
		MaxWidth:       getEnvInt("MAX_WIDTH", 1920),
		MaxHeight:      getEnvInt("MAX_HEIGHT", 1920),
	}

	// Parse forward headers (comma-separated)
	headers := getEnv("FORWARD_HEADERS", "Cookie,Authorization")
	for _, h := range strings.Split(headers, ",") {
		h := strings.TrimSpace(h)
		if h != "" {
			cfg.ForwardHeaders = append(cfg.ForwardHeaders, h)
		}
	}

	// Ensure base URL ends with /
	if !strings.HasSuffix(cfg.FileAPIBaseURL, "/") {
		cfg.FileAPIBaseURL += "/"
	}

	return cfg
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}

// ResizeParams holds parsed resize parameters from the URL.
type ResizeParams struct {
	Type   string // "fill" or "fit"
	Width  int
	Height int
}

// URL pattern: {PathPrefix}/rs:{type}:{w}:{h}/plain/{path}
// or: {PathPrefix}/rs:{type}:{size}/plain/{path} (single dimension for fit)
var resizePattern *regexp.Regexp

// initResizePattern initializes the global resizePattern using the given path prefix.
// It should be called once during application startup, after configuration is loaded.
func initResizePattern(pathPrefix string) {
	if pathPrefix == "" {
		pathPrefix = "/files-rs"
	}
	// Normalize prefix: ensure leading slash and no trailing slash.
	if !strings.HasPrefix(pathPrefix, "/") {
		pathPrefix = "/" + pathPrefix
	}
	pathPrefix = strings.TrimRight(pathPrefix, "/")

	escapedPrefix := regexp.QuoteMeta(pathPrefix)
	pattern := fmt.Sprintf(`^%s/rs:(fill|fit):(\d+)(?::(\d+))?(?:/[^/]+)?/plain/(.+)$`, escapedPrefix)

	resizePattern = regexp.MustCompile(pattern)
}

func parseRequest(path string) (*ResizeParams, string, error) {
	matches := resizePattern.FindStringSubmatch(path)
	if matches == nil {
		return nil, "", fmt.Errorf("invalid URL pattern")
	}

	resizeType := matches[1]
	width, err := strconv.Atoi(matches[2])
	if err != nil {
		return nil, "", fmt.Errorf("invalid width: %w", err)
	}
	height := 0
	if matches[3] != "" {
		height, err = strconv.Atoi(matches[3])
		if err != nil {
			return nil, "", fmt.Errorf("invalid height: %w", err)
		}
	}

	// For fit with single dimension, use same for both (will preserve aspect ratio)
	if height == 0 {
		height = width
	}

	filePath := matches[4]

	// Strip .jpg suffix if present (allows .pdf.jpg URLs to return JPEG)
	filePath = strings.TrimSuffix(filePath, ".jpg")

	return &ResizeParams{
		Type:   resizeType,
		Width:  width,
		Height: height,
	}, filePath, nil
}

func main() {
	cfg := loadConfig()

	initResizePattern(cfg.PathPrefix)

	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK")); err != nil {
			fmt.Fprintf(os.Stderr, "health handler write failed: %v\n", err)
		}
	})

	// PDF resize handler - matches everything under the path prefix
	mux.HandleFunc(cfg.PathPrefix+"/", func(w http.ResponseWriter, r *http.Request) {
		handlePDFResize(w, r, cfg)
	})

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	done := make(chan bool)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		server.Shutdown(ctx)
		close(done)
	}()

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "server failed: %v\n", err)
		os.Exit(1)
	}

	<-done
}

func handlePDFResize(w http.ResponseWriter, r *http.Request, cfg Config) {
	// Parse the URL to extract resize params and file path
	params, filePath, err := parseRequest(r.URL.Path)
	if err != nil {
		w.Header().Set("X-PDF-Error", "parse-failed")
		servePlaceholder(w)
		return
	}

	// Debug header to verify path parsing
	w.Header().Set("X-PDF-Path", filePath)

	// Enforce max dimensions
	if params.Width > cfg.MaxWidth {
		params.Width = cfg.MaxWidth
	}
	if params.Height > cfg.MaxHeight {
		params.Height = cfg.MaxHeight
	}

	// Fetch PDF from file-api
	pdfData, err := fetchPDF(cfg, filePath, r)
	if err != nil {
		w.Header().Set("X-PDF-Error", "fetch-failed: "+err.Error())
		servePlaceholder(w)
		return
	}

	// Convert PDF to JPEG
	jpegData, err := convertPDFToJPEG(pdfData, params)
	if err != nil {
		w.Header().Set("X-PDF-Error", "convert-failed: "+err.Error())
		servePlaceholder(w)
		return
	}

	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Content-Length", strconv.Itoa(len(jpegData)))
	w.WriteHeader(http.StatusOK)
	if n, err := w.Write(jpegData); err != nil {
		// Log write errors; response headers and status have already been sent.
		fmt.Fprintf(os.Stderr, "error writing JPEG response (wrote %d of %d bytes): %v\n", n, len(jpegData), err)
	}
}

func fetchPDF(cfg Config, filePath string, origReq *http.Request) ([]byte, error) {
	url := cfg.FileAPIBaseURL + filePath

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Forward configured headers from the original request
	for _, header := range cfg.ForwardHeaders {
		if val := origReq.Header.Get(header); val != "" {
			req.Header.Set(header, val)
		}
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("file-api returned status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func convertPDFToJPEG(pdfData []byte, params *ResizeParams) ([]byte, error) {
	// Create temp directory for this conversion
	tmpDir, err := os.MkdirTemp("", "pdf-convert-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	// Write PDF to temp file
	pdfPath := filepath.Join(tmpDir, "input.pdf")
	if err := os.WriteFile(pdfPath, pdfData, 0600); err != nil {
		return nil, err
	}

	// Output path (pdftocairo adds .jpg extension with -singlefile)
	outputBase := filepath.Join(tmpDir, "output")

	// Build pdftocairo command
	// -jpeg: output JPEG format
	// -singlefile: only first page, no page number suffix
	// -scale-to-x: scale width (use -1 for auto based on height)
	// -scale-to-y: scale height (use -1 for auto based on width)
	// For "fill" we want to cover the area, for "fit" we want to fit within
	args := []string{
		"-jpeg",
		"-singlefile",
		"-f", "1", // first page
		"-l", "1", // last page (same as first = only page 1)
	}

	if params.Type == "fill" {
		// Fill: scale to cover the requested dimensions
		// Use the larger scale factor to ensure coverage
		args = append(args, "-scale-to-x", strconv.Itoa(params.Width))
		args = append(args, "-scale-to-y", strconv.Itoa(params.Height))
	} else {
		// Fit: scale to fit within the requested dimensions
		// Use -scale-to which fits within a square of that size
		maxDim := params.Width
		if params.Height > maxDim {
			maxDim = params.Height
		}
		args = append(args, "-scale-to", strconv.Itoa(maxDim))
	}

	args = append(args, pdfPath, outputBase)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "pdftocairo", args...)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("pdftocairo conversion failed: %w", err)
	}

	// Read the output JPEG
	outputPath := outputBase + ".jpg"
	return os.ReadFile(outputPath)
}

func servePlaceholder(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Content-Length", strconv.Itoa(len(placeholderJPG)))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(placeholderJPG); err != nil {
		log.Printf("error writing placeholder image: %v", err)
	}
}
