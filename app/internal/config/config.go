// Package config handles application configuration from environment variables.
package config

import (
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

// MinJWTSecretLen is the minimum required length for JWT secrets.
const MinJWTSecretLen = 32

// DeleteAnyAge is the window of a file class configured as "unlimited". It is
// the largest Duration: time.Since saturates there, so no file is ever older
// and the handler's age comparison needs no special case.
const DeleteAnyAge = time.Duration(math.MaxInt64)

// Config holds all application configuration.
type Config struct {
	// Server
	Port string

	// Storage
	BasePath string

	// JWT
	JWTSecret string

	// Limits
	MaxUploadSize  int64
	MaxFilenameLen int

	// Deletion windows, bounding how old a file may be when it is deleted. Zero
	// disables deletion for that class of file; DeleteAnyAge removes the bound.
	// The DELETE /files/ route is registered only when at least one is set.
	DeleteMaxAge        time.Duration // public files
	DeleteMaxAgePrivate time.Duration // private files

	// Moderation - Scanners
	MalwareScannerURL string // e.g., http://malware-scanner:8081
	MediaScreenerURL  string // e.g., http://media-screener:8080
	ScanTimeoutMS     int    // HTTP timeout for scanner calls (default 30000)

	// Moderation - Metadata storage
	ScanMetaPath  string // e.g., /data/scan-meta
	ScanQueuePath string // e.g., /data/scan-queue (for retry)

	// Moderation - Email notifications
	SMTPHost    string
	SMTPPort    int
	SMTPFrom    string
	AlertEmails string // comma-separated list
}

// Load reads configuration from environment variables with sensible defaults.
// Panics if critical security configuration is missing or invalid.
func Load() *Config {
	jwtSecret := getSecret("JWT_SECRET", "JWT_SECRET_FILE", "")

	// Fail fast on empty or weak JWT secret
	if jwtSecret == "" {
		log.Fatal("FATAL: JWT_SECRET or JWT_SECRET_FILE must be set")
	}
	if len(jwtSecret) < MinJWTSecretLen {
		log.Fatalf("FATAL: JWT secret must be at least %d characters (got %d)", MinJWTSecretLen, len(jwtSecret))
	}

	deleteMaxAge, deleteMaxAgePrivate, err := deleteWindows(os.Getenv("DELETE_MAX_AGE"), os.Getenv("DELETE_MAX_AGE_PRIVATE"))
	if err != nil {
		// Fail fast rather than fall back: a typo here must not silently
		// disable deletion (the app would then get 405s it does not expect)
		// nor silently widen the window.
		log.Fatalf("FATAL: %v", err)
	}

	return &Config{
		Port:           getEnv("PORT", "8080"),
		BasePath:       getEnv("BASE_PATH", "/data/files"),
		JWTSecret:      jwtSecret,
		MaxUploadSize:  getEnvInt64("MAX_UPLOAD_SIZE", 200*1024*1024), // 200MB
		MaxFilenameLen: getEnvInt("MAX_FILENAME_LEN", 60),

		DeleteMaxAge:        deleteMaxAge,
		DeleteMaxAgePrivate: deleteMaxAgePrivate,

		// Moderation - Scanners (empty = disabled)
		MalwareScannerURL: getEnv("MALWARE_SCANNER_URL", ""),
		MediaScreenerURL:  getEnv("MEDIA_SCREENER_URL", ""),
		ScanTimeoutMS:     getEnvInt("SCAN_TIMEOUT_MS", 30000),

		// Moderation - Metadata storage
		ScanMetaPath:  getEnv("SCAN_META_PATH", "/data/scan-meta"),
		ScanQueuePath: getEnv("SCAN_QUEUE_PATH", "/data/scan-queue"),

		// Moderation - Email notifications
		SMTPHost:    getEnv("SMTP_HOST", ""),
		SMTPPort:    getEnvInt("SMTP_PORT", 25),
		SMTPFrom:    getEnv("SMTP_FROM", "file-api@localhost"),
		AlertEmails: getEnv("ALERT_EMAILS", ""),
	}
}

// deleteWindows resolves the public and private deletion windows from the raw
// DELETE_MAX_AGE and DELETE_MAX_AGE_PRIVATE values. DELETE_MAX_AGE covers both
// classes of file unless DELETE_MAX_AGE_PRIVATE overrides it for private ones,
// so a deployment that sets only DELETE_MAX_AGE keeps one window for all files.
func deleteWindows(public, private string) (publicAge, privateAge time.Duration, err error) {
	publicAge, err = parseDeleteMaxAge("DELETE_MAX_AGE", public)
	if err != nil {
		return 0, 0, err
	}
	privateAge, err = parseDeleteMaxAge("DELETE_MAX_AGE_PRIVATE", private)
	if err != nil {
		return 0, 0, err
	}
	if privateAge == 0 {
		privateAge = publicAge
	}
	return publicAge, privateAge, nil
}

// parseDeleteMaxAge interprets a deletion window variable, whose name is used
// in error messages. Unset or empty means no window of its own, which is the
// default. Anything else, including a value that is only whitespace, must be
// a positive Go duration such as "30m" or "24h", or the keyword "unlimited";
// a value that does not parse, or is zero or negative, is an error so that
// Load can refuse to start. Surrounding whitespace around a real value is
// tolerated.
func parseDeleteMaxAge(name, raw string) (time.Duration, error) {
	if raw == "" {
		return 0, nil
	}
	value := strings.TrimSpace(raw)
	if value == "unlimited" {
		return DeleteAnyAge, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s %q is not a duration (use e.g. 30m or 24h, or unlimited): %w", name, raw, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s %q must be positive; unset it to remove this window", name, raw)
	}
	return d, nil
}

// DescribeDeleteWindow renders a deletion window for the startup log.
func DescribeDeleteWindow(d time.Duration) string {
	switch d {
	case 0:
		return "off"
	case DeleteAnyAge:
		return "any age"
	default:
		return "younger than " + d.String()
	}
}

// getSecret reads a secret from env var or file path (for container secrets).
// Checks envKey first, then reads from file at fileEnvKey path if set.
func getSecret(envKey, fileEnvKey, defaultValue string) string {
	// First try direct env var
	if value := os.Getenv(envKey); value != "" {
		return value
	}

	// Then try file-based secret (Docker/Podman secrets pattern)
	if filePath := os.Getenv(fileEnvKey); filePath != "" {
		if data, err := os.ReadFile(filePath); err == nil {
			return strings.TrimSpace(string(data))
		}
	}

	return defaultValue
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.ParseInt(value, 10, 64); err == nil {
			return i
		}
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}
