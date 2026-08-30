// Package config handles application configuration from environment variables.
package config

import (
	"log"
	"os"
	"strconv"
	"strings"
)

// MinJWTSecretLen is the minimum required length for JWT secrets.
const MinJWTSecretLen = 32

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

	return &Config{
		Port:           getEnv("PORT", "8080"),
		BasePath:       getEnv("BASE_PATH", "/data/files"),
		JWTSecret:      jwtSecret,
		MaxUploadSize:  getEnvInt64("MAX_UPLOAD_SIZE", 200*1024*1024), // 200MB
		MaxFilenameLen: getEnvInt("MAX_FILENAME_LEN", 60),

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
