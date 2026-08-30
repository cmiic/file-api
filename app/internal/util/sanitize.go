// Package util provides utility functions for the file API.
package util

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

// Filename validation pattern: alphanumeric, dash, underscore, dot, parentheses
var validFilename = regexp.MustCompile(`^[a-zA-Z0-9\-_().]+$`)

// ClientCode validation pattern
var validClientCode = regexp.MustCompile(`^[a-zA-Z0-9\-_()]+$`)

// RelativePath validation pattern
var validRelativePath = regexp.MustCompile(`^[a-zA-Z0-9_\-/.]+$`)

// Remove non-allowed characters
var nonAlphanumeric = regexp.MustCompile(`[^a-zA-Z0-9\-_.]`)

// multiDash matches multiple consecutive dashes or underscores
var multiDash = regexp.MustCompile(`[-_]{2,}`)

// SanitizeFilename cleans a filename to be safe for storage.
// Replicates the logic from legacy optutils.lua:
// - Replaces dangerous shell characters
// - Converts German umlauts to ASCII equivalents
// - Removes any remaining non-alphanumeric characters
// - Truncates to maxLen characters (name part only, not extension)
func SanitizeFilename(filename string, maxLen int) string {
	if filename == "" {
		return ""
	}

	s := filename

	// Replace dangerous shell characters
	s = strings.ReplaceAll(s, ";", "-")
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")

	// Replace German umlauts
	umlauts := map[string]string{
		"ä": "ae", "Ä": "Ae",
		"ö": "oe", "Ö": "Oe",
		"ü": "ue", "Ü": "Ue",
		"ß": "ss",
	}
	for old, replacement := range umlauts {
		s = strings.ReplaceAll(s, old, replacement)
	}

	// Remove everything not alphanumeric, dash, underscore, or dot
	s = nonAlphanumeric.ReplaceAllString(s, "")

	// Remove multiple consecutive dashes or underscores
	s = multiDash.ReplaceAllString(s, "-")

	// Trim leading/trailing dashes, underscores, dots
	s = strings.Trim(s, "-_.")

	// Truncate name part (not extension) to maxLen
	if maxLen > 0 && len(s) > maxLen {
		// Find extension
		ext := ""
		if dotIdx := strings.LastIndex(s, "."); dotIdx > 0 {
			ext = s[dotIdx:]
			s = s[:dotIdx]
		}

		// Truncate name part
		if len(s) > maxLen {
			s = s[:maxLen]
		}

		// Trim trailing dash/underscore after truncation
		s = strings.TrimRight(s, "-_")

		// Reattach extension
		s = s + ext
	}

	return s
}

// IsValidFilename checks if a filename matches the allowed pattern.
func IsValidFilename(filename string) bool {
	return validFilename.MatchString(filename)
}

// IsValidClientCode checks if a client code matches the allowed pattern.
func IsValidClientCode(code string) bool {
	return code != "" && len(code) <= 16 && validClientCode.MatchString(code)
}

// IsValidRelativePath checks if a relative path is safe.
func IsValidRelativePath(path string) bool {
	if path == "" || len(path) > 250 {
		return false
	}
	// Prevent directory traversal
	if strings.Contains(path, "..") {
		return false
	}
	return validRelativePath.MatchString(path)
}

// IsValidURL checks if a URL is valid and safe for fetching.
// Only allows http/https schemes and blocks private/internal IPs.
func IsValidURL(rawURL string) bool {
	if rawURL == "" {
		return false
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	// Only allow http and https schemes
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}

	// Must have a host
	if parsed.Host == "" {
		return false
	}

	// Extract hostname (without port)
	host := parsed.Hostname()

	// Block localhost variants
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return false
	}

	// Parse as IP and check if private
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return false
		}
	}

	return true
}

// isPrivateIP checks if an IP is private, loopback, link-local, or otherwise internal.
func isPrivateIP(ip net.IP) bool {
	// Loopback (127.x.x.x, ::1)
	if ip.IsLoopback() {
		return true
	}

	// Link-local (169.254.x.x, fe80::)
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Private ranges (10.x, 172.16-31.x, 192.168.x, fc00::/7)
	if ip.IsPrivate() {
		return true
	}

	// Cloud metadata endpoints (169.254.169.254 is covered by link-local)
	// Also block 100.64.0.0/10 (Carrier-grade NAT)
	if ip4 := ip.To4(); ip4 != nil {
		// 100.64.0.0/10 - CGNAT
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
	}

	return false
}

// ExtractExtension returns the lowercase file extension without the dot.
func ExtractExtension(filename string) string {
	if dotIdx := strings.LastIndex(filename, "."); dotIdx > 0 && dotIdx < len(filename)-1 {
		return strings.ToLower(filename[dotIdx+1:])
	}
	return ""
}

// ExtractBaseName returns the filename without the extension.
func ExtractBaseName(filename string) string {
	if dotIdx := strings.LastIndex(filename, "."); dotIdx > 0 {
		return filename[:dotIdx]
	}
	return filename
}
