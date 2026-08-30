package util

import (
	"net"
	"testing"
)

func TestIsValidURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		// Valid external URLs
		{"valid https", "https://example.com/image.jpg", true},
		{"valid http", "http://example.com/image.jpg", true},
		{"valid with port", "https://example.com:8080/image.jpg", true},
		{"valid with query", "https://example.com/image.jpg?size=large", true},
		{"valid subdomain", "https://cdn.example.com/images/photo.png", true},

		// Invalid schemes
		{"empty url", "", false},
		{"file scheme", "file:///etc/passwd", false},
		{"ftp scheme", "ftp://example.com/file.txt", false},
		{"gopher scheme", "gopher://evil.com/", false},
		{"javascript scheme", "javascript:alert(1)", false},
		{"data scheme", "data:text/html,<script>alert(1)</script>", false},

		// Private IPs - RFC1918
		{"localhost", "http://localhost/api", false},
		{"localhost 127.0.0.1", "http://127.0.0.1/api", false},
		{"localhost ::1", "http://[::1]/api", false},
		{"private 10.x", "http://10.0.0.1/internal", false},
		{"private 172.16.x", "http://172.16.0.1/internal", false},
		{"private 172.31.x", "http://172.31.255.255/internal", false},
		{"private 192.168.x", "http://192.168.1.1/admin", false},

		// Link-local and metadata
		{"link-local", "http://169.254.1.1/", false},
		{"aws metadata", "http://169.254.169.254/latest/meta-data/", false},
		{"cgnat", "http://100.64.0.1/internal", false},

		// Edge cases
		{"no host", "http:///path", false},
		{"only scheme", "http://", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidURL(tt.url)
			if result != tt.expected {
				t.Errorf("IsValidURL(%q) = %v, want %v", tt.url, result, tt.expected)
			}
		})
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		maxLen   int
		expected string
	}{
		// Basic cases
		{"normal filename", "document.pdf", 60, "document.pdf"},
		{"spaces to dashes", "my file.pdf", 60, "my-file.pdf"},
		{"semicolons to dashes", "file;name.pdf", 60, "file-name.pdf"},
		{"slashes to underscores", "path/file.pdf", 60, "path_file.pdf"},
		{"backslashes to underscores", "path\\file.pdf", 60, "path_file.pdf"},

		// German umlauts
		{"umlaut ä", "bäcker.pdf", 60, "baecker.pdf"},
		{"umlaut ö", "König.pdf", 60, "Koenig.pdf"},
		{"umlaut ü", "Müller.pdf", 60, "Mueller.pdf"},
		{"umlaut ß", "straße.pdf", 60, "strasse.pdf"},
		{"mixed umlauts", "Größe_Übung.pdf", 60, "Groesse_Uebung.pdf"},

		// Special characters removed
		{"emoji removed", "file😀.pdf", 60, "file.pdf"},
		{"unicode removed", "文件.pdf", 60, "pdf"},

		// Truncation
		{"truncate long name", "verylongfilename.pdf", 10, "verylongfi.pdf"},
		{"no truncate", "short.pdf", 60, "short.pdf"},

		// Edge cases
		{"empty string", "", 60, ""},
		{"multiple dashes", "file--name.pdf", 60, "file-name.pdf"},
		{"leading dots trimmed", "...file.pdf", 60, "file.pdf"},
		{"trailing dashes trimmed", "file-.pdf", 60, "file-.pdf"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeFilename(tt.filename, tt.maxLen)
			if result != tt.expected {
				t.Errorf("SanitizeFilename(%q, %d) = %q, want %q", tt.filename, tt.maxLen, result, tt.expected)
			}
		})
	}
}

func TestIsValidClientCode(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		expected bool
	}{
		{"valid simple", "ACME", true},
		{"valid with numbers", "CLIENT123", true},
		{"valid with underscore", "MY_CLIENT", true},
		{"valid with dash", "MY-CLIENT", true},
		{"valid max length", "1234567890123456", true}, // 16 chars

		{"empty", "", false},
		{"too long", "12345678901234567", false}, // 17 chars
		{"space not allowed", "MY CLIENT", false},
		{"slash not allowed", "MY/CLIENT", false},
		{"dot not allowed", "MY.CLIENT", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidClientCode(tt.code)
			if result != tt.expected {
				t.Errorf("IsValidClientCode(%q) = %v, want %v", tt.code, result, tt.expected)
			}
		})
	}
}

func TestIsValidRelativePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"valid simple", "2025/01/file.jpg", true},
		{"valid with underscore", "2025/01/my_file.jpg", true},
		{"valid deep path", "a/b/c/d/e/file.jpg", true},

		{"empty", "", false},
		{"directory traversal", "../etc/passwd", false},
		{"directory traversal mid", "2025/../../../etc/passwd", false},
		{"space not allowed", "2025/01/my file.jpg", false},
		{"backslash not allowed", "2025\\01\\file.jpg", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidRelativePath(tt.path)
			if result != tt.expected {
				t.Errorf("IsValidRelativePath(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// Loopback
		{"loopback ipv4", "127.0.0.1", true},
		{"loopback ipv4 other", "127.0.0.2", true},
		{"loopback ipv6", "::1", true},

		// RFC1918 private
		{"10.x.x.x", "10.0.0.1", true},
		{"10.255.255.255", "10.255.255.255", true},
		{"172.16.x.x", "172.16.0.1", true},
		{"172.31.x.x", "172.31.255.255", true},
		{"192.168.x.x", "192.168.1.1", true},

		// Link-local
		{"link-local ipv4", "169.254.1.1", true},
		{"aws metadata", "169.254.169.254", true},
		{"link-local ipv6", "fe80::1", true},

		// CGNAT
		{"cgnat start", "100.64.0.1", true},
		{"cgnat end", "100.127.255.255", true},

		// Public IPs
		{"public 8.8.8.8", "8.8.8.8", false},
		{"public 1.1.1.1", "1.1.1.1", false},
		{"public 93.x.x.x", "93.184.216.34", false},

		// Edge of private ranges (should be public)
		{"172.15.x.x public", "172.15.255.255", false},
		{"172.32.x.x public", "172.32.0.1", false},
		{"100.63.x.x public", "100.63.255.255", false},
		{"100.128.x.x public", "100.128.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}
			result := isPrivateIP(ip)
			if result != tt.expected {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}
