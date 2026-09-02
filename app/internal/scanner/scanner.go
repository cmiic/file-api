// Package scanner provides HTTP clients for malware and NSFW scanning services.
package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"time"
)

// MalwareResult contains the response from the malware scanner /classify endpoint.
type MalwareResult struct {
	Filename   string  `json:"filename"`
	Clean      bool    `json:"clean"`
	ScanTimeMS float64 `json:"scan_time_ms"`
}

// MalwareScanResult contains the response from the malware scanner /scan endpoint.
type MalwareScanResult struct {
	Filename    string  `json:"filename"`
	Size        int64   `json:"size"`
	Infected    bool    `json:"infected"`
	MalwareName *string `json:"malware_name"`
	ScanTimeMS  float64 `json:"scan_time_ms"`
}

// NSFWResult contains the response from the media screener /classify endpoint.
type NSFWResult struct {
	Format          string   `json:"format"`
	Unsafe          bool     `json:"unsafe"`
	Confidence      float64  `json:"confidence"`
	DetectedClasses []string `json:"detected_classes"`
	FramesChecked   int      `json:"frames_checked,omitempty"`
	TotalFrames     int      `json:"total_frames,omitempty"`
	PagesChecked    int      `json:"pages_checked,omitempty"`
	TotalPages      int      `json:"total_pages,omitempty"`
	FirstUnsafeAt   *float64 `json:"first_unsafe_at,omitempty"`
}

// Client provides methods to scan files for malware and NSFW content.
type Client struct {
	httpClient        *http.Client
	malwareScannerURL string
	mediaScreenerURL  string
}

// NewClient creates a new scanner client.
// Either URL can be empty to disable that scanner.
func NewClient(malwareScannerURL, mediaScreenerURL string, timeoutMS int) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: time.Duration(timeoutMS) * time.Millisecond,
		},
		malwareScannerURL: malwareScannerURL,
		mediaScreenerURL:  mediaScreenerURL,
	}
}

// MalwareEnabled returns true if the malware scanner is configured.
func (c *Client) MalwareEnabled() bool {
	return c.malwareScannerURL != ""
}

// NSFWEnabled returns true if the media screener is configured.
func (c *Client) NSFWEnabled() bool {
	return c.mediaScreenerURL != ""
}

// ScanMalware sends a file to the malware scanner and returns the detailed result.
// Returns nil result and nil error if malware scanning is disabled.
func (c *Client) ScanMalware(name string, content io.Reader) (*MalwareScanResult, error) {
	if !c.MalwareEnabled() {
		return nil, nil
	}

	url := c.malwareScannerURL + "/scan"
	resp, err := c.uploadFile(url, name, content)
	if err != nil {
		return nil, fmt.Errorf("malware scan request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("malware scanner returned %d: %s", resp.StatusCode, string(body))
	}

	var result MalwareScanResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode malware scan response: %w", err)
	}

	return &result, nil
}

// ScanNSFW sends a file to the media screener and returns the result.
// Returns nil result and nil error if NSFW scanning is disabled.
func (c *Client) ScanNSFW(name string, content io.Reader) (*NSFWResult, error) {
	if !c.NSFWEnabled() {
		return nil, nil
	}

	url := c.mediaScreenerURL + "/classify"
	resp, err := c.uploadFile(url, name, content)
	if err != nil {
		return nil, fmt.Errorf("nsfw scan request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("media screener returned %d: %s", resp.StatusCode, string(body))
	}

	var result NSFWResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode nsfw scan response: %w", err)
	}

	return &result, nil
}

// uploadFile sends content as multipart/form-data to the given URL.
//
// Takes an open reader rather than a path. The caller opens through the
// storage root, so the scanner cannot be aimed at a file outside it, and this
// package no longer touches the filesystem at all.
func (c *Client) uploadFile(url, name string, content io.Reader) (*http.Response, error) {
	// Create multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	part, err := writer.CreateFormFile("file", filepath.Base(name))
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %w", err)
	}

	if _, err := io.Copy(part, content); err != nil {
		return nil, fmt.Errorf("failed to copy file content: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close multipart writer: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, &buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	return c.httpClient.Do(req)
}
