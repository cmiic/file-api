package util

import (
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.1.2.3", "::1",
		"10.0.0.5", "172.16.0.1", "192.168.1.1", "fd00::1",
		"0.0.0.0", "::",
		"169.254.1.1", "169.254.169.254", "fe80::1",
		"224.0.0.1", "ff02::1",
		"100.64.0.1", "100.127.255.255",
		"::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1",
	}
	for _, s := range blocked {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test bug: %q is not an IP", s)
		}
		if !BlockedIP(ip) {
			t.Errorf("BlockedIP(%s) = false, want true", s)
		}
	}

	allowed := []string{
		"8.8.8.8", "1.1.1.1", "93.184.216.34",
		"172.15.255.255", "172.32.0.1",
		"100.63.255.255", "100.128.0.1",
		"2606:4700:4700::1111",
	}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test bug: %q is not an IP", s)
		}
		if BlockedIP(ip) {
			t.Errorf("BlockedIP(%s) = true, want false", s)
		}
	}

	if !BlockedIP(nil) {
		t.Error("BlockedIP(nil) = false, want true - an unknown address must not be dialled")
	}
}

func TestSafeDialControlRejectsNonPublic(t *testing.T) {
	if err := SafeDialControl("tcp", "127.0.0.1:80", nil); err == nil {
		t.Error("expected loopback to be refused")
	}
	if err := SafeDialControl("tcp", "8.8.8.8:80", nil); err != nil {
		t.Errorf("expected a public address to be allowed, got %v", err)
	}
	// An address Control could not have produced: refuse rather than assume.
	if err := SafeDialControl("tcp", "not-an-ip:80", nil); err == nil {
		t.Error("expected an unresolved address to be refused")
	}
	if err := SafeDialControl("tcp", "missing-port", nil); err == nil {
		t.Error("expected an unparseable dial address to be refused")
	}
}

// TestDialGuardBlocksStringCheckBypasses is the regression test for the SSRF.
//
// Every URL here passed IsValidURL before the guard existed, and every one
// reaches loopback: net.ParseIP rejects these spellings so the old private-IP
// check never ran, while the system resolver accepts them.
func TestDialGuardBlocksStringCheckBypasses(t *testing.T) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 3 * time.Second, Control: SafeDialControl}).DialContext,
		},
	}

	bypasses := []struct {
		name string
		url  string
	}{
		{"uppercase host", "http://LOCALHOST/x"},
		{"trailing root dot", "http://localhost./x"},
		{"short-form ipv4", "http://127.1/x"},
		{"unspecified address", "http://0.0.0.0/x"},
		{"decimal ip", "http://2130706433/x"},
		{"octal ip", "http://0177.0.0.1/x"},
	}

	for _, tt := range bypasses {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.Get(tt.url)
			if err == nil {
				resp.Body.Close()
				t.Fatalf("%s was dialled successfully; the guard did not hold", tt.url)
			}
			// Distinguish "the guard refused" from "the host happened not to
			// resolve here", so this cannot pass for the wrong reason.
			if !strings.Contains(err.Error(), "refusing to dial") {
				t.Errorf("%s failed for an unrelated reason: %v", tt.url, err)
			}
		})
	}
}

// The two spellings IsValidURL can reject on its own should stay rejected.
func TestIsValidURLNormalisesHost(t *testing.T) {
	for _, u := range []string{
		"http://LOCALHOST/x",
		"http://localhost./x",
		"http://LocalHost./x",
		"http://localhost/x",
	} {
		if IsValidURL(u) {
			t.Errorf("IsValidURL(%q) = true, want false", u)
		}
	}
	if !IsValidURL("http://example.com/x") {
		t.Error("IsValidURL rejected an ordinary public URL")
	}
}
