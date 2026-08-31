package notifier

import (
	"strings"
	"testing"
)

func testNotifier() *Notifier {
	return &Notifier{
		host:       "mail.example.invalid",
		port:       25,
		from:       "file-api@example.invalid",
		recipients: []string{"ops@example.invalid"},
		enabled:    true,
	}
}

// TestBuildMessageStripsSubjectCRLF covers header injection: a subject
// carrying CR/LF could otherwise close the Subject line and append
// headers of its own. Every caller passes a constant subject today -
// this keeps that safe for callers that don't yet exist.
func TestBuildMessageStripsSubjectCRLF(t *testing.T) {
	n := testNotifier()

	msg := n.buildMessage("alert\r\nBcc: attacker@example.invalid", "body")

	headers, body, found := strings.Cut(msg, "\r\n\r\n")
	if !found {
		t.Fatalf("message has no header/body separator: %q", msg)
	}

	// The injected text is neutralized by staying *inside* the Subject
	// line - what must not happen is it starting a header line of its
	// own, so assert on line starts rather than on the text appearing.
	for _, line := range strings.Split(headers, "\r\n") {
		if strings.HasPrefix(line, "Bcc:") {
			t.Errorf("injected header became its own header line:\n%s", headers)
		}
	}
	if got := strings.Count(headers, "Subject:"); got != 1 {
		t.Errorf("expected exactly one Subject header, got %d:\n%s", got, headers)
	}
	if body != "body" {
		t.Errorf("body = %q, want %q", body, "body")
	}
}

func TestBuildMessageKeepsOrdinarySubject(t *testing.T) {
	n := testNotifier()

	msg := n.buildMessage("[file-api] Malware detected and removed", "File: 2026/1/x.jpg\n")

	if !strings.Contains(msg, "Subject: [file-api] Malware detected and removed\r\n") {
		t.Errorf("subject not preserved verbatim:\n%s", msg)
	}
	if !strings.Contains(msg, "From: file-api@example.invalid\r\n") {
		t.Errorf("from header missing:\n%s", msg)
	}
	if !strings.HasSuffix(msg, "File: 2026/1/x.jpg\n") {
		t.Errorf("body not preserved:\n%s", msg)
	}
}

func TestSendAlertDisabledIsNoOp(t *testing.T) {
	n := &Notifier{enabled: false}
	if err := n.SendAlert("subject", "body"); err != nil {
		t.Errorf("disabled notifier should not error, got %v", err)
	}
}
