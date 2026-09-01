package notifier

import (
	"bufio"
	"net"
	"strconv"
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

// headerLines returns the header block of a built message, split into
// lines, so tests can assert on what is and is not its own header.
func headerLines(t *testing.T, msg string) []string {
	t.Helper()
	headers, _, found := strings.Cut(msg, "\r\n\r\n")
	if !found {
		t.Fatalf("message has no header/body separator: %q", msg)
	}
	return strings.Split(headers, "\r\n")
}

// TestBuildMessageStripsFromAndRecipients covers the other two values
// that land in the header block. They come from configuration rather
// than from a request, but the guard belongs at the boundary either way
// - the header block should be safe by construction, not by trusting
// whoever populated the config.
func TestBuildMessageStripsFromAndRecipients(t *testing.T) {
	n := &Notifier{
		host:       "mail.example.invalid",
		port:       25,
		from:       "file-api@example.invalid\r\nBcc: attacker@evil.invalid",
		recipients: []string{"ops@example.invalid\r\nX-Injected: yes", "second@example.invalid"},
		enabled:    true,
	}

	msg := n.buildMessage("subject", "body")

	for _, line := range headerLines(t, msg) {
		if strings.HasPrefix(line, "Bcc:") || strings.HasPrefix(line, "X-Injected:") {
			t.Errorf("injected value became its own header line:\n%s", msg)
		}
	}
	// The legitimate second recipient must survive intact.
	if !strings.Contains(msg, "second@example.invalid") {
		t.Errorf("legitimate recipient was lost:\n%s", msg)
	}
}

// TestBuildMessageBodyCannotIntroduceHeaders pins why the body is not
// stripped: it sits after the separator, so even a body full of CRLF
// and header-shaped lines stays in the body. If the message layout ever
// changes so the body is no longer last, this fails.
func TestBuildMessageBodyCannotIntroduceHeaders(t *testing.T) {
	n := testNotifier()

	body := "File: photo.jpg\r\nBcc: attacker@evil.invalid\r\n\r\nmore text\n"
	msg := n.buildMessage("[file-api] alert", body)

	for _, line := range headerLines(t, msg) {
		if strings.HasPrefix(line, "Bcc:") {
			t.Errorf("body content reached the header block:\n%s", msg)
		}
	}
	// And the body must be preserved verbatim - stripping it would
	// mangle every multi-line alert this package sends.
	_, gotBody, _ := strings.Cut(msg, "\r\n\r\n")
	if gotBody != body {
		t.Errorf("body was altered:\ngot  %q\nwant %q", gotBody, body)
	}
}

// TestSendAlertBodyCannotSmuggleSMTPCommands is the load-bearing test
// for leaving the body unsanitized. A body containing a lone "." line
// would end DATA early and let everything after it be read as SMTP
// commands - if the transport did not dot-stuff. net/smtp does, so the
// smuggled commands stay inside the message.
//
// This guards our code, not the stdlib's: if SendAlert is ever changed
// to hand-roll the SMTP conversation, the assumption breaks and this
// test catches it.
func TestSendAlertBodyCannotSmuggleSMTPCommands(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	defer ln.Close()

	type capture struct {
		transactions int
		raw          string
	}
	done := make(chan capture, 1)

	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- capture{}
			return
		}
		defer c.Close()

		r := bufio.NewReader(c)
		w := bufio.NewWriter(c)
		say := func(s string) { w.WriteString(s + "\r\n"); w.Flush() }

		say("220 fake ESMTP")
		var raw strings.Builder
		cap := capture{}
		inData := false

		for {
			line, err := r.ReadString('\n')
			if err != nil {
				break
			}
			if inData {
				raw.WriteString(line)
				if line == ".\r\n" {
					say("250 OK")
					inData = false
				}
				continue
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				say("250-fake")
				say("250 OK")
			case strings.HasPrefix(cmd, "MAIL FROM"):
				cap.transactions++
				say("250 OK")
			case strings.HasPrefix(cmd, "DATA"):
				say("354 send it")
				inData = true
			case strings.HasPrefix(cmd, "QUIT"):
				say("221 bye")
				cap.raw = raw.String()
				done <- cap
				return
			default:
				say("250 OK")
			}
		}
		cap.raw = raw.String()
		done <- cap
	}()

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	n := &Notifier{
		host:       host,
		port:       p,
		from:       "file-api@example.invalid",
		recipients: []string{"ops@example.invalid"},
		enabled:    true,
	}

	// A malware name that tries to close DATA and open a new transaction.
	evil := "Trojan\r\n.\r\nMAIL FROM:<attacker@evil.invalid>\r\nRCPT TO:<victim@evil.invalid>\r\nDATA\r\nSmuggled\r\n.\r\n"
	if err := n.MalwareAlert("2026/1/photo.jpg", evil); err != nil {
		t.Fatalf("MalwareAlert: %v", err)
	}

	got := <-done
	if got.transactions != 1 {
		t.Errorf("expected exactly 1 SMTP transaction, got %d - body smuggled a command", got.transactions)
	}
	if !strings.Contains(got.raw, "..\r\n") {
		t.Errorf("expected the lone dot to be dot-stuffed, raw stream:\n%q", got.raw)
	}
}

func TestSendAlertDisabledIsNoOp(t *testing.T) {
	n := &Notifier{enabled: false}
	if err := n.SendAlert("subject", "body"); err != nil {
		t.Errorf("disabled notifier should not error, got %v", err)
	}
}
