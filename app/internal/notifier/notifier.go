// Package notifier provides email notification functionality.
package notifier

import (
	"fmt"
	"log"
	"net/smtp"
	"strings"
)

// Notifier sends email alerts via SMTP.
type Notifier struct {
	host       string
	port       int
	from       string
	recipients []string
	enabled    bool
}

// NewNotifier creates a new email notifier.
// If host or recipients are empty, notifications are disabled.
func NewNotifier(host string, port int, from, alertEmails string) *Notifier {
	var recipients []string
	if alertEmails != "" {
		for _, email := range strings.Split(alertEmails, ",") {
			email = strings.TrimSpace(email)
			if email != "" {
				recipients = append(recipients, email)
			}
		}
	}

	enabled := host != "" && len(recipients) > 0

	if !enabled {
		log.Println("Email notifications disabled (SMTP_HOST or ALERT_EMAILS not configured)")
	} else {
		log.Printf("Email notifications enabled: %s:%d -> %v", host, port, recipients)
	}

	return &Notifier{
		host:       host,
		port:       port,
		from:       from,
		recipients: recipients,
		enabled:    enabled,
	}
}

// Enabled returns true if email notifications are configured.
func (n *Notifier) Enabled() bool {
	return n.enabled
}

// headerStripper removes the CR and LF bytes that would let a value
// close its header line and inject headers of its own.
var headerStripper = strings.NewReplacer("\r", " ", "\n", " ")

// SendAlert sends an email alert with the given subject and body.
// Does nothing if notifications are disabled.
//
// Every value that lands in the header block - subject, From, To - is
// stripped of CR/LF here rather than at the call sites. The alert
// helpers below currently pass a constant subject, but they also embed
// fields the scanner services return (malware name, NSFW classes, and
// the error text ScanErrorAlert takes, which wraps remote response
// bodies), and this package cannot see what a future caller will hand
// it. The boundary enforces the invariant so callers do not have to.
//
// The body is deliberately left alone: it is legitimately multi-line,
// it sits after the header separator so it cannot introduce a header,
// and the SMTP transport dot-stuffs it so it cannot end DATA early.
// TestSendAlertBodyCannotSmuggleSMTPCommands pins that last assumption.
func (n *Notifier) SendAlert(subject, body string) error {
	if !n.enabled {
		return nil
	}

	addr := fmt.Sprintf("%s:%d", n.host, n.port)
	safeSubject := headerStripper.Replace(subject)
	msg := n.buildMessage(subject, body)

	// Send without auth (internal mail gateway)
	err := smtp.SendMail(addr, nil, n.from, n.recipients, []byte(msg))
	if err != nil {
		log.Printf("Failed to send alert email: %v", err)
		return fmt.Errorf("smtp send failed: %w", err)
	}

	// Log the stripped subject: CR/LF here would forge log lines just as
	// it would forge headers.
	log.Printf("Alert email sent: %s", safeSubject)
	return nil
}

// buildMessage assembles the RFC 5322 message. Split out from SendAlert
// so the header construction is testable without an SMTP server.
func (n *Notifier) buildMessage(subject, body string) string {
	recipients := make([]string, len(n.recipients))
	for i, addr := range n.recipients {
		recipients[i] = headerStripper.Replace(addr)
	}

	return fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/plain; charset=\"utf-8\"\r\n"+
		"\r\n"+
		"%s",
		headerStripper.Replace(n.from),
		strings.Join(recipients, ", "),
		headerStripper.Replace(subject),
		body,
	)
}

// Alerts identify a file by its content hash, never by its path.
//
// The stored path embeds the uploader's own filename - sanitised, but still
// theirs - and these alerts go to operators. For a cli/ upload that filename
// can carry client information the operator has no business receiving, so it
// stays out of the message. The SHA1 locates the file just as well, is unique
// per stored file because it is what deduplication keys on, and is derived
// from content rather than supplied by anyone.
const locateHint = "Locate it by hash:\n" +
	"  find $BASE_PATH -name '*%s*'\n\n" +
	"The filename is omitted deliberately: it comes from the uploader and may\n" +
	"carry client information.\n"

// MalwareAlert sends an alert about a malware detection.
func (n *Notifier) MalwareAlert(sha1, scope, malwareName string) error {
	subject := "[file-api] Malware detected and removed"
	body := fmt.Sprintf("Malware detected in uploaded file.\n\n"+
		"SHA1: %s\n"+
		"Scope: %s\n"+
		"Malware: %s\n"+
		"Action: File deleted, metadata preserved\n\n"+
		locateHint,
		sha1,
		scope,
		malwareName,
		sha1,
	)
	return n.SendAlert(subject, body)
}

// NSFWAlert sends an alert about NSFW content detection.
func (n *Notifier) NSFWAlert(sha1, scope string, confidence float64, classes []string) error {
	subject := "[file-api] NSFW content detected"
	body := fmt.Sprintf("NSFW content detected in uploaded file.\n\n"+
		"SHA1: %s\n"+
		"Scope: %s\n"+
		"Confidence: %.2f\n"+
		"Classes: %s\n"+
		"Action: File flagged for review\n\n"+
		locateHint,
		sha1,
		scope,
		confidence,
		strings.Join(classes, ", "),
		sha1,
	)
	return n.SendAlert(subject, body)
}

// ScanErrorAlert sends an alert about a scan failure.
func (n *Notifier) ScanErrorAlert(sha1, scope, scanType, errorMsg string) error {
	subject := fmt.Sprintf("[file-api] %s scan failed", scanType)
	body := fmt.Sprintf("Scan failed for uploaded file.\n\n"+
		"SHA1: %s\n"+
		"Scope: %s\n"+
		"Scan type: %s\n"+
		"Error: %s\n"+
		"Action: Queued for retry\n\n"+
		locateHint,
		sha1,
		scope,
		scanType,
		errorMsg,
		sha1,
	)
	return n.SendAlert(subject, body)
}
