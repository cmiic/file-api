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

// SendAlert sends an email alert with the given subject and body.
// Does nothing if notifications are disabled.
func (n *Notifier) SendAlert(subject, body string) error {
	if !n.enabled {
		return nil
	}

	addr := fmt.Sprintf("%s:%d", n.host, n.port)

	// Build email message
	msg := fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/plain; charset=\"utf-8\"\r\n"+
		"\r\n"+
		"%s",
		n.from,
		strings.Join(n.recipients, ", "),
		subject,
		body,
	)

	// Send without auth (internal mail gateway)
	err := smtp.SendMail(addr, nil, n.from, n.recipients, []byte(msg))
	if err != nil {
		log.Printf("Failed to send alert email: %v", err)
		return fmt.Errorf("smtp send failed: %w", err)
	}

	log.Printf("Alert email sent: %s", subject)
	return nil
}

// MalwareAlert sends an alert about a malware detection.
func (n *Notifier) MalwareAlert(relativePath, malwareName string) error {
	subject := "[file-api] Malware detected and removed"
	body := fmt.Sprintf("Malware detected in uploaded file.\n\n"+
		"File: %s\n"+
		"Malware: %s\n"+
		"Action: File deleted, metadata preserved\n",
		relativePath,
		malwareName,
	)
	return n.SendAlert(subject, body)
}

// NSFWAlert sends an alert about NSFW content detection.
func (n *Notifier) NSFWAlert(relativePath string, confidence float64, classes []string) error {
	subject := "[file-api] NSFW content detected"
	body := fmt.Sprintf("NSFW content detected in uploaded file.\n\n"+
		"File: %s\n"+
		"Confidence: %.2f\n"+
		"Classes: %s\n"+
		"Action: File flagged for review\n",
		relativePath,
		confidence,
		strings.Join(classes, ", "),
	)
	return n.SendAlert(subject, body)
}

// ScanErrorAlert sends an alert about a scan failure.
func (n *Notifier) ScanErrorAlert(relativePath, scanType, errorMsg string) error {
	subject := fmt.Sprintf("[file-api] %s scan failed", scanType)
	body := fmt.Sprintf("Scan failed for uploaded file.\n\n"+
		"File: %s\n"+
		"Scan type: %s\n"+
		"Error: %s\n"+
		"Action: Queued for retry\n",
		relativePath,
		scanType,
		errorMsg,
	)
	return n.SendAlert(subject, body)
}
