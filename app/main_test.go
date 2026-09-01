package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestLoggingMiddlewareCannotForgeLogLines is the regression test for log
// forging through the request logger.
//
// r.URL.Path is percent-decoded, so "%0a" in a request target arrives here as
// a real newline - the same property that let "%2e%2e%2f" past the mux in the
// /meta/files/ traversal. Logged with %s, one unauthenticated GET could append
// a line indistinguishable from a genuine one:
//
//	2026/09/01 18:00:19 GET /files/x
//	2026/09/01 16:00:00 ADMIN LOGIN SUCCESS from 127.0.0.1 10.0.0.1:1234
//
// %q escapes it into the single quoted field it belongs in.
func TestLoggingMiddlewareCannotForgeLogLines(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(nil)
		log.SetFlags(log.LstdFlags)
	})

	handler := loggingMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	const forged = "ADMIN LOGIN SUCCESS from 127.0.0.1"
	target := "/files/x%0a2026/09/01%2016:00:00%20" + strings.ReplaceAll(forged, " ", "%20")

	req := httptest.NewRequest(http.MethodGet, target, nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	out := buf.String()

	// The decoded newline must not survive as a line break: everything the
	// middleware writes for one request has to stay on one line.
	if got := strings.Count(strings.TrimSuffix(out, "\n"), "\n"); got != 0 {
		t.Errorf("one request produced %d extra log line(s):\n%s", got, out)
	}
	// And no line may begin with the attacker's text, which is what makes a
	// forged entry look genuine.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "2026/") && strings.Contains(line, forged) {
			t.Errorf("forged line reached the log as its own entry:\n%s", out)
		}
	}
	// The path is still recorded - escaped, not dropped.
	if !strings.Contains(out, `\n`) || !strings.Contains(out, "/files/x") {
		t.Errorf("expected the path to be logged with the newline escaped, got:\n%s", out)
	}
}
