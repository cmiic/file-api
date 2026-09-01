package handler

import (
	"net/http"
	"testing"
)

// TestFetchClientIgnoresEnvironmentProxy pins the reason transport.Proxy is
// nil. DefaultTransport honours HTTP_PROXY and HTTPS_PROXY, and a proxy would
// reopen the SSRF this handler's dial guard exists to close: every request
// would dial the proxy, the guard would approve the proxy's public address,
// and the proxy would then resolve and connect to whatever the caller asked
// for. Restoring the default transport, or dropping this assignment, must fail
// here rather than in production.
func TestFetchClientIgnoresEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.invalid:3128")
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:3128")

	h := NewFetchHandler(nil, 1<<20, "test-secret")

	transport, ok := h.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected an *http.Transport, got %T", h.httpClient.Transport)
	}
	if transport.Proxy != nil {
		t.Error("fetch transport must not honour an environment proxy: a proxy dials the target itself, past the dial guard")
	}
	if transport.DialContext == nil {
		t.Error("fetch transport must install the guarded dialer")
	}
}
