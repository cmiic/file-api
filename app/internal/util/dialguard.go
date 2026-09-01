package util

import (
	"fmt"
	"net"
	"syscall"
)

// BlockedIP reports whether ip must not be dialled by the fetch handler.
//
// It rejects everything that is not a routable public unicast address:
// loopback, RFC1918 and ULA private ranges, the unspecified address, link-local
// (which covers the 169.254.169.254 cloud metadata endpoint), multicast, and
// carrier-grade NAT.
//
// The IPv4-in-IPv6 forms are handled by the standard library: net.IP's
// predicates operate on the 4-byte form when one exists, so ::ffff:127.0.0.1
// is reported as loopback.
func BlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}
	// 100.64.0.0/10, carrier-grade NAT. net.IP has no predicate for it.
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return true
	}
	return false
}

// SafeDialControl is a net.Dialer Control function that refuses connections to
// non-public addresses. Install it on the transport used to fetch caller-
// supplied URLs.
//
// This is the security boundary for SSRF, not IsValidURL. Control runs once per
// dial attempt, after the name has been resolved, so it sees the address the
// kernel is about to connect to rather than the text the caller supplied. That
// closes three classes of hole a string check cannot:
//
//   - hostnames that resolve to internal addresses, including ones whose text
//     gives no hint ("localtest.me", "metadata.google.internal");
//   - alternative spellings of an address that net.ParseIP does not accept but
//     the resolver does - "127.1", "2130706433", "0177.0.0.1", "LOCALHOST",
//     "localhost." - each of which reached loopback past the old string check;
//   - DNS rebinding, where the name resolves to a public address while it is
//     being validated and to a private one when it is dialled.
//
// Redirects need no special handling: every hop dials, and every dial is
// checked.
func SafeDialControl(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("cannot parse dial address %q: %w", address, err)
	}

	// Control is called with a resolved address, so this is the literal IP
	// being connected to. A parse failure here means an assumption broke;
	// refuse rather than let it through.
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("refusing to dial unresolved address %q", address)
	}

	if BlockedIP(ip) {
		return fmt.Errorf("refusing to dial non-public address %s", ip)
	}
	return nil
}
