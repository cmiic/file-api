package util

import (
	"fmt"
	"net"
	"syscall"
)

// blockedCIDRs are the address ranges the fetch handler must never connect to:
// everything IANA lists as special-purpose, plus the private and loopback space.
//
// A deny list of ranges rather than a handful of net.IP predicates, because the
// predicates do not cover the whole of it. IsPrivate, IsLoopback,
// IsLinkLocalUnicast and IsMulticast between them leave the benchmarking,
// documentation, reserved and "this network" ranges looking like ordinary
// public addresses - and a deployment that routes any of those internally would
// have them dialled. The claim this guard makes is "public unicast only", so
// the list has to match the claim.
//
// Two IPv6 entries are here for a subtler reason: 64:ff9b::/96 (NAT64) and
// 2002::/16 (6to4) embed an IPv4 address inside an IPv6 one. net.IP's
// predicates do not look inside, so 64:ff9b::7f00:1 - which is 127.0.0.1 - is
// not reported as loopback. Blocking the translation prefixes outright is
// simpler and safer than decoding them.
//
// ::ffff:0:0/96 is deliberately absent: net.IP.To4 returns a 4-byte form for
// IPv4-mapped addresses, so they are matched against the IPv4 list below and
// ::ffff:8.8.8.8 stays reachable while ::ffff:127.0.0.1 does not.
var blockedCIDRs = mustParseCIDRs([]string{
	// IPv4
	"0.0.0.0/8",       // "this network" (RFC 1122)
	"10.0.0.0/8",      // private (RFC 1918)
	"100.64.0.0/10",   // carrier-grade NAT (RFC 6598)
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local, includes 169.254.169.254 cloud metadata
	"172.16.0.0/12",   // private (RFC 1918)
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1 documentation
	"192.88.99.0/24",  // 6to4 relay anycast (deprecated)
	"192.168.0.0/16",  // private (RFC 1918)
	"198.18.0.0/15",   // benchmarking (RFC 2544)
	"198.51.100.0/24", // TEST-NET-2 documentation
	"203.0.113.0/24",  // TEST-NET-3 documentation
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved, includes 255.255.255.255 broadcast

	// IPv6
	"::/128",        // unspecified
	"::1/128",       // loopback
	"64:ff9b::/96",  // NAT64 - embeds IPv4, see above
	"100::/64",      // discard-only
	"2001:db8::/32", // documentation
	"2002::/16",     // 6to4 - embeds IPv4, see above
	"fc00::/7",      // unique local
	"fe80::/10",     // link-local
	"ff00::/8",      // multicast
})

func mustParseCIDRs(cidrs []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("util: bad CIDR in blockedCIDRs: " + c)
		}
		nets = append(nets, n)
	}
	return nets
}

// BlockedIP reports whether ip must not be dialled by the fetch handler.
//
// True for anything outside public unicast space, and for a nil address: an
// address that could not be determined is not one to connect to.
func BlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}

	// Match IPv4 and IPv4-mapped IPv6 against the IPv4 ranges, so
	// ::ffff:127.0.0.1 is treated as 127.0.0.1.
	probe := ip
	if v4 := ip.To4(); v4 != nil {
		probe = v4
	}

	for _, n := range blockedCIDRs {
		if n.Contains(probe) {
			return true
		}
	}

	// Backstop for anything the ranges above miss - interface-local multicast
	// has no CIDR of its own in the list, and this keeps the predicates and the
	// table agreeing.
	return !ip.IsGlobalUnicast() || ip.IsInterfaceLocalMulticast()
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
