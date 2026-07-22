// Package ssrfguard provides an SSRF-safe HTTP fetcher for services that must
// retrieve user- or webhook-supplied URLs — agents browsing links, webhook
// media downloads, URL preview/unfurl services, and similar.
//
// The load-bearing idea is to guard at the DIAL, on the RESOLVED connect IP,
// rather than validating a hostname or IP string before the request is made.
// A pre-request hostname check is fundamentally bypassable via DNS rebinding:
// a hostname can resolve to a public IP during validation and to a private IP
// (127.0.0.1, 169.254.169.254, 10.x, …) a moment later at connect time. By
// wiring [Control] into a [net.Dialer.Control] hook, every actual connection —
// including every redirect hop, which re-dials — is checked against the IP the
// socket is really about to connect to. There is no window to rebind into.
//
//	client := ssrfguard.NewClient()
//	body, err := ssrfguard.Fetch(ctx, client, userURL, 5<<20)
//
// See the package README for the full threat model.
package ssrfguard

import (
	"fmt"
	"net"
	"syscall"
)

// ErrBlockedIP is returned by [Control] and the guarded dialer when a
// connection is refused because its resolved IP is not publicly routable. It
// carries the offending IP so callers can log or classify the block.
type ErrBlockedIP struct {
	IP net.IP
}

func (e *ErrBlockedIP) Error() string {
	if e.IP == nil {
		return "ssrfguard: blocked dial to non-public address"
	}
	return fmt.Sprintf("ssrfguard: blocked dial to non-public address %s", e.IP)
}

// blockedV4 lists IPv4 ranges that must never be reached by a fetch of an
// untrusted URL. The set is intentionally explicit and auditable rather than
// delegated to stdlib helpers, so a reviewer can see exactly what is refused.
var blockedV4 = mustCIDRs(
	"0.0.0.0/8",       // "this host" / unspecified (RFC 1122)
	"10.0.0.0/8",      // RFC 1918 private
	"100.64.0.0/10",   // RFC 6598 carrier-grade NAT
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // RFC 3927 link-local — includes cloud metadata 169.254.169.254
	"172.16.0.0/12",   // RFC 1918 private
	"192.0.0.0/24",    // RFC 6890 IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1 documentation (RFC 5737)
	"192.168.0.0/16",  // RFC 1918 private
	"198.18.0.0/15",   // RFC 2544 benchmarking
	"198.51.100.0/24", // TEST-NET-2 documentation (RFC 5737)
	"203.0.113.0/24",  // TEST-NET-3 documentation (RFC 5737)
	"224.0.0.0/4",     // multicast (RFC 5771)
	"240.0.0.0/4",     // reserved; includes 255.255.255.255 broadcast
)

// blockedV6 lists IPv6 ranges that must never be reached. IPv4-mapped
// addresses (::ffff:a.b.c.d) are unwrapped to IPv4 before this list is
// consulted, and 6to4/Teredo embeddings are recursed into, so this covers
// native IPv6 space only.
var blockedV6 = mustCIDRs(
	"::/128",        // unspecified
	"::1/128",       // loopback
	"::ffff:0:0/96", // IPv4-mapped (defense in depth; normally unwrapped first)
	"64:ff9b::/96",  // NAT64 well-known prefix (RFC 6052) — embeds IPv4, treat as internal
	"100::/64",      // discard-only (RFC 6666)
	"2001:db8::/32", // documentation (RFC 3849)
	"fc00::/7",      // unique local addresses (RFC 4193): fc00::/8 + fd00::/8
	"fe80::/10",     // link-local unicast (RFC 4291)
	"ff00::/8",      // multicast (RFC 4291)
)

// IsPublicIP reports whether ip is a globally routable, publicly reachable
// address. It returns false for the unspecified address, loopback (v4 and v6),
// RFC 1918 private space, IPv4 link-local 169.254.0.0/16 (which covers the
// cloud metadata endpoint 169.254.169.254) and IPv6 fe80::/10, carrier-grade
// NAT 100.64.0.0/10, IPv6 unique-local fc00::/7, multicast, the broadcast
// address, documentation/TEST-NET and benchmarking ranges, and IPv4-mapped
// IPv6 addresses whose embedded IPv4 is itself non-public. 6to4 (2002::/16)
// and Teredo (2001:0::/32) addresses are unwrapped to their embedded IPv4 and
// re-checked, so a tunnel into private space is rejected too.
//
// A nil IP returns false.
func IsPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Prefer the 4-byte form when this is (or embeds) an IPv4 address. This
	// also unwraps IPv4-mapped IPv6 addresses such as ::ffff:10.0.0.1.
	if v4 := ip.To4(); v4 != nil {
		for _, block := range blockedV4 {
			if block.Contains(v4) {
				return false
			}
		}
		return true
	}

	ip16 := ip.To16()
	if ip16 == nil {
		return false
	}

	// 6to4 (2002::/16): bytes 2..5 hold an embedded IPv4 address. Reachability
	// of the 6to4 address follows the reachability of that IPv4.
	if ip16[0] == 0x20 && ip16[1] == 0x02 {
		return IsPublicIP(net.IPv4(ip16[2], ip16[3], ip16[4], ip16[5]))
	}

	// Teredo (2001:0000::/32): the client IPv4 is the last four bytes,
	// bitwise-inverted (RFC 4380).
	if ip16[0] == 0x20 && ip16[1] == 0x01 && ip16[2] == 0x00 && ip16[3] == 0x00 {
		return IsPublicIP(net.IPv4(
			ip16[12]^0xff, ip16[13]^0xff, ip16[14]^0xff, ip16[15]^0xff,
		))
	}

	for _, block := range blockedV6 {
		if block.Contains(ip16) {
			return false
		}
	}
	return true
}

// Control is a ready-made [net.Dialer.Control] hook that refuses any connection
// whose resolved address is not publicly routable, returning an [*ErrBlockedIP].
// Because Control runs after DNS resolution and immediately before connect, and
// because HTTP redirects re-dial, wiring this hook checks every real connection
// attempt against the IP the socket is actually about to reach — which is what
// defeats DNS rebinding.
//
//	dialer := &net.Dialer{Control: ssrfguard.Control}
//
// [NewClient] installs a configurable variant of this hook (honoring
// WithAllowPrivate / WithAllowCIDRs); use Control directly for a strict,
// dependency-free dialer.
func Control(network, address string, c syscall.RawConn) error {
	return checkDialAddr(address, false, nil)
}

// checkDialAddr parses a dialer "host:port" address and enforces the guard.
// allowPrivate short-circuits to allow (dev/test only); allowed is an explicit
// CIDR punch-through list consulted only for otherwise-blocked IPs.
func checkDialAddr(address string, allowPrivate bool, allowed []*net.IPNet) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("ssrfguard: cannot parse dial address %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// The Control hook receives an already-resolved IP literal. A
		// non-literal here means something upstream skipped resolution; refuse.
		return fmt.Errorf("ssrfguard: dial address host %q is not an IP literal", host)
	}
	if allowPrivate {
		return nil
	}
	if IsPublicIP(ip) {
		return nil
	}
	for _, n := range allowed {
		if n.Contains(ip) {
			return nil
		}
	}
	return &ErrBlockedIP{IP: ip}
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("ssrfguard: invalid CIDR " + s + ": " + err.Error())
	}
	return n
}

func mustCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, len(cidrs))
	for i, s := range cidrs {
		out[i] = mustCIDR(s)
	}
	return out
}
