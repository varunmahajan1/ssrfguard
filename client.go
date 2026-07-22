package ssrfguard

import (
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// Default tuning for the guarded client. Kept conservative: an untrusted URL
// fetch should not be allowed to tie up a connection indefinitely.
const (
	defaultTimeout        = 30 * time.Second
	defaultMaxRedirects   = 5
	dialTimeout           = 10 * time.Second
	dialKeepAlive         = 30 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	responseHeaderTimeout = 15 * time.Second
	expectContinueTimeout = 1 * time.Second
	idleConnTimeout       = 90 * time.Second
	maxIdleConns          = 100
)

type config struct {
	timeout      time.Duration
	maxRedirects int
	allowPrivate bool
	allowedCIDRs []*net.IPNet
}

// Option configures a client built by [NewClient].
type Option func(*config)

// WithTimeout sets the overall per-request timeout (dial through body read).
// A non-positive value is ignored and the default is kept.
func WithTimeout(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithMaxRedirects caps how many redirects the client will follow. Every hop
// re-dials, so the guard re-checks each one; this cap bounds the chain length.
// A negative value is ignored (the default is kept); zero disables redirects.
func WithMaxRedirects(n int) Option {
	return func(c *config) {
		if n >= 0 {
			c.maxRedirects = n
		}
	}
}

// WithAllowPrivate disables the guard entirely, permitting connections to
// private, loopback, and link-local addresses. Intended for tests and local
// development only. Never enable it for a client that fetches untrusted URLs.
func WithAllowPrivate() Option {
	return func(c *config) {
		c.allowPrivate = true
	}
}

// WithAllowCIDRs punches explicit holes in the guard for CIDRs you deliberately
// trust — for example an internal service the fetcher is allowed to reach. Only
// addresses that would otherwise be blocked are consulted against this list, so
// it can only widen access, never narrow it.
//
// Each argument must be a valid CIDR; an invalid one panics at construction,
// since it is static configuration and a silent skip would fail open on intent.
func WithAllowCIDRs(cidrs ...string) Option {
	nets := make([]*net.IPNet, len(cidrs))
	for i, s := range cidrs {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			panic(fmt.Sprintf("ssrfguard: WithAllowCIDRs: invalid CIDR %q: %v", s, err))
		}
		nets[i] = n
	}
	return func(c *config) {
		c.allowedCIDRs = append(c.allowedCIDRs, nets...)
	}
}

// control builds the dialer Control hook for this configuration.
func (c *config) control() func(network, address string, rc syscall.RawConn) error {
	allowPrivate := c.allowPrivate
	allowed := c.allowedCIDRs
	return func(network, address string, rc syscall.RawConn) error {
		return checkDialAddr(address, allowPrivate, allowed)
	}
}

// NewClient returns an [*http.Client] whose dialer refuses to connect to any
// non-public IP, with sane timeouts and a bounded redirect policy. The guard is
// enforced by a [net.Dialer.Control] hook on the resolved connect IP, so DNS
// rebinding cannot slip a private address past it — and because each redirect
// hop re-dials, the hook re-checks every hop automatically.
//
// The transport does not honor HTTP(S)_PROXY environment variables: routing
// through a proxy would dial the proxy rather than the target, bypassing the
// guard. If you need a proxy, wrap this at a layer that is itself trusted.
func NewClient(opts ...Option) *http.Client {
	cfg := &config{
		timeout:      defaultTimeout,
		maxRedirects: defaultMaxRedirects,
	}
	for _, o := range opts {
		o(cfg)
	}

	dialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: dialKeepAlive,
		Control:   cfg.control(),
	}

	transport := &http.Transport{
		// No Proxy: see NewClient doc — a proxy would bypass the dial guard.
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          maxIdleConns,
		IdleConnTimeout:       idleConnTimeout,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
		ExpectContinueTimeout: expectContinueTimeout,
	}

	maxRedirects := cfg.maxRedirects
	return &http.Client{
		Timeout:   cfg.timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("ssrfguard: stopped after %d redirects", maxRedirects)
			}
			return nil
		},
	}
}
