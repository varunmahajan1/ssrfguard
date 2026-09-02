# ssrfguard

SSRF-safe HTTP fetching for Go. Guard at dial time on the resolved connect IP so a user- or tool-supplied URL cannot DNS-rebind onto `169.254.169.254`, loopback, or RFC1918 after a hostname check. Zero dependencies.

`http.Get` is unsafe for untrusted URLs: a hostname can resolve public during validation and private at connect. Agents, webhook downloaders, and unfurlers hit this every time they fetch a caller-chosen link.

## Install

```
go get github.com/varunmahajan1/ssrfguard
```

Requires Go 1.22+.

## Example

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/varunmahajan1/ssrfguard"
)

func main() {
	ctx := context.Background()
	client := ssrfguard.NewClient()

	body, err := ssrfguard.Fetch(ctx, client, "https://example.com", 5<<20)
	if err != nil {
		var blocked *ssrfguard.ErrBlockedIP
		switch {
		case errors.As(err, &blocked):
			log.Fatalf("blocked non-public address %s", blocked.IP)
		case errors.Is(err, ssrfguard.ErrScheme):
			log.Fatal("only http and https are allowed")
		case errors.Is(err, ssrfguard.ErrTooLarge):
			log.Fatal("response exceeded size cap")
		default:
			log.Fatal(err)
		}
	}
	fmt.Printf("got %d bytes\n", len(body))
}
```

`Get` is the same call on a default guarded client:

```go
body, err := ssrfguard.Get(ctx, userURL, 5<<20)
```

## What is blocked

The dialer refuses any connection whose resolved IP is not publicly routable:

- Cloud metadata and IPv4 link-local (`169.254.0.0/16`, including `169.254.169.254`)
- Loopback (`127.0.0.0/8`, `::1`)
- RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- CGNAT (`100.64.0.0/10`), IPv6 ULA (`fc00::/7`), IPv6 link-local (`fe80::/10`)
- Unspecified, multicast, broadcast, documentation/TEST-NET, and benchmarking ranges
- IPv4-mapped IPv6, 6to4, and Teredo addresses whose embedded IPv4 is itself non-public

`Fetch` and `Get` additionally allow only `http`/`https` (`ErrScheme`) and refuse oversize bodies rather than truncating (`ErrTooLarge`). Redirects re-dial, so a public first hop that 302s to a private IP is blocked on the next connect. The transport does not honor `HTTP(S)_PROXY`; a proxy would dial the proxy, not the target.

## What is still your job

ssrfguard decides **where** a socket may connect. It does not authenticate the request, sanitize the bytes, or decide which public hosts are legitimate. Auth headers, host allowlists (when the URL space is not actually arbitrary), TLS trust extras, and treating the body as untrusted input remain the caller’s. `Fetch`/`Get` take a `maxBytes` cap; if you use `NewClient` as a raw `*http.Client`, size limits are yours.

`WithAllowPrivate` turns the IP guard off. Use it only for tests and local development.

## How the guard works

`NewClient` installs a `net.Dialer.Control` hook that runs **after** DNS resolution and **immediately before** connect, on the IP the kernel is about to use. There is no second lookup and no TOCTOU window to rebind into. `ssrfguard.Control` is the strict, option-free form of that hook if you already have a dialer.

## API

```go
func NewClient(opts ...Option) *http.Client
func WithTimeout(d time.Duration) Option          // default 30s; non-positive ignored
func WithMaxRedirects(n int) Option               // default 5; 0 disables redirects
func WithAllowPrivate() Option                    // disables the IP guard
func WithAllowCIDRs(cidrs ...string) Option       // punch-through; invalid CIDR panics

func Fetch(ctx context.Context, client *http.Client, rawURL string, maxBytes int64) ([]byte, error)
func Get(ctx context.Context, rawURL string, maxBytes int64) ([]byte, error)

func IsPublicIP(ip net.IP) bool
func Control(network, address string, c syscall.RawConn) error
```

Typed errors: `*ErrBlockedIP` (`.IP`), `ErrScheme`, `ErrTooLarge`. They work with `errors.As` / `errors.Is`, including when wrapped in `*url.Error` from a redirect.

## Tests

```
go test ./...
```

## License

MIT
