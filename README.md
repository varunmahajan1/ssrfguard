# ssrfguard

An SSRF-safe HTTP fetcher for Go services that must retrieve **user- or webhook-supplied URLs** — agents browsing links a user pasted, webhook handlers downloading media, URL preview/unfurl cards, image proxies. Zero dependencies, standard library only.

The one idea that makes it safe: **guard at the dial, on the resolved connect IP.** Not the hostname. Not the URL string. The actual IP the socket is about to connect to, checked by a [`net.Dialer.Control`](https://pkg.go.dev/net#Dialer.Control) hook the moment before connect — and re-checked on every redirect hop, because each hop re-dials.

```go
client := ssrfguard.NewClient()
body, err := ssrfguard.Fetch(ctx, client, userURL, 5<<20) // 5 MiB cap
```

That's it. `userURL` can be anything an attacker types; the fetch cannot be steered onto `169.254.169.254`, `127.0.0.1:6379`, or your `10.x` service mesh.

---

## The threat: Server-Side Request Forgery

When your server fetches a URL that an untrusted party controls, the attacker gets to point *your server's network position* at a target of their choosing. From the public internet they can't reach your cloud metadata endpoint or your internal admin ports — but your server can, and now they're driving it.

The classic targets:

- **Cloud metadata** — `http://169.254.169.254/latest/meta-data/iam/security-credentials/`. On unpatched IMDSv1 this hands back temporary IAM credentials. This single IP is the most valuable SSRF target in existence.
- **Loopback admin surfaces** — `http://127.0.0.1:6379` (Redis), `:9200` (Elasticsearch), `:2375` (Docker), Kubernetes kubelet, unauthenticated dashboards that trust "it came from localhost."
- **Private ranges** — `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`: internal APIs, databases, service meshes that assume the network perimeter is the auth boundary.
- **Link-local, CGNAT, ULA** — `169.254/16`, `100.64/10`, `fc00::/7` and friends.

A production AI assistant I run fetches links, downloads webhook media, and unfurls URLs on behalf of users all day. Every one of those is an untrusted URL reaching outward from trusted network real estate. This library is the chokepoint that makes that safe.

---

## Why dial-time, resolved-IP guarding — and not a hostname check

The intuitive fix is to validate the URL before you fetch it: parse the host, resolve it, reject it if it's private. **This is bypassable, and the bypass is easy.** It's called DNS rebinding.

```
                    ATTACKER CONTROLS THE DNS FOR evil.example.com
                    with a ~0s TTL, and flips the answer between calls.

   your code                    DNS for evil.example.com
   ─────────                    ────────────────────────
   1. resolve("evil.example.com")  ──►  "it's 93.184.216.34"   (a public IP)
   2. IsPublic(93.184.216.34)? ✅ yes — validation PASSES
                                         ┌──────────────────────────────┐
                                         │  attacker flips the DNS record │
                                         └──────────────────────────────┘
   3. http.Get resolves AGAIN   ──►  "it's 169.254.169.254"  (metadata!)
   4. connect ───────────────────────►  169.254.169.254  ☠  credentials leaked
```

The check in step 2 and the connect in step 4 resolve the name **twice**, and the attacker changes the answer in between. Your pre-flight validation looked at a different IP than the one you actually connected to. This is a TOCTOU (time-of-check to time-of-use) hole, and no amount of hostname parsing closes it — the hostname was never the problem.

**The fix is to move the check to the use.** A `net.Dialer.Control` hook runs *after* the resolver has produced the concrete IP and *immediately before* the kernel connects the socket — on the exact IP bytes about to be used. There is no second resolution, so there is no window to rebind into:

```
   your code
   ─────────
   http.Get("http://evil.example.com/…")
        │
        ▼  net/http resolves the name → 169.254.169.254
        │
        ▼  Dialer.Control("tcp", "169.254.169.254:80", conn)  ◄── ssrfguard.Control
        │        IsPublicIP(169.254.169.254)? ❌  → return ErrBlockedIP
        │
        ✗  connection refused before a single packet leaves the box
```

Whatever the hostname resolved to, *that* is what gets checked. Blocklists of hostnames and IP strings are advisory at best; the `Control` hook is load-bearing.

And because **HTTP redirects re-dial**, the hook fires again on every hop automatically. A public URL that 302-redirects to `http://169.254.169.254/` is caught on the redirect's dial — you get this for free, no redirect-parsing code of your own.

---

## Why reject oversize bodies instead of truncating

`Fetch` caps the response size and, when the body is too big, **returns `ErrTooLarge` rather than handing you the first N bytes.** That's a deliberate safety choice.

A truncated download is silently corrupt data. Cut a JSON document at a byte boundary and it won't parse — or worse, it parses into something subtly wrong. Cut an image and a thumbnailer downstream chokes or renders garbage. The corruption surfaces far from the fetch, in code that has no idea the bytes were truncated, and someone burns an afternoon tracing it back. A refused fetch fails *here*, loudly, with a clear error, at the one place that knows why.

The cap is enforced two ways: the `Content-Length` header is checked first to reject early when the server is honest, and the body is read through an `io.LimitReader` set to `maxBytes+1` so a lying or absent length (including chunked responses) is still caught — if that one extra byte materializes, the body was over the limit.

---

## Quickstart

```go
package main

import (
    "context"
    "errors"
    "fmt"

    "github.com/varunmahajan1/ssrfguard"
)

func main() {
    ctx := context.Background()

    // One-liner with the default guarded client.
    body, err := ssrfguard.Get(ctx, "https://example.com/robots.txt", 1<<20)
    if err != nil {
        var blocked *ssrfguard.ErrBlockedIP
        switch {
        case errors.As(err, &blocked):
            fmt.Println("refused non-public address:", blocked.IP)
        case errors.Is(err, ssrfguard.ErrScheme):
            fmt.Println("only http/https allowed")
        case errors.Is(err, ssrfguard.ErrTooLarge):
            fmt.Println("response too large")
        default:
            fmt.Println("fetch failed:", err)
        }
        return
    }
    fmt.Printf("got %d bytes\n", len(body))
}
```

Install:

```
go get github.com/varunmahajan1/ssrfguard
```

---

## API

### `IsPublicIP(ip net.IP) bool`

Reports whether an IP is globally routable and publicly reachable. Returns `false` for the unspecified address, loopback (v4 + v6), RFC 1918 private space, IPv4 link-local `169.254.0.0/16` (which covers cloud metadata `169.254.169.254`) and IPv6 `fe80::/10`, CGNAT `100.64.0.0/10`, IPv6 ULA `fc00::/7`, multicast, broadcast `255.255.255.255`, the documentation/TEST-NET ranges, and benchmarking `198.18.0.0/15`. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is unwrapped and re-checked; 6to4 and Teredo addresses are unwrapped to their embedded IPv4 and re-checked, so a tunnel into private space is rejected too.

### `Control(network, address string, c syscall.RawConn) error`

A ready-made `net.Dialer.Control` hook — the load-bearing guard. Rejects any connection whose resolved address isn't public with a typed `*ErrBlockedIP`. Use it directly for a strict, dependency-free dialer:

```go
dialer := &net.Dialer{Control: ssrfguard.Control}
```

### `NewClient(opts ...Option) *http.Client`

An `*http.Client` with the guarded dialer, conservative timeouts, and a redirect cap (default 5). Each redirect hop re-dials, so the `Control` hook re-checks every hop. The transport deliberately does **not** honor `HTTP(S)_PROXY` env vars — a proxy would dial the proxy instead of the target and slip past the guard.

| Option | Effect |
| --- | --- |
| `WithTimeout(d)` | Overall per-request timeout (default 30s). |
| `WithMaxRedirects(n)` | Cap redirect hops (default 5; `0` disables redirects). |
| `WithAllowPrivate()` | **Disables the guard.** Tests / local dev only. |
| `WithAllowCIDRs(...string)` | Allowlist punch-through for CIDRs you trust — e.g. one internal service. Only widens access; invalid CIDR panics at construction. |

### `Fetch(ctx, client, url string, maxBytes int64) ([]byte, error)`

Guarded GET with a scheme allowlist (`http`/`https` only → `ErrScheme`) and a reject-not-truncate size cap (`ErrTooLarge`). Honors context cancellation.

### `Get(ctx, url string, maxBytes int64) ([]byte, error)`

Convenience wrapper over `Fetch` using a default guarded client.

**Typed errors:** `*ErrBlockedIP` (carries `.IP`), `ErrScheme`, `ErrTooLarge`. All work with `errors.Is` / `errors.As`, including when wrapped inside a `*url.Error` from a redirect.

---

## What this is not

- **Not a URL allowlister.** If you know the exact hosts you'll ever fetch, an allowlist is stronger — use one. ssrfguard is for the case where the URL is genuinely arbitrary.
- **Not a WAF or output sanitizer.** It controls *where you connect*, not what you do with the bytes. Treat fetched content as untrusted.
- **Not a proxy.** It fetches directly and intentionally ignores proxy env vars.

---

## Related projects

ssrfguard pairs naturally with **[promptshield](https://github.com/varunmahajan1/promptshield)**: promptshield guards what goes *into* your agent; ssrfguard guards where your agent is allowed to *reach*.

Part of a small family of production-hardened Go building blocks:

- [llm-meter](https://github.com/varunmahajan1/llm-meter) — token accounting and cost metering for LLM calls
- [agent-runtime](https://github.com/varunmahajan1/agent-runtime) — a runtime harness for tool-using agents
- [agent-stream](https://github.com/varunmahajan1/agent-stream) — streaming primitives for agent output
- [promptshield](https://github.com/varunmahajan1/promptshield) — prompt-injection and input guarding
- [llm-failover](https://github.com/varunmahajan1/llm-failover) — provider failover and retry for LLM APIs
- [timeanchor](https://github.com/varunmahajan1/timeanchor) — time grounding and timezone-correct scheduling
- [channelfmt](https://github.com/varunmahajan1/channelfmt) — message formatting across chat channels

## License

MIT © 2026 Varun Mahajan
