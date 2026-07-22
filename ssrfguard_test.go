package ssrfguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsPublicIP(t *testing.T) {
	cases := []struct {
		ip     string
		public bool
	}{
		// Public — must pass.
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"93.184.216.34", true},
		{"172.32.0.1", true},           // just outside 172.16/12
		{"100.128.0.1", true},          // just outside CGNAT 100.64/10
		{"2606:4700:4700::1111", true}, // Cloudflare DNS (public v6)
		{"2001:4860:4860::8888", true}, // Google DNS (public v6)
		{"::ffff:8.8.8.8", true},       // v4-mapped public
		{"2002:0808:0808::", true},     // 6to4 embedding 8.8.8.8 (public)

		// Cloud metadata + link-local.
		{"169.254.169.254", false}, // AWS/GCP/Azure metadata endpoint
		{"169.254.0.1", false},
		{"fe80::1", false},

		// RFC 1918 private.
		{"10.0.0.1", false},
		{"10.255.255.255", false},
		{"172.16.0.1", false},
		{"172.31.255.255", false},
		{"192.168.1.1", false},

		// Loopback + unspecified.
		{"127.0.0.1", false},
		{"127.10.20.30", false},
		{"0.0.0.0", false},
		{"::1", false},
		{"::", false},

		// IPv6 ULA.
		{"fc00::1", false},
		{"fd12:3456:789a::1", false},

		// CGNAT.
		{"100.64.0.1", false},
		{"100.127.255.255", false},

		// v4-mapped private.
		{"::ffff:10.0.0.1", false},
		{"::ffff:127.0.0.1", false},
		{"::ffff:169.254.169.254", false},

		// Documentation / TEST-NET / benchmarking.
		{"192.0.2.1", false},
		{"198.51.100.1", false},
		{"203.0.113.1", false},
		{"198.18.0.1", false},
		{"2001:db8::1", false},

		// Multicast + broadcast.
		{"224.0.0.1", false},
		{"239.255.255.250", false},
		{"255.255.255.255", false},
		{"ff02::1", false},

		// Tunnels into private space (nice-to-have).
		{"2002:0a00:0001::", false},                        // 6to4 embedding 10.0.0.1
		{"2001:0000:4136:e378:8000:63bf:3fff:fdd2", false}, // Teredo; client IPv4 inverts to 192.0.2.45 (TEST-NET)
	}

	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("test bug: could not parse %q", tc.ip)
		}
		if got := IsPublicIP(ip); got != tc.public {
			t.Errorf("IsPublicIP(%s) = %v, want %v", tc.ip, got, tc.public)
		}
	}

	if IsPublicIP(nil) {
		t.Error("IsPublicIP(nil) = true, want false")
	}
}

func TestControl(t *testing.T) {
	cases := []struct {
		address string
		blocked bool
	}{
		{"8.8.8.8:443", false},
		{"[2606:4700:4700::1111]:443", false},
		{"127.0.0.1:80", true},
		{"169.254.169.254:80", true},
		{"10.0.0.5:8080", true},
		{"[::1]:80", true},
		{"[fc00::1]:443", true},
	}

	for _, tc := range cases {
		err := Control("tcp", tc.address, nil)
		if tc.blocked {
			var blocked *ErrBlockedIP
			if !errors.As(err, &blocked) {
				t.Errorf("Control(%q) = %v, want *ErrBlockedIP", tc.address, err)
			}
		} else if err != nil {
			t.Errorf("Control(%q) = %v, want nil", tc.address, err)
		}
	}
}

func TestControlRejectsNonLiteralHost(t *testing.T) {
	// The Control hook must never see an unresolved hostname; if it does, refuse.
	if err := Control("tcp", "example.com:80", nil); err == nil {
		t.Error("Control with hostname = nil, want error")
	}
}

func TestFetchScheme(t *testing.T) {
	ctx := context.Background()
	client := NewClient(WithAllowPrivate())
	for _, raw := range []string{
		"file:///etc/passwd",
		"ftp://example.com/x",
		"gopher://example.com/",
		"data:text/plain,hello",
	} {
		_, err := Fetch(ctx, client, raw, 1<<20)
		if !errors.Is(err, ErrScheme) {
			t.Errorf("Fetch(%q) error = %v, want ErrScheme", raw, err)
		}
	}
}

func TestFetchLocalhostBlockedByDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("secret"))
	}))
	defer srv.Close()

	// Default client: httptest listens on 127.0.0.1, which must be refused.
	_, err := Fetch(context.Background(), NewClient(), srv.URL, 1<<20)
	var blocked *ErrBlockedIP
	if !errors.As(err, &blocked) {
		t.Fatalf("Fetch(localhost) error = %v, want *ErrBlockedIP", err)
	}
}

func TestFetchLocalhostAllowedWithOption(t *testing.T) {
	want := "hello world"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(want))
	}))
	defer srv.Close()

	client := NewClient(WithAllowPrivate())
	body, err := Fetch(context.Background(), client, srv.URL, 1<<20)
	if err != nil {
		t.Fatalf("Fetch = %v, want nil", err)
	}
	if string(body) != want {
		t.Errorf("body = %q, want %q", body, want)
	}
}

func TestFetchLocalhostAllowedWithCIDR(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// Punch through only the loopback range, leaving the rest of the guard on.
	client := NewClient(WithAllowCIDRs("127.0.0.0/8", "::1/128"))
	if _, err := Fetch(context.Background(), client, srv.URL, 1<<20); err != nil {
		t.Fatalf("Fetch with allowed CIDR = %v, want nil", err)
	}
}

func TestFetchSizeCapContentLength(t *testing.T) {
	// Handler writes the full body so net/http sets Content-Length.
	makeServer := func(size int) *httptest.Server {
		body := bytes.Repeat([]byte("a"), size)
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(body)
		}))
	}

	client := NewClient(WithAllowPrivate())
	ctx := context.Background()

	// Exactly at the boundary: accepted.
	srv := makeServer(100)
	body, err := Fetch(ctx, client, srv.URL, 100)
	srv.Close()
	if err != nil {
		t.Fatalf("Fetch at boundary = %v, want nil", err)
	}
	if len(body) != 100 {
		t.Errorf("boundary body len = %d, want 100", len(body))
	}

	// One byte over: rejected, not truncated.
	srv = makeServer(101)
	_, err = Fetch(ctx, client, srv.URL, 100)
	srv.Close()
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("Fetch over boundary = %v, want ErrTooLarge", err)
	}
}

func TestFetchSizeCapChunked(t *testing.T) {
	// Flushing before finishing forces chunked encoding, so the client sees
	// ContentLength == -1 and the LimitReader path (not the header check) must
	// catch the oversize body.
	makeServer := func(size int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fl, ok := w.(http.Flusher)
			if !ok {
				t.Error("ResponseWriter is not a Flusher")
				return
			}
			chunk := bytes.Repeat([]byte("b"), 10)
			written := 0
			for written < size {
				n := 10
				if size-written < n {
					n = size - written
				}
				_, _ = w.Write(chunk[:n])
				fl.Flush()
				written += n
			}
		}))
	}

	client := NewClient(WithAllowPrivate())
	ctx := context.Background()

	srv := makeServer(100)
	body, err := Fetch(ctx, client, srv.URL, 100)
	srv.Close()
	if err != nil {
		t.Fatalf("chunked Fetch at boundary = %v, want nil", err)
	}
	if len(body) != 100 {
		t.Errorf("chunked boundary body len = %d, want 100", len(body))
	}

	srv = makeServer(101)
	_, err = Fetch(ctx, client, srv.URL, 100)
	srv.Close()
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("chunked Fetch over boundary = %v, want ErrTooLarge", err)
	}
}

func TestFetchRedirectToBlockedIsStopped(t *testing.T) {
	// The first hop is on loopback (allowed via CIDR punch-through) and issues a
	// redirect to the cloud metadata IP, which is NOT in the allowlist and not
	// public. The redirect re-dials, so the Control hook must block it — proving
	// every hop is re-checked.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	client := NewClient(WithAllowCIDRs("127.0.0.0/8", "::1/128"))
	_, err := Fetch(context.Background(), client, srv.URL, 1<<20)
	if err == nil {
		t.Fatal("Fetch following redirect to metadata IP = nil, want error")
	}
	var blocked *ErrBlockedIP
	if !errors.As(err, &blocked) {
		t.Fatalf("redirect error = %v, want *ErrBlockedIP in chain", err)
	}
	if blocked.IP.String() != "169.254.169.254" {
		t.Errorf("blocked IP = %s, want 169.254.169.254", blocked.IP)
	}
}

func TestFetchMaxRedirectsCap(t *testing.T) {
	// A loopback server that redirects to itself forever; the cap must stop it.
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+r.URL.Path+"x", http.StatusFound)
	}))
	defer srv.Close()

	client := NewClient(WithAllowPrivate(), WithMaxRedirects(3))
	_, err := Fetch(context.Background(), client, srv.URL, 1<<20)
	if err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Fatalf("Fetch = %v, want redirect-cap error", err)
	}
}

func TestWithAllowCIDRsPanicsOnBadInput(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("WithAllowCIDRs(bad) did not panic")
		}
	}()
	WithAllowCIDRs("not-a-cidr")
}

func TestGetUsesGuardedDefaultClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("x"))
	}))
	defer srv.Close()

	// Get has no options, so its default client must block loopback.
	_, err := Get(context.Background(), srv.URL, 1<<20)
	var blocked *ErrBlockedIP
	if !errors.As(err, &blocked) {
		t.Fatalf("Get(localhost) = %v, want *ErrBlockedIP", err)
	}
}

// Example ties the pieces together the way a caller would use them.
func ExampleFetch() {
	client := NewClient()
	_, err := Fetch(context.Background(), client, "http://169.254.169.254/latest/meta-data/", 1<<20)
	var blocked *ErrBlockedIP
	if errors.As(err, &blocked) {
		fmt.Println("refused metadata endpoint")
	}
	// Output: refused metadata endpoint
}
