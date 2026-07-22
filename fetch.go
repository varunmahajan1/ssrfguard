package ssrfguard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// ErrScheme is returned by [Fetch] and [Get] when the URL scheme is not http or
// https. Fetching file://, ftp://, gopher://, and friends is a classic SSRF and
// local-file-read vector, so only the two web schemes are permitted.
var ErrScheme = errors.New("ssrfguard: URL scheme not allowed (only http and https)")

// ErrTooLarge is returned by [Fetch] and [Get] when the response body exceeds
// the caller's maxBytes. The body is rejected, never truncated: a silently
// truncated download is worse than a refused one because the corruption
// surfaces far downstream, where it is hard to trace back to the fetch.
var ErrTooLarge = errors.New("ssrfguard: response body exceeds maximum size")

// defaultClient backs [Get]. It is a fully guarded client with default options.
var defaultClient = NewClient()

// Fetch performs a guarded HTTP GET of url using client and returns the body.
//
// It enforces three things beyond the dial-time IP guard already built into a
// [NewClient] client:
//
//   - Scheme allowlist: only http and https are permitted ([ErrScheme]).
//   - Size cap that rejects rather than truncates ([ErrTooLarge]): the
//     Content-Length header is checked when present, and the body is read
//     through an [io.LimitReader] set to maxBytes+1 so that an oversize body
//     (including chunked responses with no declared length) is detected and
//     refused instead of silently cut off.
//   - Context cancellation via ctx.
//
// The returned bytes are the full body when it is within maxBytes.
func Fetch(ctx context.Context, client *http.Client, rawURL string, maxBytes int64) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("ssrfguard: invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: %q", ErrScheme, u.Scheme)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("ssrfguard: build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Fast path: trust a declared Content-Length only to reject early. A
	// truthful oversize length saves us reading the body at all; a lying or
	// absent length is caught by the LimitReader below regardless.
	if resp.ContentLength > maxBytes {
		return nil, ErrTooLarge
	}

	// Read one byte past the limit: if the LimitReader is exhausted, the body
	// was larger than maxBytes and must be refused.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("ssrfguard: read body: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, ErrTooLarge
	}
	return body, nil
}

// Get is a convenience wrapper over [Fetch] using a default guarded client.
// Use [Fetch] with a [NewClient] client when you need custom options such as a
// timeout or an internal-service allowlist.
func Get(ctx context.Context, rawURL string, maxBytes int64) ([]byte, error) {
	return Fetch(ctx, defaultClient, rawURL, maxBytes)
}
