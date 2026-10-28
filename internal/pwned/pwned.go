// Package pwned checks passwords against Have I Been Pwned's list of
// passwords seen in data breaches, using its range API
// (https://haveibeenpwned.com/API/v3#PwnedPasswords).
//
// The password never leaves the server. Only the first 5 hex characters of
// its SHA-1 hash are sent, and the API answers with every breached hash
// that starts with them ("k-anonymity"). Padding is requested, so the
// response's size doesn't hint at the answer either.
package pwned

import (
	"bufio"
	"context"
	"crypto/sha1" //nolint:gosec // G505: SHA-1 is what the HIBP range API is keyed on; it isn't used for security here.
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultURL is the range API's base URL.
const DefaultURL = "https://api.pwnedpasswords.com"

// Timeout bounds a whole check. A slow API must not hold up sign-ups.
const Timeout = 2 * time.Second

// maxResponse bounds the response read. A padded response is about 40 KB.
const maxResponse = 1 << 20

// Checker checks passwords against the range API.
type Checker struct {
	client  *http.Client
	baseURL string
}

// New returns a Checker using the API at baseURL (DefaultURL outside tests).
func New(baseURL string) *Checker {
	return &Checker{client: &http.Client{Timeout: Timeout}, baseURL: strings.TrimRight(baseURL, "/")}
}

// Breached reports whether password appears in a known data breach. It
// returns an error if the API can't be reached or answers unexpectedly;
// callers decide whether to fail open.
func (c *Checker) Breached(ctx context.Context, password string) (bool, error) {
	sum := sha1.Sum([]byte(password)) //nolint:gosec // G401: see the import.
	hash := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := hash[:5], hash[5:]

	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/range/"+prefix, nil)
	if err != nil {
		return false, fmt.Errorf("pwned: building request: %w", err)
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "atlasopsec-auth")

	resp, err := c.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("pwned: calling API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("pwned: API returned %s", resp.Status)
	}

	// Each line is "SUFFIX:COUNT". Padding lines have a count of 0.
	sc := bufio.NewScanner(io.LimitReader(resp.Body, maxResponse))
	for sc.Scan() {
		s, count, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if ok && strings.EqualFold(s, suffix) && count != "0" {
			return true, nil
		}
	}
	if err := sc.Err(); err != nil {
		return false, fmt.Errorf("pwned: reading response: %w", err)
	}
	return false, nil
}
