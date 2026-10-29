package auth

import (
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/atlasopsec/auth/internal/httpapi"
	"github.com/atlasopsec/auth/internal/ratelimit"
)

// The rate limits from docs/api.md §10. Per-IP limits are generous: offices
// and mobile carriers put many people behind one address.
var (
	// limitLogin covers every way to log in or prove who you are.
	limitLogin  = ratelimit.Rule{Name: "login:ip", Limit: 30, Window: 10 * time.Minute}
	limitSignUp = ratelimit.Rule{Name: "signup:ip", Limit: 10, Window: time.Hour}
	// limitEmailIP and limitEmailAddress cover requests that email an
	// address the caller chose.
	limitEmailIP      = ratelimit.Rule{Name: "email:ip", Limit: 10, Window: time.Hour}
	limitEmailAddress = ratelimit.Rule{Name: "email:address", Limit: 10, Window: 24 * time.Hour}
	limitOAuthStart   = ratelimit.Rule{Name: "oauth:ip", Limit: 30, Window: 10 * time.Minute}
	// limitWrongCodes counts wrong 2FA codes, on top of the per-user
	// guessing limit (§8).
	limitWrongCodes = ratelimit.Rule{Name: "wrong-2fa:ip", Limit: 30, Window: time.Hour}
	// limitWrongPassword counts wrong current passwords on logged-in
	// endpoints, per user, so a stolen session can't be used to guess the
	// password.
	limitWrongPassword = ratelimit.Rule{Name: "wrong-password:user", Limit: 10, Window: time.Hour}
)

// limitIP wraps h so each client IP gets at most rule's requests.
func (a *Auth) limitIP(rule ratelimit.Rule, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok, retry, err := a.limiter.Hit(r.Context(), rule, a.clientIP(r))
		if err != nil {
			httpapi.WriteInternalError(w, r, a.log, err)
			return
		}
		if !ok {
			writeRateLimited(w, r, retry)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// allowEmailTo counts a request that emails addr, writing 429 and returning
// false if the address has had too many today. It's counted whether or
// not the address has an account, so it reveals nothing.
func (a *Auth) allowEmailTo(w http.ResponseWriter, r *http.Request, addr string) bool {
	ok, retry, err := a.limiter.Hit(r.Context(), limitEmailAddress, ratelimit.Email(addr))
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return false
	}
	if !ok {
		writeRateLimited(w, r, retry)
	}
	return ok
}

// clientIP returns the rate-limit subject for the request's client.
func (a *Auth) clientIP(r *http.Request) string {
	ip, _ := httpapi.Client(r, a.trusted)
	return ratelimit.IP(ip)
}

func writeRateLimited(w http.ResponseWriter, r *http.Request, retry time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(max(int(math.Ceil(retry.Seconds())), 1)))
	httpapi.WriteError(w, r, http.StatusTooManyRequests, "rate_limited", "Too many requests. Wait a few minutes, then try again.", nil)
}
