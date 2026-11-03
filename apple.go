package auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/httpapi"
	"github.com/atlasopsec/auth/internal/session"
	"github.com/atlasopsec/auth/internal/token"
)

type appleSignInRequest struct {
	IdentityToken string `json:"identity_token"`
	Nonce         string `json:"nonce"`
}

// appleSignIn logs in with native Sign in with Apple from the iOS app. The
// app sends the identity token from the system sheet, and the nonce whose
// hex SHA-256 it gave Apple. Each nonce signs in once. The account rules
// are the same as for the other providers (docs/api.md §9).
func (a *Auth) appleSignIn(w http.ResponseWriter, r *http.Request) {
	if a.apple == nil {
		writeNotFound(w, r)
		return
	}
	var req appleSignInRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return
	}
	var details []httpapi.FieldError
	if req.IdentityToken == "" {
		details = append(details, httpapi.FieldError{Field: "identity_token", Code: "required", Message: "Send the identity token from Sign in with Apple."})
	}
	if req.Nonce == "" {
		details = append(details, httpapi.FieldError{Field: "nonce", Code: "required", Message: "Send the nonce the app generated."})
	}
	if details != nil {
		writeValidationFailed(w, r, details)
		return
	}

	// Taken before the token's expiry is checked (see UseAppleNonce).
	now := a.now().UTC().Truncate(time.Microsecond)
	id, expires, err := a.apple.Verify(r.Context(), req.IdentityToken, req.Nonce)
	if err != nil {
		a.writeOAuthError(w, r, fmt.Errorf("%w: %w", errOAuthFailed, err))
		return
	}
	// The nonce is spent before signing in, so a captured token and nonce
	// can't be sent again, and two requests with them can't both get in.
	// If the sign-in then fails, the app gets a new token from the sheet.
	n, err := a.q.UseAppleNonce(r.Context(), db.UseAppleNonceParams{
		ID: uuid.Must(uuid.NewV7()), NonceHash: token.Hash(req.Nonce), ExpiresAt: expires, Now: now,
	})
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, fmt.Errorf("recording Apple nonce: %w", err))
		return
	}
	if n == 0 {
		a.writeOAuthError(w, r, fmt.Errorf("%w: apple: identity token's nonce was already used", errOAuthFailed))
		return
	}
	res, err := a.oauthLogIn(r, providerApple, id, session.ClientMobile)
	if err != nil {
		a.writeOAuthError(w, r, err)
		return
	}
	a.writeOAuthLogin(w, r, providerApple, res)
}
