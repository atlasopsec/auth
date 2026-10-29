package auth

import (
	"fmt"
	"net/http"

	"github.com/atlasopsec/auth/internal/httpapi"
	"github.com/atlasopsec/auth/internal/session"
)

type appleSignInRequest struct {
	IdentityToken string `json:"identity_token"`
	Nonce         string `json:"nonce"`
}

// appleSignIn logs in with native Sign in with Apple from the iOS app. The
// app sends the identity token from the system sheet, and the nonce whose
// hex SHA-256 it gave Apple. The account rules are the same as for the
// other providers (docs/api.md §9).
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

	id, err := a.apple.Verify(r.Context(), req.IdentityToken, req.Nonce)
	if err != nil {
		a.writeOAuthError(w, r, fmt.Errorf("%w: %w", errOAuthFailed, err))
		return
	}
	res, err := a.oauthLogIn(r, providerApple, id, session.ClientMobile)
	if err != nil {
		a.writeOAuthError(w, r, err)
		return
	}
	a.writeOAuthLogin(w, r, providerApple, res)
}
