package auth

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/httpapi"
	"github.com/atlasopsec/auth/rbac"
)

// registerAPIKeys adds the key endpoints (docs/api.md §18), when keys are
// on. They need a session: Authenticated never takes a key, so a key can't
// list, make, or revoke keys.
func (a *Auth) registerAPIKeys(mux *http.ServeMux) {
	if a.keyPrefix == "" {
		return
	}
	mux.Handle("GET /v1/api-keys", endpoint(a.Authenticated(http.HandlerFunc(a.listAPIKeys))))
	mux.Handle("POST /v1/api-keys", endpoint(a.Authenticated(a.limitIP(limitLogin, http.HandlerFunc(a.createAPIKey)))))
	mux.Handle("DELETE /v1/api-keys/{id}", endpoint(a.Authenticated(http.HandlerFunc(a.revokeAPIKey))))
}

type apiKeyJSON struct {
	ID          uuid.UUID         `json:"id"`
	Name        string            `json:"name"`
	Hint        string            `json:"hint"`
	Permissions []rbac.Permission `json:"permissions"`
	CreatedAt   timestamp         `json:"created_at"`
	ExpiresAt   timestamp         `json:"expires_at"`
	LastUsedAt  *timestamp        `json:"last_used_at"`
	LastUsedIP  *string           `json:"last_used_ip"`
}

type newAPIKeyJSON struct {
	apiKeyJSON
	// Key is sent once, here.
	Key string `json:"key"`
}

type apiKeyList struct {
	Data       []apiKeyJSON `json:"data"`
	NextCursor *string      `json:"next_cursor"`
}

func toAPIKeyJSON(k APIKey) apiKeyJSON {
	j := apiKeyJSON{
		ID:          k.ID,
		Name:        k.Name,
		Hint:        k.Hint,
		Permissions: k.Permissions,
		CreatedAt:   timestamp(k.CreatedAt),
		ExpiresAt:   timestamp(k.ExpiresAt),
	}
	if k.LastUsedAt != nil {
		t := timestamp(*k.LastUsedAt)
		j.LastUsedAt = &t
	}
	if k.LastUsedIP != nil {
		ip := k.LastUsedIP.String()
		j.LastUsedIP = &ip
	}
	return j
}

func (a *Auth) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	keys, err := a.ListAPIKeys(r.Context(), c.user.ID)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	list := apiKeyList{Data: make([]apiKeyJSON, len(keys))}
	for i, k := range keys {
		list.Data[i] = toAPIKeyJSON(k)
	}
	httpapi.WriteJSON(w, r, http.StatusOK, list)
}

type createAPIKeyRequest struct {
	Name        string            `json:"name"`
	Permissions []rbac.Permission `json:"permissions"`
	// ExpiresAt is RFC 3339, or null for DefaultAPIKeyLifetime.
	ExpiresAt       *time.Time `json:"expires_at"`
	CurrentPassword string     `json:"current_password"`
	// Code is required when the user has 2FA on.
	Code string `json:"code"`
}

var (
	apiKeyNameInvalid        = httpapi.FieldError{Field: "name", Code: "invalid", Message: "Name the key in 1 to 100 characters."}
	apiKeyPermissionsInvalid = httpapi.FieldError{Field: "permissions", Code: "invalid", Message: "Choose at least one permission you have that keys may carry."}
	apiKeyExpiryInvalid      = httpapi.FieldError{Field: "expires_at", Code: "invalid", Message: "Choose an expiry within the next 365 days."}
)

// createAPIKey makes a key for the logged-in user. It takes the password,
// and a 2FA code when they have 2FA on, so a stolen session alone can't
// make a key that outlives it. The key is in the answer, once, and the
// user is emailed, so a key they didn't make doesn't go unnoticed.
func (a *Auth) createAPIKey(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	var req createAPIKeyRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return
	}
	if !a.requirePassword(w, r, c.user.ID) {
		return
	}
	tf, err := a.twoFactorStatus(r.Context(), c.user.ID)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	// The cheap checks first, so a mistake doesn't cost a 2FA code.
	var details []httpapi.FieldError
	if req.CurrentPassword == "" {
		details = append(details, currentPasswordRequired)
	}
	if tf.enabled && req.Code == "" {
		details = append(details, codeRequired)
	}
	if fe, ok := a.precheckAPIKey(req); !ok {
		details = append(details, fe...)
	}
	if details != nil {
		writeValidationFailed(w, r, details)
		return
	}
	if !a.passwordChecked(w, r, c.user.ID, req.CurrentPassword) {
		return
	}
	if tf.enabled {
		var check codeCheck
		err := a.inTx(r.Context(), func(q *db.Queries) error {
			var err error
			// A wrong code is committed, so it counts.
			check, err = a.checkLoginCode(r.Context(), q, c.user.ID, req.Code, a.clientIP(r), "")
			return err
		})
		if a.writeTwoFactorError(w, r, err) {
			return
		}
		if !check.ok {
			a.wrongTwoFactorCode(w, r, c.user.ID, c.user.Email, check)
			return
		}
	}
	nk := NewAPIKey{Name: req.Name, Permissions: req.Permissions}
	if req.ExpiresAt != nil {
		nk.ExpiresAt = *req.ExpiresAt
	}
	k, key, err := a.CreateAPIKey(r.Context(), c.user.ID, nk, a.ActorOf(r))
	switch {
	case errors.Is(err, ErrInvalidAPIKeyName):
		writeValidationFailed(w, r, []httpapi.FieldError{apiKeyNameInvalid})
		return
	case errors.Is(err, ErrAPIKeyPermission):
		writeValidationFailed(w, r, []httpapi.FieldError{apiKeyPermissionsInvalid})
		return
	case errors.Is(err, ErrAPIKeyExpiry):
		writeValidationFailed(w, r, []httpapi.FieldError{apiKeyExpiryInvalid})
		return
	case errors.Is(err, ErrTooManyAPIKeys):
		httpapi.WriteError(w, r, http.StatusConflict, "too_many_api_keys", "You have as many API keys as you can. Revoke one you no longer use first.", nil)
		return
	case err != nil:
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	a.send(c.user.Email, a.emails.APIKeyCreated, EmailData{AppName: a.appName, AppURL: a.appURL, APIKeyName: k.Name, APIKeyExpiresAt: k.ExpiresAt}, k.ID)
	httpapi.WriteJSON(w, r, http.StatusCreated, newAPIKeyJSON{apiKeyJSON: toAPIKeyJSON(k), Key: key})
}

// precheckAPIKey checks what it can of a key request without the
// database: CreateAPIKey checks it all again, with the user's role.
func (a *Auth) precheckAPIKey(req createAPIKeyRequest) ([]httpapi.FieldError, bool) {
	var details []httpapi.FieldError
	if _, err := cleanAPIKeyName(req.Name); err != nil {
		details = append(details, apiKeyNameInvalid)
	}
	if len(req.Permissions) == 0 {
		details = append(details, apiKeyPermissionsInvalid)
	}
	for _, p := range req.Permissions {
		if !a.keyMayCarry(p) {
			details = append(details, apiKeyPermissionsInvalid)
			break
		}
	}
	if req.ExpiresAt != nil {
		if _, err := a.apiKeyExpiry(*req.ExpiresAt); err != nil {
			details = append(details, apiKeyExpiryInvalid)
		}
	}
	return details, details == nil
}

func (a *Auth) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeNotFound(w, r)
		return
	}
	err = a.RevokeAPIKey(r.Context(), c.user.ID, id, a.ActorOf(r))
	if errors.Is(err, ErrAPIKeyNotFound) {
		writeNotFound(w, r)
		return
	}
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	a.logEvent(r, "auth: API key revoked", c.user.ID)
	w.WriteHeader(http.StatusNoContent)
}
