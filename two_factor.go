package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/httpapi"
	"github.com/atlasopsec/auth/internal/password"
	"github.com/atlasopsec/auth/internal/recoverycode"
	"github.com/atlasopsec/auth/internal/totp"
)

func (a *Auth) registerTwoFactor(mux *http.ServeMux) {
	mux.Handle("POST /v1/users/me/two-factor", endpoint(a.duringSetup(http.HandlerFunc(a.startTwoFactor))))
	mux.Handle("POST /v1/users/me/two-factor/confirm", endpoint(a.duringSetup(http.HandlerFunc(a.confirmTwoFactor))))
	mux.Handle("DELETE /v1/users/me/two-factor", endpoint(a.Authenticated(http.HandlerFunc(a.disableTwoFactor))))
	mux.Handle("POST /v1/users/me/two-factor/recovery-codes", endpoint(a.Authenticated(http.HandlerFunc(a.regenerateRecoveryCodes))))
	mux.Handle("POST /v1/two-factor-challenges/verify", endpoint(http.HandlerFunc(a.verifyChallenge)))
}

// twoFactorStatus reports whether a user has 2FA on, and whether they
// must.
func (a *Auth) twoFactorStatus(ctx context.Context, userID uuid.UUID) (twoFactorState, error) {
	_, s, err := a.userWithTwoFactor(ctx, a.q, userID)
	return s, err
}

// checkPassword verifies a user's current password. Accounts without one
// (OAuth only) never match, after the same work as a real check.
func (a *Auth) checkPassword(ctx context.Context, userID uuid.UUID, pw string) (bool, error) {
	row, err := a.q.GetUserByID(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("reading user: %w", err)
	}
	if row.PasswordHash == nil {
		password.SimulateVerify(pw)
		return false, nil
	}
	ok, err := password.Verify(pw, *row.PasswordHash)
	if err != nil {
		return false, fmt.Errorf("verifying password for user %s: %w", row.ID, err)
	}
	return ok, nil
}

// errBadCode means a 2FA code didn't match.
var errBadCode = errors.New("wrong two-factor code")

// checkSecondFactor checks a TOTP code or a recovery code for a user with
// 2FA on, and spends it. Call it in a transaction: it locks the user's
// secret, so the same code can't be used twice concurrently. It returns
// errBadCode if the code doesn't match.
func (a *Auth) checkSecondFactor(ctx context.Context, q *db.Queries, userID uuid.UUID, code string) (usedRecovery bool, err error) {
	row, err := q.GetTOTPSecretForUpdate(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && row.ConfirmedAt == nil {
		return false, errBadCode
	}
	if err != nil {
		return false, fmt.Errorf("reading 2FA: %w", err)
	}
	now := a.now().UTC().Truncate(time.Microsecond)

	if normalized, ok := recoverycode.Normalize(code); ok {
		n, err := q.UseRecoveryCode(ctx, db.UseRecoveryCodeParams{UserID: userID, CodeHash: recoverycode.Hash(normalized), Now: &now})
		if err != nil {
			return false, fmt.Errorf("using recovery code: %w", err)
		}
		if n == 0 {
			return false, errBadCode
		}
		return true, nil
	}

	secret, err := a.openSecret(row)
	if err != nil {
		return false, err
	}
	step, ok := totp.Verify(secret, code, now, row.LastUsedStep)
	if !ok {
		return false, errBadCode
	}
	if err := q.RecordTOTPStep(ctx, db.RecordTOTPStepParams{UserID: userID, Step: step, Now: now}); err != nil {
		return false, fmt.Errorf("recording 2FA step: %w", err)
	}
	return false, nil
}

func (a *Auth) openSecret(row db.AuthTotpSecret) ([]byte, error) {
	secret, err := a.box.Open(row.SecretEncrypted, row.UserID[:])
	if err != nil {
		return nil, fmt.Errorf("decrypting 2FA secret for user %s (was Config.EncryptionKey changed?): %w", row.UserID, err)
	}
	return secret, nil
}

type passwordRequest struct {
	CurrentPassword string `json:"current_password"`
}

type twoFactorSetupJSON struct {
	Secret     string `json:"secret"`
	OTPAuthURI string `json:"otpauth_uri"`
}

// startTwoFactor creates a pending TOTP secret for the user to add to
// their authenticator app. 2FA isn't on until confirmTwoFactor.
func (a *Auth) startTwoFactor(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	var req passwordRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return
	}
	if req.CurrentPassword == "" {
		writeValidationFailed(w, r, []httpapi.FieldError{currentPasswordRequired})
		return
	}
	ctx := r.Context()
	ok, err := a.checkPassword(ctx, c.user.ID, req.CurrentPassword)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	if !ok {
		writeValidationFailed(w, r, []httpapi.FieldError{currentPasswordIncorrect})
		return
	}

	secret := totp.NewSecret()
	n, err := a.q.UpsertPendingTOTPSecret(ctx, db.UpsertPendingTOTPSecretParams{
		UserID:          c.user.ID,
		SecretEncrypted: a.box.Seal(secret, c.user.ID[:]),
		Now:             a.now().UTC().Truncate(time.Microsecond),
	})
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	if n == 0 {
		writeTwoFactorAlreadyEnabled(w, r)
		return
	}
	httpapi.WriteJSON(w, r, http.StatusCreated, twoFactorSetupJSON{
		Secret:     totp.EncodeSecret(secret),
		OTPAuthURI: totp.URI(a.appName, c.user.Email, secret),
	})
}

type codeRequest struct {
	Code string `json:"code"`
}

type recoveryCodesJSON struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

var errNoPendingSetup = errors.New("no pending 2FA setup")

// confirmTwoFactor turns 2FA on once the user proves their authenticator
// works, and returns their recovery codes, the only time they're shown.
func (a *Auth) confirmTwoFactor(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	var req codeRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return
	}
	if req.Code == "" {
		writeValidationFailed(w, r, []httpapi.FieldError{codeRequired})
		return
	}

	var codes []string
	err := a.inTx(r.Context(), func(q *db.Queries) error {
		row, err := q.GetTOTPSecretForUpdate(r.Context(), c.user.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNoPendingSetup
		}
		if err != nil {
			return fmt.Errorf("reading 2FA: %w", err)
		}
		if row.ConfirmedAt != nil {
			return errTwoFactorAlreadyEnabled
		}
		secret, err := a.openSecret(row)
		if err != nil {
			return err
		}
		now := a.now().UTC().Truncate(time.Microsecond)
		step, ok := totp.Verify(secret, req.Code, now, row.LastUsedStep)
		if !ok {
			return errBadCode
		}
		if err := q.ConfirmTOTPSecret(r.Context(), db.ConfirmTOTPSecretParams{UserID: c.user.ID, Step: step, Now: &now}); err != nil {
			return fmt.Errorf("confirming 2FA: %w", err)
		}
		codes, err = a.replaceRecoveryCodes(r.Context(), q, c.user.ID)
		return err
	})
	if a.writeTwoFactorError(w, r, err) {
		return
	}
	a.logEvent(r, "auth: two-factor enabled", c.user.ID)
	a.sendNotice(c.user.Email, a.emails.TwoFactorEnabled)
	httpapi.WriteJSON(w, r, http.StatusOK, recoveryCodesJSON{RecoveryCodes: codes})
}

type passwordAndCodeRequest struct {
	CurrentPassword string `json:"current_password"`
	Code            string `json:"code"`
}

// decodePasswordAndCode reads and checks a request that needs both the
// current password and a 2FA code, writing the error response if it fails.
func (a *Auth) decodePasswordAndCode(w http.ResponseWriter, r *http.Request, userID uuid.UUID) (passwordAndCodeRequest, bool) {
	var req passwordAndCodeRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return req, false
	}
	var details []httpapi.FieldError
	if req.CurrentPassword == "" {
		details = append(details, currentPasswordRequired)
	}
	if req.Code == "" {
		details = append(details, codeRequired)
	}
	if details != nil {
		writeValidationFailed(w, r, details)
		return req, false
	}
	ok, err := a.checkPassword(r.Context(), userID, req.CurrentPassword)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return req, false
	}
	if !ok {
		writeValidationFailed(w, r, []httpapi.FieldError{currentPasswordIncorrect})
		return req, false
	}
	return req, true
}

var errTwoFactorRequired = errors.New("two-factor authentication is required")

// disableTwoFactor turns 2FA off, with the password and a code. Users who
// must have 2FA can't.
func (a *Auth) disableTwoFactor(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	status, err := a.twoFactorStatus(r.Context(), c.user.ID)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	if !status.enabled {
		writeTwoFactorNotEnabled(w, r)
		return
	}
	if status.required {
		a.writeTwoFactorError(w, r, errTwoFactorRequired)
		return
	}
	req, ok := a.decodePasswordAndCode(w, r, c.user.ID)
	if !ok {
		return
	}
	err = a.inTx(r.Context(), func(q *db.Queries) error {
		if _, err := a.checkSecondFactor(r.Context(), q, c.user.ID, req.Code); err != nil {
			return err
		}
		if err := q.DeleteTOTPSecret(r.Context(), c.user.ID); err != nil {
			return fmt.Errorf("deleting 2FA secret: %w", err)
		}
		if err := q.DeleteRecoveryCodes(r.Context(), c.user.ID); err != nil {
			return fmt.Errorf("deleting recovery codes: %w", err)
		}
		return nil
	})
	if a.writeTwoFactorError(w, r, err) {
		return
	}
	a.logEvent(r, "auth: two-factor disabled", c.user.ID)
	a.sendNotice(c.user.Email, a.emails.TwoFactorDisabled)
	w.WriteHeader(http.StatusNoContent)
}

// regenerateRecoveryCodes replaces the user's recovery codes, with the
// password and a code.
func (a *Auth) regenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	status, err := a.twoFactorStatus(r.Context(), c.user.ID)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	if !status.enabled {
		writeTwoFactorNotEnabled(w, r)
		return
	}
	req, ok := a.decodePasswordAndCode(w, r, c.user.ID)
	if !ok {
		return
	}
	var codes []string
	err = a.inTx(r.Context(), func(q *db.Queries) error {
		if _, err := a.checkSecondFactor(r.Context(), q, c.user.ID, req.Code); err != nil {
			return err
		}
		codes, err = a.replaceRecoveryCodes(r.Context(), q, c.user.ID)
		return err
	})
	if a.writeTwoFactorError(w, r, err) {
		return
	}
	a.logEvent(r, "auth: recovery codes regenerated", c.user.ID)
	a.sendNotice(c.user.Email, a.emails.RecoveryCodesRegenerated)
	httpapi.WriteJSON(w, r, http.StatusOK, recoveryCodesJSON{RecoveryCodes: codes})
}

// replaceRecoveryCodes deletes the user's recovery codes and creates new
// ones, returning them for display.
func (a *Auth) replaceRecoveryCodes(ctx context.Context, q *db.Queries, userID uuid.UUID) ([]string, error) {
	if err := q.DeleteRecoveryCodes(ctx, userID); err != nil {
		return nil, fmt.Errorf("deleting recovery codes: %w", err)
	}
	codes := recoverycode.New()
	now := a.now().UTC().Truncate(time.Microsecond)
	for _, code := range codes {
		id, err := uuid.NewV7()
		if err != nil {
			return nil, fmt.Errorf("generating recovery code ID: %w", err)
		}
		normalized, _ := recoverycode.Normalize(code)
		if err := q.CreateRecoveryCode(ctx, db.CreateRecoveryCodeParams{ID: id, UserID: userID, CodeHash: recoverycode.Hash(normalized), Now: now}); err != nil {
			return nil, fmt.Errorf("creating recovery code: %w", err)
		}
	}
	return codes, nil
}

// inTx runs f in a transaction, committing if it returns nil.
func (a *Auth) inTx(ctx context.Context, f func(q *db.Queries) error) error {
	return a.withTx(ctx, func(tx pgx.Tx) error { return f(db.New(tx)) })
}

// withTx is inTx for work that needs the transaction itself, such as
// creating a session.
func (a *Auth) withTx(ctx context.Context, f func(tx pgx.Tx) error) error {
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	// After Commit this is a no-op.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := f(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing: %w", err)
	}
	return nil
}

var errTwoFactorAlreadyEnabled = errors.New("two-factor authentication is already on")

var (
	currentPasswordRequired  = httpapi.FieldError{Field: "current_password", Code: "required", Message: "Enter your current password."}
	currentPasswordIncorrect = httpapi.FieldError{Field: "current_password", Code: "incorrect", Message: "Your current password is incorrect."}
	codeRequired             = httpapi.FieldError{Field: "code", Code: "required", Message: "Enter the code from your authenticator app."}
	codeIncorrect            = httpapi.FieldError{Field: "code", Code: "incorrect", Message: "That code isn't right. Check your authenticator app and try again."}
)

func writeTwoFactorAlreadyEnabled(w http.ResponseWriter, r *http.Request) {
	httpapi.WriteError(w, r, http.StatusConflict, "two_factor_already_enabled", "Two-factor authentication is already on.", nil)
}

func writeTwoFactorNotEnabled(w http.ResponseWriter, r *http.Request) {
	httpapi.WriteError(w, r, http.StatusConflict, "two_factor_not_enabled", "Two-factor authentication isn't on.", nil)
}

// writeTwoFactorError writes the response for an error from the 2FA
// endpoints, and reports whether there was one. A wrong code is a field
// error, not a 401: the user is logged in.
func (a *Auth) writeTwoFactorError(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, errBadCode):
		writeValidationFailed(w, r, []httpapi.FieldError{codeIncorrect})
	case errors.Is(err, errNoPendingSetup):
		httpapi.WriteError(w, r, http.StatusConflict, "two_factor_setup_not_started", "Start setting up two-factor authentication first.", nil)
	case errors.Is(err, errTwoFactorAlreadyEnabled):
		writeTwoFactorAlreadyEnabled(w, r)
	case errors.Is(err, errTwoFactorRequired):
		httpapi.WriteError(w, r, http.StatusForbidden, "two_factor_required", "Two-factor authentication is required for your account, so it can't be turned off.", nil)
	default:
		httpapi.WriteInternalError(w, r, a.log, err)
	}
	return true
}
