package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/emailtoken"
	"github.com/atlasopsec/auth/internal/httpapi"
	"github.com/atlasopsec/auth/internal/password"
	"github.com/atlasopsec/auth/internal/session"
)

// checkBreached reports whether a new password appears in a known data
// breach, as a field error on field. If the check can't be done, it's
// skipped and logged: an outage at Have I Been Pwned mustn't block users.
func (a *Auth) checkBreached(r *http.Request, field, pw string) (httpapi.FieldError, bool) {
	if a.breach == nil {
		return httpapi.FieldError{}, true
	}
	breached, err := a.breach.Breached(r.Context(), pw)
	if err != nil {
		a.log.WarnContext(r.Context(), "auth: breached-password check skipped",
			slog.String("request_id", httpapi.RequestIDFrom(r.Context())),
			slog.String("error", err.Error()))
		return httpapi.FieldError{}, true
	}
	if breached {
		return httpapi.FieldError{Field: field, Code: "breached",
			Message: "This password has appeared in a data breach. Choose a different one."}, false
	}
	return httpapi.FieldError{}, true
}

// requestPasswordReset emails a reset link. It always answers 202, whether
// or not the email has an account, so it can't be used to find accounts.
func (a *Auth) requestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req emailRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if fe, ok := checkEmail(req.Email); !ok {
		writeValidationFailed(w, r, []httpapi.FieldError{fe})
		return
	}

	row, err := a.q.GetUserByEmail(r.Context(), req.Email)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	default:
		// Accounts without a password (OAuth only) can use a reset to add
		// one.
		tok, t, err := a.tokens.Create(r.Context(), row.ID, emailtoken.ResetPassword, "")
		if err != nil && !errors.Is(err, emailtoken.ErrCooldown) {
			httpapi.WriteInternalError(w, r, a.log, err)
			return
		}
		if err == nil {
			a.sendEmail(row.Email, a.emails.PasswordReset, emailtoken.ResetPassword, tok, t.ID)
		}
	}
	w.WriteHeader(http.StatusAccepted)
}

type confirmResetRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

// confirmPasswordReset sets a new password from a reset link. It also
// verifies the email, since the user just proved they control it, and ends
// every session. Together these let the real owner take back an account
// someone else created with their address.
func (a *Auth) confirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req confirmResetRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return
	}
	var details []httpapi.FieldError
	if req.Token == "" {
		details = append(details, httpapi.FieldError{Field: "token", Code: "required", Message: "The link is missing its token."})
	}
	if fe, ok := checkNewPassword(req.Password); !ok {
		details = append(details, fe)
	}
	if details != nil {
		writeValidationFailed(w, r, details)
		return
	}

	ctx := r.Context()
	t, err := a.tokens.Lookup(ctx, req.Token, emailtoken.ResetPassword)
	if errors.Is(err, emailtoken.ErrInvalid) {
		writeTokenInvalid(w, r)
		return
	}
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	if fe, ok := a.checkBreached(r, "password", req.Password); !ok {
		writeValidationFailed(w, r, []httpapi.FieldError{fe})
		return
	}
	hash, err := password.Hash(req.Password, password.DefaultParams)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}

	email, err := a.resetPassword(ctx, t.UserID, t.ID, hash)
	if errors.Is(err, emailtoken.ErrInvalid) {
		// A concurrent request used the token first.
		writeTokenInvalid(w, r)
		return
	}
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	a.logEvent(r, "auth: password reset", t.UserID)
	a.sendNotice(email, a.emails.PasswordChanged)
	w.WriteHeader(http.StatusNoContent)
}

// resetPassword spends the token, sets the password, verifies the email,
// and ends every session, all or nothing. It returns the user's email.
func (a *Auth) resetPassword(ctx context.Context, userID, tokenID uuid.UUID, hash string) (string, error) {
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("beginning reset: %w", err)
	}
	// After Commit this is a no-op.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	q := db.New(tx)
	now := a.now().UTC().Truncate(time.Microsecond)

	if err := emailtoken.NewManager(tx, a.now).Use(ctx, tokenID); err != nil {
		return "", err
	}
	if err := q.UpdatePasswordHash(ctx, db.UpdatePasswordHashParams{ID: userID, PasswordHash: &hash, Now: now}); err != nil {
		return "", fmt.Errorf("setting password: %w", err)
	}
	if err := q.MarkEmailVerified(ctx, db.MarkEmailVerifiedParams{ID: userID, Now: now}); err != nil {
		return "", fmt.Errorf("marking email verified: %w", err)
	}
	if _, err := session.NewManager(tx, a.now).RevokeAll(ctx, userID); err != nil {
		return "", err
	}
	row, err := q.GetUserByID(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("reading user: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("committing reset: %w", err)
	}
	return row.Email, nil
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// changePassword changes the logged-in user's password. It requires the
// current one, and ends every other session.
func (a *Auth) changePassword(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	var req changePasswordRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return
	}
	var details []httpapi.FieldError
	if req.CurrentPassword == "" {
		details = append(details, httpapi.FieldError{Field: "current_password", Code: "required", Message: "Enter your current password."})
	}
	if fe, ok := checkNewPassword(req.NewPassword); !ok {
		fe.Field = "new_password"
		details = append(details, fe)
	}
	if details != nil {
		writeValidationFailed(w, r, details)
		return
	}

	ctx := r.Context()
	row, err := a.q.GetUserByID(ctx, c.user.ID)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	ok := false
	if row.PasswordHash == nil {
		// OAuth-only accounts have no current password; they add one with
		// a reset.
		password.SimulateVerify(req.CurrentPassword)
	} else if ok, err = password.Verify(req.CurrentPassword, *row.PasswordHash); err != nil {
		httpapi.WriteInternalError(w, r, a.log, fmt.Errorf("verifying password for user %s: %w", row.ID, err))
		return
	}
	if !ok {
		// Not 401: that would tell the app the user had been logged out.
		writeValidationFailed(w, r, []httpapi.FieldError{{Field: "current_password", Code: "incorrect", Message: "Your current password is incorrect."}})
		return
	}
	if fe, ok := a.checkBreached(r, "new_password", req.NewPassword); !ok {
		writeValidationFailed(w, r, []httpapi.FieldError{fe})
		return
	}
	hash, err := password.Hash(req.NewPassword, password.DefaultParams)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}

	if err := a.setPasswordKeepingSession(ctx, row.ID, c.session.ID, hash); err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	a.logEvent(r, "auth: password changed", row.ID)
	a.sendNotice(row.Email, a.emails.PasswordChanged)
	w.WriteHeader(http.StatusNoContent)
}

// setPasswordKeepingSession sets the password and ends every session but
// keepID, all or nothing.
func (a *Auth) setPasswordKeepingSession(ctx context.Context, userID, keepID uuid.UUID, hash string) error {
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning password change: %w", err)
	}
	// After Commit this is a no-op.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if err := db.New(tx).UpdatePasswordHash(ctx, db.UpdatePasswordHashParams{
		ID: userID, PasswordHash: &hash, Now: a.now().UTC().Truncate(time.Microsecond),
	}); err != nil {
		return fmt.Errorf("setting password: %w", err)
	}
	if _, err := session.NewManager(tx, a.now).RevokeOthers(ctx, userID, keepID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing password change: %w", err)
	}
	return nil
}
