package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/emailtoken"
	"github.com/atlasopsec/auth/internal/httpapi"
	"github.com/atlasopsec/auth/internal/session"
)

type emailChangeRequest struct {
	Email           string `json:"email"`
	CurrentPassword string `json:"current_password"`
}

// requestEmailChange starts changing the logged-in user's email: it sends a
// confirmation link to the new address. It answers 202 even if the new
// address belongs to another account, so it can't be used to find
// accounts; that address's owner is emailed instead.
func (a *Auth) requestEmailChange(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	var req emailChangeRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return
	}
	if !a.requirePassword(w, r, c.user.ID) {
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	var details []httpapi.FieldError
	if fe, ok := checkEmail(req.Email); !ok {
		details = append(details, fe)
	} else if strings.EqualFold(req.Email, c.user.Email) {
		details = append(details, httpapi.FieldError{Field: "email", Code: "unchanged", Message: "That's already your email address."})
	}
	if req.CurrentPassword == "" {
		details = append(details, currentPasswordRequired)
	}
	if details != nil {
		writeValidationFailed(w, r, details)
		return
	}
	// Changing the email is sensitive, so the current one must be verified
	// first (auth standard §3).
	if !c.user.EmailVerified {
		writeEmailNotVerified(w, r)
		return
	}
	if !a.allowEmailTo(w, r, req.Email) {
		return
	}

	ctx := r.Context()
	if !a.passwordChecked(w, r, c.user.ID, req.CurrentPassword) {
		return
	}

	_, err := a.q.GetUserByEmail(ctx, req.Email)
	switch {
	case err == nil:
		// Taken: tell its owner, as for a sign-up with their address.
		if err := a.notifyExistingAccount(r, req.Email); err != nil {
			httpapi.WriteInternalError(w, r, a.log, err)
			return
		}
	case errors.Is(err, pgx.ErrNoRows):
		tok, t, err := a.tokens.Create(ctx, c.user.ID, emailtoken.ChangeEmail, req.Email)
		if err != nil && !errors.Is(err, emailtoken.ErrCooldown) {
			httpapi.WriteInternalError(w, r, a.log, err)
			return
		}
		if err == nil {
			a.sendEmail(req.Email, a.emails.EmailChange, emailtoken.ChangeEmail, tok, t.ID)
		}
	default:
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	a.logEvent(r, "auth: email change requested", c.user.ID)
	w.WriteHeader(http.StatusAccepted)
}

type tokenRequest struct {
	Token string `json:"token"`
}

// confirmEmailChange finishes an email change from the link sent to the
// new address. It ends every session and tells the old address.
func (a *Auth) confirmEmailChange(w http.ResponseWriter, r *http.Request) {
	var req tokenRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return
	}
	if req.Token == "" {
		writeValidationFailed(w, r, []httpapi.FieldError{{Field: "token", Code: "required", Message: "The link is missing its token."}})
		return
	}

	ctx := r.Context()
	t, err := a.tokens.Lookup(ctx, req.Token, emailtoken.ChangeEmail)
	if errors.Is(err, emailtoken.ErrInvalid) {
		writeTokenInvalid(w, r)
		return
	}
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}

	oldEmail, err := a.changeEmail(ctx, t.UserID, t.ID, t.NewEmail)
	if errors.Is(err, emailtoken.ErrInvalid) || errors.Is(err, errEmailTaken) {
		// Used by a concurrent request, or the address was taken since the
		// link was sent.
		writeTokenInvalid(w, r)
		return
	}
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	a.logEvent(r, "auth: email changed", t.UserID)
	a.event(r, EventEmailChanged, &t.UserID, nil, nil)
	a.sendNotice(oldEmail, a.emails.EmailChanged)
	w.WriteHeader(http.StatusNoContent)
}

// changeEmail spends the token, switches the email (verified, since the
// link proved control of it), cancels the user's other email tokens, and
// ends every session, all or nothing. It returns the old email.
func (a *Auth) changeEmail(ctx context.Context, userID, tokenID uuid.UUID, newEmail string) (string, error) {
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("beginning email change: %w", err)
	}
	// After Commit this is a no-op.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	q := db.New(tx)

	if err := emailtoken.NewManager(tx, a.now).Use(ctx, tokenID); err != nil {
		return "", err
	}
	row, err := q.GetUserByID(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("reading user: %w", err)
	}
	now := a.now().UTC().Truncate(time.Microsecond)
	err = q.UpdateUserEmail(ctx, db.UpdateUserEmailParams{ID: userID, Email: newEmail, Now: &now})
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" && pgErr.ConstraintName == "idx_users_email" {
		return "", errEmailTaken
	}
	if err != nil {
		return "", fmt.Errorf("changing email: %w", err)
	}
	// Links already sent to the old address, such as a password reset,
	// must stop working.
	if err := q.DeleteUnusedUserEmailTokens(ctx, userID); err != nil {
		return "", fmt.Errorf("cancelling email tokens: %w", err)
	}
	if _, err := session.NewManager(tx, a.now).RevokeAll(ctx, userID); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("committing email change: %w", err)
	}
	return row.Email, nil
}

func writeEmailNotVerified(w http.ResponseWriter, r *http.Request) {
	httpapi.WriteError(w, r, http.StatusForbidden, "email_not_verified", "Verify your email address first. Check your inbox for the link.", nil)
}
