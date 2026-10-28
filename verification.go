package auth

import (
	"errors"
	"fmt"
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

type emailRequest struct {
	Email string `json:"email"`
}

// requestVerification sends a new verification link. It always answers
// 202, whether or not the email has an account, so it can't be used to
// find accounts.
func (a *Auth) requestVerification(w http.ResponseWriter, r *http.Request) {
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
	case row.EmailVerifiedAt == nil:
		tok, t, err := a.tokens.Create(r.Context(), row.ID, emailtoken.VerifyEmail, "")
		if err != nil && !errors.Is(err, emailtoken.ErrCooldown) {
			httpapi.WriteInternalError(w, r, a.log, err)
			return
		}
		if err == nil {
			a.sendEmail(row.Email, a.emails.VerifyEmail, emailtoken.VerifyEmail, tok, t.ID)
		}
	}
	w.WriteHeader(http.StatusAccepted)
}

type confirmVerificationRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
	Client   string `json:"client"`
}

// confirmVerification verifies the email of the token's account and logs
// the user in. It requires the account's password as well as the token:
// otherwise someone who signed up with another person's address could get
// that person to verify the account for them just by clicking the link.
func (a *Auth) confirmVerification(w http.ResponseWriter, r *http.Request) {
	var req confirmVerificationRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return
	}
	var details []httpapi.FieldError
	if req.Token == "" {
		details = append(details, httpapi.FieldError{Field: "token", Code: "required", Message: "The link is missing its token."})
	}
	if req.Password == "" {
		details = append(details, httpapi.FieldError{Field: "password", Code: "required", Message: "Enter your password."})
	}
	if fe, ok := checkClient(req.Client); !ok {
		details = append(details, fe)
	}
	if details != nil {
		writeValidationFailed(w, r, details)
		return
	}

	ctx := r.Context()
	t, err := a.tokens.Lookup(ctx, req.Token, emailtoken.VerifyEmail)
	if errors.Is(err, emailtoken.ErrInvalid) {
		writeTokenInvalid(w, r)
		return
	}
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	row, err := a.q.GetUserByID(ctx, t.UserID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeTokenInvalid(w, r)
		return
	}
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}

	ok := false
	if row.PasswordHash == nil {
		password.SimulateVerify(req.Password)
	} else if ok, err = password.Verify(req.Password, *row.PasswordHash); err != nil {
		httpapi.WriteInternalError(w, r, a.log, fmt.Errorf("verifying password for user %s: %w", row.ID, err))
		return
	}
	if !ok {
		if err := a.tokens.RecordFailure(ctx, t.ID); err != nil {
			httpapi.WriteInternalError(w, r, a.log, err)
			return
		}
		writeInvalidCredentials(w, r)
		return
	}

	twoFactor, err := twoFactorEnabled(ctx, a.q, row.ID)
	if err == nil && twoFactor {
		// Nothing is spent while the user is at the guessing limit, so the
		// link still works afterwards.
		err = a.checkPaused(ctx, a.q, row.ID)
	}
	if err != nil {
		a.writeLoginCodeError(w, r, err)
		return
	}

	tok, expires, err := a.verifyAndLogIn(r, row.ID, t.ID, session.Client(req.Client), twoFactor)
	if errors.Is(err, emailtoken.ErrInvalid) {
		// A concurrent request used the token first.
		writeTokenInvalid(w, r)
		return
	}
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	a.logEvent(r, "auth: email verified", row.ID)
	if twoFactor {
		a.logEvent(r, "auth: two-factor challenge started", row.ID)
		writeChallengeJSON(w, r, tok, expires)
		return
	}
	user := userFromRow(row)
	user.EmailVerified = true
	httpapi.WriteJSON(w, r, http.StatusCreated, loginResponse{User: toUserJSON(user), Token: tok, ExpiresAt: timestamp(expires)})
}

// verifyAndLogIn spends the token, marks the email verified, and starts a
// session, all or nothing. For a user with 2FA, it starts a 2FA challenge
// instead of the session. It returns the session's or challenge's token
// and when it expires.
func (a *Auth) verifyAndLogIn(r *http.Request, userID, tokenID uuid.UUID, client session.Client, twoFactor bool) (string, time.Time, error) {
	ctx := r.Context()
	var (
		tok     string
		expires time.Time
	)
	err := a.withTx(ctx, func(tx pgx.Tx) error {
		if err := emailtoken.NewManager(tx, a.now).Use(ctx, tokenID); err != nil {
			return err
		}
		q := db.New(tx)
		if err := q.MarkEmailVerified(ctx, db.MarkEmailVerifiedParams{ID: userID, Now: a.now().UTC().Truncate(time.Microsecond)}); err != nil {
			return fmt.Errorf("marking email verified: %w", err)
		}
		var err error
		if twoFactor {
			tok, expires, err = a.createChallenge(ctx, q, userID, client)
			return err
		}
		ip, ua := httpapi.Client(r, a.trusted)
		var s session.Session
		tok, s, err = session.NewManager(tx, a.now).Create(ctx, userID, session.Meta{Client: client, IP: ip, UserAgent: ua}, session.Standard)
		expires = s.ExpiresAt
		return err
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return tok, expires, nil
}

func writeTokenInvalid(w http.ResponseWriter, r *http.Request) {
	httpapi.WriteError(w, r, http.StatusUnprocessableEntity, "token_invalid_or_expired",
		"This link is invalid or has expired. Request a new one.", nil)
}
