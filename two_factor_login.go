package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/httpapi"
	"github.com/atlasopsec/auth/internal/session"
	"github.com/atlasopsec/auth/internal/token"
)

const (
	// challengeLifetime is how long a user has to enter their code after
	// their password.
	challengeLifetime = 5 * time.Minute
	// maxChallengeAttempts is how many wrong codes one challenge allows
	// before the user has to start over with their password.
	maxChallengeAttempts = 5
	// guessLimit wrong codes within guessWindow, across all of a user's
	// challenges and password resets, pause code checks for that user
	// until the window has passed. Step 8's rate limiting replaces this.
	guessLimit  = 10
	guessWindow = 15 * time.Minute
)

// twoFactorEnabled reports whether a user has confirmed 2FA.
func twoFactorEnabled(ctx context.Context, q *db.Queries, userID uuid.UUID) (bool, error) {
	secret, err := q.GetTOTPSecret(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading 2FA: %w", err)
	}
	return secret.ConfirmedAt != nil, nil
}

// pausedError means the user reached the guessing limit. Code checks
// resume at until.
type pausedError struct {
	until time.Time
}

func (e pausedError) Error() string {
	return "too many wrong two-factor codes; paused until " + e.until.Format(time.RFC3339)
}

// checkPaused returns a pausedError if the user has reached the guessing
// limit.
func (a *Auth) checkPaused(ctx context.Context, q *db.Queries, userID uuid.UUID) error {
	now := a.now().UTC().Truncate(time.Microsecond)
	t, err := q.NthRecentTwoFactorFailure(ctx, db.NthRecentTwoFactorFailureParams{
		UserID: userID,
		Since:  now.Add(-guessWindow),
		N:      guessLimit - 1,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("checking 2FA guessing limit: %w", err)
	}
	return pausedError{until: t.Add(guessWindow)}
}

// codeCheck is the result of checkLoginCode.
type codeCheck struct {
	ok           bool
	usedRecovery bool
	// tripped means this wrong code reached the guessing limit.
	tripped bool
}

// checkLoginCode checks a code entered to log in or to reset a password,
// where wrong codes count toward the guessing limit. Call it in a
// transaction. A wrong code is reported in the result rather than as an
// error, so the caller can commit the count. While the user's limit, or the
// client IP's (ip, from ratelimit.IP), is reached it returns a pausedError
// without checking the code.
func (a *Auth) checkLoginCode(ctx context.Context, q *db.Queries, userID uuid.UUID, code, ip string) (codeCheck, error) {
	// Taking checkSecondFactor's lock first means concurrent wrong codes are
	// counted one at a time, so the limit can't be overshot, and the
	// warning is sent once.
	if _, err := q.GetTOTPSecretForUpdate(ctx, userID); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return codeCheck{}, fmt.Errorf("reading 2FA: %w", err)
	}
	if err := a.checkPaused(ctx, q, userID); err != nil {
		return codeCheck{}, err
	}
	reached, retry, err := a.limiter.Reached(ctx, limitWrongCodes, ip)
	if err != nil {
		return codeCheck{}, err
	}
	if reached {
		return codeCheck{}, pausedError{until: a.now().Add(retry)}
	}
	usedRecovery, err := a.checkSecondFactor(ctx, q, userID, code)
	if err == nil {
		return codeCheck{ok: true, usedRecovery: usedRecovery}, nil
	}
	if !errors.Is(err, errBadCode) {
		return codeCheck{}, err
	}

	now := a.now().UTC().Truncate(time.Microsecond)
	if err := q.DeleteOldTwoFactorFailures(ctx, db.DeleteOldTwoFactorFailuresParams{UserID: userID, Since: now.Add(-guessWindow)}); err != nil {
		return codeCheck{}, fmt.Errorf("deleting old 2FA failures: %w", err)
	}
	id, err := uuid.NewV7()
	if err != nil {
		return codeCheck{}, fmt.Errorf("generating 2FA failure ID: %w", err)
	}
	if err := q.CreateTwoFactorFailure(ctx, db.CreateTwoFactorFailureParams{ID: id, UserID: userID, Now: now}); err != nil {
		return codeCheck{}, fmt.Errorf("recording 2FA failure: %w", err)
	}
	// Counted outside the transaction, so it holds even if that rolls back.
	if _, _, err := a.limiter.Hit(ctx, limitWrongCodes, ip); err != nil {
		return codeCheck{}, err
	}
	err = a.checkPaused(ctx, q, userID)
	var paused pausedError
	if err != nil && !errors.As(err, &paused) {
		return codeCheck{}, err
	}
	return codeCheck{tripped: err != nil}, nil
}

type challengeJSON struct {
	TwoFactorRequired bool      `json:"two_factor_required"`
	ChallengeToken    string    `json:"challenge_token"`
	ExpiresAt         timestamp `json:"expires_at"`
}

// createChallenge starts a 2FA challenge for a user who has just proved
// their password, and returns its token.
func (a *Auth) createChallenge(ctx context.Context, q *db.Queries, userID uuid.UUID, client session.Client) (string, time.Time, error) {
	now := a.now().UTC().Truncate(time.Microsecond)
	if err := q.DeleteSpentTwoFactorChallenges(ctx, db.DeleteSpentTwoFactorChallengesParams{
		UserID: userID, Now: now, MaxFailedAttempts: maxChallengeAttempts,
	}); err != nil {
		return "", time.Time{}, fmt.Errorf("deleting spent 2FA challenges: %w", err)
	}
	id, err := uuid.NewV7()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("generating 2FA challenge ID: %w", err)
	}
	tok := token.New()
	expires := now.Add(challengeLifetime)
	if err := q.CreateTwoFactorChallenge(ctx, db.CreateTwoFactorChallengeParams{
		ID:        id,
		UserID:    userID,
		TokenHash: token.Hash(tok),
		Client:    string(client),
		ExpiresAt: expires,
		Now:       now,
	}); err != nil {
		return "", time.Time{}, fmt.Errorf("creating 2FA challenge: %w", err)
	}
	return tok, expires, nil
}

// writeChallenge starts a 2FA challenge and returns it in place of a
// session. While the user is at the guessing limit, it refuses instead.
func (a *Auth) writeChallenge(w http.ResponseWriter, r *http.Request, userID uuid.UUID, client session.Client) {
	if err := a.checkPaused(r.Context(), a.q, userID); err != nil {
		a.writeLoginCodeError(w, r, err)
		return
	}
	tok, expires, err := a.createChallenge(r.Context(), a.q, userID, client)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	a.logEvent(r, "auth: two-factor challenge started", userID)
	writeChallengeJSON(w, r, tok, expires)
}

func writeChallengeJSON(w http.ResponseWriter, r *http.Request, tok string, expires time.Time) {
	httpapi.WriteJSON(w, r, http.StatusOK, challengeJSON{TwoFactorRequired: true, ChallengeToken: tok, ExpiresAt: timestamp(expires)})
}

type verifyChallengeRequest struct {
	ChallengeToken string `json:"challenge_token"`
	Code           string `json:"code"`
}

var errChallengeInvalid = errors.New("two-factor challenge is invalid or expired")

// verifyChallenge finishes a 2FA login: with the challenge from the
// password step and a TOTP or recovery code, it starts the session.
func (a *Auth) verifyChallenge(w http.ResponseWriter, r *http.Request) {
	var req verifyChallengeRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return
	}
	var details []httpapi.FieldError
	if req.ChallengeToken == "" {
		details = append(details, httpapi.FieldError{Field: "challenge_token", Code: "required", Message: "Log in with your password first."})
	}
	if req.Code == "" {
		details = append(details, codeRequired)
	}
	if details != nil {
		writeValidationFailed(w, r, details)
		return
	}
	if !token.Valid(req.ChallengeToken) {
		a.writeLoginCodeError(w, r, errChallengeInvalid)
		return
	}

	ctx := r.Context()
	var (
		check codeCheck
		user  db.AuthUser
		tok   string
		s     session.Session
		left  int64
		// policy is set inside the transaction, from the user's roles.
		policy session.Policy
	)
	err := a.withTx(ctx, func(tx pgx.Tx) error {
		q := db.New(tx)
		ch, err := q.GetTwoFactorChallengeForUpdate(ctx, token.Hash(req.ChallengeToken))
		if errors.Is(err, pgx.ErrNoRows) {
			return errChallengeInvalid
		}
		if err != nil {
			return fmt.Errorf("reading 2FA challenge: %w", err)
		}
		now := a.now().UTC().Truncate(time.Microsecond)
		if ch.UsedAt != nil || !now.Before(ch.ExpiresAt) || ch.FailedAttempts >= maxChallengeAttempts {
			return errChallengeInvalid
		}
		var tf twoFactorState
		if user, tf, err = a.userWithTwoFactor(ctx, q, ch.UserID); err != nil {
			return err
		}
		policy = sessionPolicy(tf)

		if check, err = a.checkLoginCode(ctx, q, ch.UserID, req.Code, a.clientIP(r)); err != nil {
			return err
		}
		if !check.ok {
			if err := q.RecordTwoFactorChallengeFailure(ctx, db.RecordTwoFactorChallengeFailureParams{ID: ch.ID, Now: now}); err != nil {
				return fmt.Errorf("recording 2FA challenge failure: %w", err)
			}
			// Commit, so the wrong code is counted.
			return nil
		}

		if err := q.UseTwoFactorChallenge(ctx, db.UseTwoFactorChallengeParams{ID: ch.ID, Now: &now}); err != nil {
			return fmt.Errorf("using 2FA challenge: %w", err)
		}
		if check.usedRecovery {
			if left, err = q.CountUnusedRecoveryCodes(ctx, ch.UserID); err != nil {
				return fmt.Errorf("counting recovery codes: %w", err)
			}
		}
		ip, ua := httpapi.Client(r, a.trusted)
		tok, s, err = session.NewManager(tx, a.now).Create(ctx, ch.UserID, session.Meta{Client: session.Client(ch.Client), IP: ip, UserAgent: ua}, policy)
		return err
	})
	if err != nil {
		a.writeLoginCodeError(w, r, err)
		return
	}
	if !check.ok {
		a.event(r, EventLoginFailed, &user.ID, nil, map[string]string{"method": "two_factor"})
		a.wrongLoginCode(w, r, user, check)
		return
	}
	if check.usedRecovery {
		a.logEvent(r, "auth: recovery code used", user.ID)
		a.event(r, EventRecoveryCodeUsed, &user.ID, nil, nil)
		a.send(user.Email, a.emails.RecoveryCodeUsed, EmailData{AppName: a.appName, AppURL: a.appURL, RecoveryCodesLeft: int(left)}, uuid.Must(uuid.NewV7()))
	}
	a.logEvent(r, "auth: user logged in", user.ID)
	a.event(r, EventLoginSucceeded, &user.ID, nil, map[string]string{"method": "two_factor"})
	httpapi.WriteJSON(w, r, http.StatusCreated, newLoginResponse(toUserJSON(userFromRow(user)), tok, s))
}

// wrongLoginCode answers a wrong code entered to log in or reset a
// password, warning the user if it reached the guessing limit.
func (a *Auth) wrongLoginCode(w http.ResponseWriter, r *http.Request, user db.AuthUser, check codeCheck) {
	a.logEvent(r, "auth: wrong two-factor code", user.ID)
	if check.tripped {
		a.logEvent(r, "auth: two-factor guessing limit reached", user.ID)
		a.sendNotice(user.Email, a.emails.TwoFactorGuessing)
	}
	httpapi.WriteError(w, r, http.StatusUnauthorized, "invalid_two_factor_code", "That code isn't right. Check your authenticator app and try again.", nil)
}

// writeLoginCodeError writes the response for an error from logging in or
// resetting a password with 2FA.
func (a *Auth) writeLoginCodeError(w http.ResponseWriter, r *http.Request, err error) {
	var paused pausedError
	switch {
	case errors.As(err, &paused):
		secs := math.Ceil(paused.until.Sub(a.now()).Seconds())
		w.Header().Set("Retry-After", strconv.Itoa(max(int(secs), 1)))
		httpapi.WriteError(w, r, http.StatusTooManyRequests, "rate_limited", "Too many wrong codes. Wait a few minutes, then try again.", nil)
	case errors.Is(err, errChallengeInvalid):
		httpapi.WriteError(w, r, http.StatusUnauthorized, "two_factor_challenge_invalid", "This login has expired. Log in with your password again.", nil)
	default:
		httpapi.WriteInternalError(w, r, a.log, err)
	}
}

// ResetTwoFactor turns off a user's 2FA and ends all their sessions. It's
// for admin tooling and support, for a user who has lost both their
// authenticator and their recovery codes, after confirming who they are
// some other way. There's no endpoint for it. The user is emailed that 2FA
// was turned off. It does nothing for a user without 2FA. by is who's
// resetting it, for the security event log.
func (a *Auth) ResetTwoFactor(ctx context.Context, userID uuid.UUID, by Actor) error {
	var email string
	err := a.withTx(ctx, func(tx pgx.Tx) error {
		q := db.New(tx)
		secret, err := q.GetTOTPSecretForUpdate(ctx, userID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading 2FA: %w", err)
		}
		if secret.ConfirmedAt == nil {
			return nil
		}
		user, err := q.GetUserByID(ctx, userID)
		if err != nil {
			return fmt.Errorf("reading user: %w", err)
		}
		email = user.Email
		if err := q.DeleteTOTPSecret(ctx, userID); err != nil {
			return fmt.Errorf("deleting 2FA secret: %w", err)
		}
		if err := q.DeleteRecoveryCodes(ctx, userID); err != nil {
			return fmt.Errorf("deleting recovery codes: %w", err)
		}
		if err := q.DeleteTwoFactorChallenges(ctx, userID); err != nil {
			return fmt.Errorf("deleting 2FA challenges: %w", err)
		}
		_, err = session.NewManager(tx, a.now).RevokeAll(ctx, userID)
		return err
	})
	if err != nil {
		return fmt.Errorf("auth: resetting 2FA: %w", err)
	}
	if email != "" {
		a.log.InfoContext(ctx, "auth: two-factor reset", slog.String("user_id", userID.String()))
		a.adminEvent(ctx, by, Event{Type: EventTwoFactorReset, UserID: &userID})
		a.sendNotice(email, a.emails.TwoFactorDisabled)
	}
	return nil
}
