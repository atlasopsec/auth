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
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/httpapi"
	"github.com/atlasopsec/auth/internal/oauth"
)

// providerNames are the providers' names as shown to users.
var providerNames = map[string]string{
	providerGoogle: "Google",
	providerGitHub: "GitHub",
	providerApple:  "Apple",
}

type oauthAccountJSON struct {
	ID        uuid.UUID `json:"id"`
	Provider  string    `json:"provider"`
	Email     string    `json:"email"`
	CreatedAt timestamp `json:"created_at"`
}

func toOAuthAccountJSON(acct db.AuthOauthAccount) oauthAccountJSON {
	return oauthAccountJSON{ID: acct.ID, Provider: acct.Provider, Email: acct.Email, CreatedAt: timestamp(acct.CreatedAt)}
}

type oauthAccountListJSON struct {
	Data []oauthAccountJSON `json:"data"`
	// NextCursor is always null: a user has at most one account per
	// provider. It's there for the list format every endpoint shares.
	NextCursor *string `json:"next_cursor"`
}

// listOAuthAccounts lists the providers the user can sign in with.
func (a *Auth) listOAuthAccounts(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	rows, err := a.q.ListOAuthAccounts(r.Context(), c.user.ID)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	list := oauthAccountListJSON{Data: []oauthAccountJSON{}}
	for _, row := range rows {
		list.Data = append(list.Data, toOAuthAccountJSON(row))
	}
	httpapi.WriteJSON(w, r, http.StatusOK, list)
}

type startLinkRequest struct {
	startOAuthRequest
	CurrentPassword string `json:"current_password"`
}

// startLink starts linking a provider to the logged-in user. It takes the
// current password if the account has one: linking adds a way in, and is
// how someone with a stolen session would make their access last.
func (a *Auth) startLink(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	var req startLinkRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return
	}
	row, err := a.q.GetUserByID(r.Context(), c.user.ID)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, fmt.Errorf("reading user: %w", err))
		return
	}
	challenge, details := a.checkFlowStart(req.startOAuthRequest)
	hasPassword := row.PasswordHash != nil
	if hasPassword && req.CurrentPassword == "" {
		details = append(details, currentPasswordRequired)
	}
	if details != nil {
		writeValidationFailed(w, r, details)
		return
	}
	if hasPassword && !a.passwordChecked(w, r, c.user.ID, req.CurrentPassword) {
		return
	}
	linked, err := a.q.UserHasOAuthProvider(r.Context(), db.UserHasOAuthProviderParams{UserID: c.user.ID, Provider: req.Provider})
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	if linked {
		writeOAuthAlreadyLinked(w, r)
		return
	}
	a.writeNewFlow(w, r, req.startOAuthRequest, challenge, "link", &c.user.ID)
}

// sessionUserID returns the user of the request's session, if it has a
// valid one. Finishing a flow is public, but finishing a link flow needs
// the session that started it.
func (a *Auth) sessionUserID(r *http.Request) *uuid.UUID {
	tok, ok := bearerToken(r)
	if !ok {
		return nil
	}
	s, err := a.sessions.Validate(r.Context(), tok)
	if err != nil {
		return nil
	}
	return &s.UserID
}

var (
	errOAuthAccountInUse  = errors.New("provider account is linked to another user")
	errOAuthAlreadyLinked = errors.New("user already has an account with this provider")
)

// finishLink links the provider account a link flow identified to the user
// who started the flow, and emails them about it.
func (a *Auth) finishLink(w http.ResponseWriter, r *http.Request, flow db.AuthOauthFlow, id oauth.Identity) {
	ctx := r.Context()
	userID := *flow.UserID
	email := strings.TrimSpace(id.Email)
	if _, ok := checkEmail(email); !ok {
		// Shown in settings only, so a missing or odd address isn't fatal.
		email = ""
	}
	var acct db.AuthOauthAccount
	err := a.inTx(ctx, func(q *db.Queries) error {
		existing, err := q.GetOAuthAccount(ctx, db.GetOAuthAccountParams{Provider: flow.Provider, ProviderUserID: id.Subject})
		switch {
		case err == nil && existing.UserID == userID:
			// Linked already, e.g. by a retried request.
			acct = existing
			return nil
		case err == nil:
			// Never moved silently: its owner would lose a way in.
			return errOAuthAccountInUse
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("reading OAuth account: %w", err)
		}
		aid, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("generating OAuth account ID: %w", err)
		}
		now := a.now().UTC().Truncate(time.Microsecond)
		err = q.CreateOAuthAccount(ctx, db.CreateOAuthAccountParams{
			ID: aid, UserID: userID, Provider: flow.Provider, ProviderUserID: id.Subject, Email: email, Now: now,
		})
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" && pgErr.ConstraintName == "oauth_accounts_user_provider_key" {
			// Another account with this provider was linked since the
			// flow started.
			return errOAuthAlreadyLinked
		}
		if err != nil {
			return fmt.Errorf("linking OAuth account: %w", err)
		}
		acct = db.AuthOauthAccount{ID: aid, UserID: userID, Provider: flow.Provider, ProviderUserID: id.Subject, Email: email, CreatedAt: now, UpdatedAt: now}
		return nil
	})
	switch {
	case errors.Is(err, errOAuthAccountInUse):
		httpapi.WriteError(w, r, http.StatusConflict, "oauth_account_in_use",
			"That "+providerNames[flow.Provider]+" account is already linked to another account here.", nil)
		return
	case errors.Is(err, errOAuthAlreadyLinked):
		writeOAuthAlreadyLinked(w, r)
		return
	case err != nil:
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	a.logEvent(r, "auth: "+flow.Provider+" linked", userID)
	a.event(r, EventOAuthLinked, &userID, nil, map[string]string{"provider": flow.Provider})
	a.sendProviderNotice(ctx, userID, a.emails.OAuthLinked, flow.Provider)
	httpapi.WriteJSON(w, r, http.StatusCreated, toOAuthAccountJSON(acct))
}

func writeOAuthAlreadyLinked(w http.ResponseWriter, r *http.Request) {
	httpapi.WriteError(w, r, http.StatusConflict, "oauth_already_linked",
		"An account with this provider is already linked. Unlink it first.", nil)
}

var errLastLoginMethod = errors.New("the only way left to log in")

// unlink removes a provider from the logged-in user. It takes the current
// password if the account has one, and refuses to remove the only way left
// to log in.
func (a *Auth) unlink(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	acctID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeNotFound(w, r)
		return
	}
	var req passwordRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return
	}
	ctx := r.Context()
	row, err := a.q.GetUserByID(ctx, c.user.ID)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, fmt.Errorf("reading user: %w", err))
		return
	}
	if row.PasswordHash != nil {
		if req.CurrentPassword == "" {
			writeValidationFailed(w, r, []httpapi.FieldError{currentPasswordRequired})
			return
		}
		if !a.passwordChecked(w, r, c.user.ID, req.CurrentPassword) {
			return
		}
	}
	var provider string
	err = a.inTx(ctx, func(q *db.Queries) error {
		// Locking the user serializes unlinks, so two at once can't each
		// leave the other as the last way in, and then remove it.
		if _, err := q.LockUser(ctx, c.user.ID); err != nil {
			return fmt.Errorf("locking user: %w", err)
		}
		user, err := q.GetUserByID(ctx, c.user.ID)
		if err != nil {
			return fmt.Errorf("reading user: %w", err)
		}
		if provider, err = q.DeleteOAuthAccount(ctx, db.DeleteOAuthAccountParams{ID: acctID, UserID: c.user.ID}); err != nil {
			return err
		}
		if user.PasswordHash != nil {
			return nil
		}
		left, err := q.CountOAuthAccounts(ctx, c.user.ID)
		if err != nil {
			return fmt.Errorf("counting OAuth accounts: %w", err)
		}
		if left == 0 {
			return errLastLoginMethod
		}
		return nil
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		writeNotFound(w, r)
		return
	case errors.Is(err, errLastLoginMethod):
		httpapi.WriteError(w, r, http.StatusConflict, "last_login_method",
			"This is your only way to log in. Set a password or link another account first.", nil)
		return
	case err != nil:
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	a.logEvent(r, "auth: "+provider+" unlinked", c.user.ID)
	a.event(r, EventOAuthUnlinked, &c.user.ID, nil, map[string]string{"provider": provider})
	a.sendProviderNotice(ctx, c.user.ID, a.emails.OAuthUnlinked, provider)
	w.WriteHeader(http.StatusNoContent)
}

// sendProviderNotice emails a user about a change to their linked
// providers.
func (a *Auth) sendProviderNotice(ctx context.Context, userID uuid.UUID, tmpl func(EmailData) (string, string, string), provider string) {
	user, err := a.q.GetUserByID(ctx, userID)
	if err != nil {
		a.log.ErrorContext(ctx, "auth: reading user for a notice",
			slog.String("user_id", userID.String()),
			slog.String("error", err.Error()))
		return
	}
	a.send(user.Email, tmpl, EmailData{AppName: a.appName, AppURL: a.appURL, Provider: providerNames[provider]}, uuid.Must(uuid.NewV7()))
}
