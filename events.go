package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/httpapi"
)

// Event types in the security event log. More may be added; existing ones
// never change.
const (
	// EventLoginSucceeded is a session started. Metadata "method" is
	// "password", "verification_link", "two_factor", "google", "github",
	// or "apple".
	EventLoginSucceeded = "login_succeeded"
	// EventLoginFailed is a wrong password or 2FA code at login. Metadata
	// "method" is "password" or "two_factor". UserID is nil for an email
	// without an account.
	EventLoginFailed      = "login_failed"
	EventLogout           = "logout"
	EventLogoutEverywhere = "logout_everywhere"
	// EventSessionEnded is a user ending one of their other sessions.
	EventSessionEnded             = "session_ended"
	EventPasswordChanged          = "password_changed"
	EventPasswordReset            = "password_reset"
	EventTwoFactorEnabled         = "two_factor_enabled"
	EventTwoFactorDisabled        = "two_factor_disabled"
	EventTwoFactorReset           = "two_factor_reset"
	EventRecoveryCodeUsed         = "recovery_code_used"
	EventRecoveryCodesRegenerated = "recovery_codes_regenerated"
	// EventOAuthLinked and EventOAuthUnlinked have metadata "provider".
	EventOAuthLinked   = "oauth_linked"
	EventOAuthUnlinked = "oauth_unlinked"
	EventEmailChanged  = "email_changed"
	// EventAppRoleChanged has metadata "role" ("" when removed).
	EventAppRoleChanged = "app_role_changed"
	// EventOrgRoleChanged and EventMemberAdded have metadata
	// "organization_id" and "role"; EventMemberRemoved has
	// "organization_id". ActorID is who made the change.
	EventOrgRoleChanged = "org_role_changed"
	EventMemberAdded    = "member_added"
	EventMemberRemoved  = "member_removed"
	// EventTwoFactorRequiredChanged has metadata "required" ("true" or
	// "false").
	EventTwoFactorRequiredChanged = "two_factor_required_changed"
)

// Event is one entry in the security event log. It never contains
// passwords, tokens, codes, or email addresses.
type Event struct {
	ID uuid.UUID
	// UserID is who it happened to. It's nil for a failed login with an
	// unknown email, and once the user is deleted.
	UserID *uuid.UUID
	// ActorID is who did it, when that's someone else.
	ActorID *uuid.UUID
	// Type is one of the Event constants.
	Type      string
	IP        *netip.Addr
	UserAgent string
	Metadata  map[string]string
	CreatedAt time.Time
}

// eventRetention is how long events are kept before cleanup deletes them.
const eventRetention = 365 * 24 * time.Hour

// eventPageSize is how many events Events returns at a time.
const eventPageSize = 50

// event records an event that happened in request r, with the client's IP
// and user agent.
func (a *Auth) event(r *http.Request, typ string, userID, actorID *uuid.UUID, metadata map[string]string) {
	ip, ua := httpapi.Client(r, a.trusted)
	a.recordEvent(r.Context(), Event{UserID: userID, ActorID: actorID, Type: typ, IP: ip, UserAgent: ua, Metadata: metadata})
}

// recordEvent stores e and runs Hooks.OnEvent. It's best effort: the action
// already happened, so a failure to record is logged, not returned.
func (a *Auth) recordEvent(ctx context.Context, e Event) {
	id, err := uuid.NewV7()
	if err == nil {
		e.ID = id
		e.CreatedAt = a.now().UTC().Truncate(time.Microsecond)
		err = a.insertEvent(ctx, e)
	}
	if err != nil {
		a.log.ErrorContext(ctx, "auth: recording security event",
			slog.String("request_id", httpapi.RequestIDFrom(ctx)),
			slog.String("event", e.Type),
			slog.String("error", err.Error()))
		return
	}
	if a.hooks.OnEvent != nil {
		a.hooks.OnEvent(ctx, e)
	}
}

func (a *Auth) insertEvent(ctx context.Context, e Event) error {
	if e.Metadata == nil {
		e.Metadata = map[string]string{}
	}
	meta, err := json.Marshal(e.Metadata)
	if err != nil {
		return fmt.Errorf("encoding metadata: %w", err)
	}
	var ua *string
	if e.UserAgent != "" {
		s := truncateRunes(strings.ToValidUTF8(e.UserAgent, "�"), 512)
		ua = &s
	}
	if err := a.q.CreateAuthEvent(ctx, db.CreateAuthEventParams{
		ID: e.ID, UserID: e.UserID, ActorID: e.ActorID, Event: e.Type, Ip: e.IP, UserAgent: ua, Metadata: meta, Now: e.CreatedAt,
	}); err != nil {
		return fmt.Errorf("inserting: %w", err)
	}
	return nil
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// EventPage is a page of a user's events, newest first.
type EventPage struct {
	Events []Event
	// NextCursor fetches the next page with Events; it's empty on the
	// last page.
	NextCursor string
}

// ErrBadCursor means a cursor passed to Events wasn't one it returned.
var ErrBadCursor = errors.New("auth: bad cursor")

// Events returns a page of a user's security events, newest first, 50 at a
// time. Pass "" for the first page, then each page's NextCursor. It's for
// admin tooling and support; there's no endpoint for it.
func (a *Auth) Events(ctx context.Context, userID uuid.UUID, cursor string) (EventPage, error) {
	var before *uuid.UUID
	if cursor != "" {
		id, err := uuid.Parse(cursor)
		if err != nil {
			return EventPage{}, ErrBadCursor
		}
		before = &id
	}
	rows, err := a.q.ListAuthEvents(ctx, db.ListAuthEventsParams{UserID: &userID, Before: before, PageSize: eventPageSize + 1})
	if err != nil {
		return EventPage{}, fmt.Errorf("auth: listing events: %w", err)
	}
	var page EventPage
	if len(rows) > eventPageSize {
		rows = rows[:eventPageSize]
		page.NextCursor = rows[len(rows)-1].ID.String()
	}
	page.Events = make([]Event, 0, len(rows))
	for _, row := range rows {
		e := Event{ID: row.ID, UserID: row.UserID, ActorID: row.ActorID, Type: row.Event, IP: row.Ip, CreatedAt: row.CreatedAt.UTC()}
		if row.UserAgent != nil {
			e.UserAgent = *row.UserAgent
		}
		if err := json.Unmarshal(row.Metadata, &e.Metadata); err != nil {
			return EventPage{}, fmt.Errorf("auth: reading event metadata: %w", err)
		}
		page.Events = append(page.Events, e)
	}
	return page, nil
}
