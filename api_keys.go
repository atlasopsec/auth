package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/atlasopsec/auth/internal/apikey"
	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/httpapi"
	"github.com/atlasopsec/auth/rbac"
)

// Errors from the API key methods (docs/api.md §18).
var (
	// ErrAPIKeysOff means Config.APIKeyPermissions is empty.
	ErrAPIKeysOff = errors.New("auth: API keys are off: set Config.APIKeyPermissions")
	// ErrAPIKeyNotFound means the user has no key with the ID.
	ErrAPIKeyNotFound = errors.New("auth: no such API key")
	// ErrInvalidAPIKeyName means a key's name is blank or over 100
	// characters.
	ErrInvalidAPIKeyName = errors.New("auth: API key name must be 1 to 100 characters")
	// ErrAPIKeyPermission means a key would carry no permission, or one
	// that isn't in Config.APIKeyPermissions or that the user's app role
	// doesn't have.
	ErrAPIKeyPermission = errors.New("auth: API key permissions must be ones keys may carry and the user's role has")
	// ErrAPIKeyExpiry means a key's expiry is in the past, or more than a
	// year away.
	ErrAPIKeyExpiry = errors.New("auth: API key must expire within 365 days")
	// ErrTooManyAPIKeys means the user already has MaxAPIKeys keys that
	// haven't expired.
	ErrTooManyAPIKeys = errors.New("auth: too many API keys")
)

const (
	// DefaultAPIKeyLifetime is how long a key lasts when NewAPIKey doesn't
	// say.
	DefaultAPIKeyLifetime = 90 * 24 * time.Hour
	// MaxAPIKeyLifetime is the longest a key can last. No key lasts
	// forever.
	MaxAPIKeyLifetime = 365 * 24 * time.Hour
	// MaxAPIKeys is how many keys that haven't expired a user may have.
	MaxAPIKeys = 10

	maxAPIKeyName = 100
	// keyTouchEvery is how often a key's last use is written, so a busy
	// key doesn't write on every request.
	keyTouchEvery = time.Minute
	// maxListedKeys bounds ListAPIKeys. A user has at most MaxAPIKeys that
	// work; expired ones wait for cleanup.
	maxListedKeys = 100
)

// APIKey is an API key's details. It never contains the key or its hash.
type APIKey struct {
	ID     uuid.UUID
	UserID uuid.UUID
	Name   string
	// Hint is the first characters of the key after the prefix, to tell
	// keys apart.
	Hint string
	// Permissions are what the key may do, as long as its owner's role
	// still has them and they're still in Config.APIKeyPermissions.
	Permissions []rbac.Permission
	ExpiresAt   time.Time
	// LastUsedAt and LastUsedIP are when and from where the key was last
	// used, to the minute; nil if it never has been.
	LastUsedAt *time.Time
	LastUsedIP *netip.Addr
	CreatedAt  time.Time
}

// NewAPIKey is a key CreateAPIKey creates.
type NewAPIKey struct {
	// Name says what the key is for, e.g. "Nightly blocklist sync": 1 to
	// 100 characters.
	Name string
	// Permissions are what the key may do: at least one, each in
	// Config.APIKeyPermissions and held by the user's app role.
	Permissions []rbac.Permission
	// ExpiresAt is when the key stops working: in the future, and at most
	// MaxAPIKeyLifetime away. Zero means DefaultAPIKeyLifetime from now.
	ExpiresAt time.Time
}

// checkAPIKeyConfig checks Config.APIKeyPermissions and APIKeyPrefix.
func checkAPIKeyConfig(cfg Config) error {
	if len(cfg.APIKeyPermissions) == 0 {
		if cfg.APIKeyPrefix != "" {
			return errors.New("auth: Config.APIKeyPrefix is set, but Config.APIKeyPermissions is empty")
		}
		return nil
	}
	if !apikey.ValidPrefix(cfg.APIKeyPrefix) {
		return errors.New("auth: Config.APIKeyPrefix must be 3 to 20 lowercase letters, digits, and underscores, starting with a letter")
	}
	for _, p := range cfg.APIKeyPermissions {
		if p == rbac.All {
			return errors.New(`auth: Config.APIKeyPermissions can't contain "*": list each permission keys may carry`)
		}
		// Keys work only under Require, which checks app roles.
		if !cfg.AppRoles.Mentions(p) {
			return fmt.Errorf("auth: Config.APIKeyPermissions: no role in Config.AppRoles has %q", p)
		}
	}
	return nil
}

// CreateAPIKey creates a key for userID and returns it, with the key
// itself: the only time it's available. Store it or hand it over at once.
//
// Like the other admin methods it trusts its caller to decide who may make
// a key for whom, but it still checks the key: its name, that each
// permission is one keys may carry and the user's app role has now, its
// expiry, and that the user has fewer than MaxAPIKeys. It sends no email.
// by is who's making the change, for the security event log.
func (a *Auth) CreateAPIKey(ctx context.Context, userID uuid.UUID, k NewAPIKey, by Actor) (APIKey, string, error) {
	if a.keyPrefix == "" {
		return APIKey{}, "", ErrAPIKeysOff
	}
	name := strings.TrimSpace(k.Name)
	if name == "" || utf8.RuneCountInString(name) > maxAPIKeyName {
		return APIKey{}, "", ErrInvalidAPIKeyName
	}
	perms := slices.Clone(k.Permissions)
	slices.Sort(perms)
	perms = slices.Compact(perms)
	if len(perms) == 0 {
		return APIKey{}, "", ErrAPIKeyPermission
	}
	now := a.now().UTC().Truncate(time.Microsecond)
	expires := k.ExpiresAt.UTC().Truncate(time.Microsecond)
	if k.ExpiresAt.IsZero() {
		expires = now.Add(DefaultAPIKeyLifetime)
	}
	if !expires.After(now) || expires.After(now.Add(MaxAPIKeyLifetime)) {
		return APIKey{}, "", ErrAPIKeyExpiry
	}
	id, err := uuid.NewV7()
	if err != nil {
		return APIKey{}, "", fmt.Errorf("auth: generating API key ID: %w", err)
	}
	key, hash, hint := apikey.New(a.keyPrefix)

	var created APIKey
	err = a.inTx(ctx, func(q *db.Queries) error {
		// Under the user's lock, so two requests can't both pass the limit,
		// and the role can't change between the check and the insert.
		if _, err := q.LockUser(ctx, userID); err != nil {
			return fmt.Errorf("locking user: %w", err)
		}
		role, err := q.GetUserRole(ctx, userID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("reading app role: %w", err)
		}
		for _, p := range perms {
			if !slices.Contains(a.keyPerms, p) || !a.appRoles.Has(role, p) {
				return ErrAPIKeyPermission
			}
		}
		n, err := q.CountActiveUserAPIKeys(ctx, db.CountActiveUserAPIKeysParams{UserID: userID, Now: now})
		if err != nil {
			return fmt.Errorf("counting API keys: %w", err)
		}
		if n >= MaxAPIKeys {
			return ErrTooManyAPIKeys
		}
		row, err := q.CreateAPIKey(ctx, db.CreateAPIKeyParams{
			ID:          id,
			UserID:      userID,
			Name:        name,
			KeyHash:     hash,
			Hint:        hint,
			Permissions: permStrings(perms),
			ExpiresAt:   expires,
			Now:         now,
		})
		if err != nil {
			return fmt.Errorf("creating API key: %w", err)
		}
		created = apiKeyFromRow(row)
		return nil
	})
	if err != nil {
		return APIKey{}, "", apiKeyError("creating API key", err)
	}
	a.log.InfoContext(ctx, "auth: API key created",
		slog.String("user_id", userID.String()),
		slog.String("api_key_id", id.String()))
	a.adminEvent(ctx, by, Event{Type: EventAPIKeyCreated, UserID: &userID, Metadata: map[string]string{
		"api_key_id":  id.String(),
		"permissions": strings.Join(permStrings(perms), ","),
	}})
	return created, key, nil
}

// ListAPIKeys returns userID's keys, newest first, including any that
// have expired but haven't been cleaned up yet.
func (a *Auth) ListAPIKeys(ctx context.Context, userID uuid.UUID) ([]APIKey, error) {
	rows, err := a.q.ListUserAPIKeys(ctx, db.ListUserAPIKeysParams{UserID: userID, MaxRows: maxListedKeys})
	if err != nil {
		return nil, fmt.Errorf("auth: listing API keys: %w", err)
	}
	keys := make([]APIKey, len(rows))
	for i, r := range rows {
		keys[i] = apiKeyFromRow(r)
	}
	return keys, nil
}

// RevokeAPIKey deletes one of userID's keys, which stops working at once.
// It returns ErrAPIKeyNotFound if userID has no key keyID. by is who's
// making the change, for the security event log.
func (a *Auth) RevokeAPIKey(ctx context.Context, userID, keyID uuid.UUID, by Actor) error {
	_, err := a.q.DeleteAPIKey(ctx, db.DeleteAPIKeyParams{ID: keyID, UserID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrAPIKeyNotFound
	}
	if err != nil {
		return fmt.Errorf("auth: revoking API key: %w", err)
	}
	a.adminEvent(ctx, by, revokedKeyEvent(userID, keyID))
	return nil
}

// RevokeUserAPIKeys deletes every key userID has. by is who's making the
// change, for the security event log.
func (a *Auth) RevokeUserAPIKeys(ctx context.Context, userID uuid.UUID, by Actor) error {
	ids, err := deleteUserAPIKeys(ctx, a.q, userID)
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	for _, id := range ids {
		a.adminEvent(ctx, by, revokedKeyEvent(userID, id))
	}
	return nil
}

// deleteUserAPIKeys deletes userID's keys through q, which may be in a
// transaction, and returns their IDs for the event log.
func deleteUserAPIKeys(ctx context.Context, q *db.Queries, userID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := q.DeleteUserAPIKeys(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("revoking API keys: %w", err)
	}
	ids := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	return ids, nil
}

func revokedKeyEvent(userID, keyID uuid.UUID) Event {
	return Event{Type: EventAPIKeyRevoked, UserID: &userID, Metadata: map[string]string{"api_key_id": keyID.String()}}
}

// APIKeyFrom returns the key a request under Require was made with. ok is
// false for a request made with a session, and outside Require.
func APIKeyFrom(ctx context.Context) (k APIKey, ok bool) {
	c, ok := ctx.Value(contextKey{}).(current)
	if !ok || c.apiKey == nil {
		return APIKey{}, false
	}
	return *c.apiKey, true
}

// keyHash returns the hash of the API key r carries, and false if it
// carries none: keys are off, or its bearer token isn't shaped like a key.
// Such a token is then checked as a session token, and refused.
func (a *Auth) keyHash(r *http.Request) ([]byte, bool) {
	if a.keyPrefix == "" {
		return nil, false
	}
	tok, ok := bearerToken(r)
	if !ok {
		return nil, false
	}
	return apikey.Hash(a.keyPrefix, tok)
}

// serveKey is Require for a request made with an API key. The key grants
// only the permissions it lists that are still allowed for keys and that
// its owner's app role has now, checked on every request, so a demoted
// owner's keys lose what the owner lost at once.
func (a *Auth) serveKey(w http.ResponseWriter, r *http.Request, hash []byte, permission rbac.Permission, h http.Handler) {
	ctx := r.Context()
	subject := a.clientIP(r)
	// Wrong keys count with failed logins, so nobody can guess keys from one
	// address any faster than passwords.
	reached, retry, err := a.limiter.Reached(ctx, limitLogin, subject)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	if reached {
		writeRateLimited(w, r, retry)
		return
	}
	now := a.now()
	row, err := a.q.GetAPIKeyByHash(ctx, hash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		httpapi.WriteInternalError(w, r, a.log, fmt.Errorf("looking up API key: %w", err))
		return
	}
	// An expired key is refused like an unknown one. Cleanup deletes it.
	if errors.Is(err, pgx.ErrNoRows) || !now.Before(row.ExpiresAt) {
		if _, _, err := a.limiter.Hit(ctx, limitLogin, subject); err != nil {
			httpapi.WriteInternalError(w, r, a.log, err)
			return
		}
		writeUnauthenticated(w, r)
		return
	}
	user, tf, err := a.userWithTwoFactor(ctx, a.q, row.UserID)
	if errors.Is(err, pgx.ErrNoRows) {
		// The user was deleted after the lookup; their keys went with them.
		writeUnauthenticated(w, r)
		return
	}
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	// A user who must set up 2FA can do nothing until they have, with a key
	// as with a session.
	if tf.required && !tf.enabled {
		httpapi.WriteError(w, r, http.StatusForbidden, "two_factor_setup_required", "Set up two-factor authentication to continue.", nil)
		return
	}
	role, err := a.q.GetUserRole(ctx, row.UserID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	if !a.appRoles.Defines(role) {
		a.warnUndefinedRole(r, role, row.UserID)
	}
	key := apiKeyFromRow(row)
	can := func(p rbac.Permission) bool {
		return slices.Contains(key.Permissions, p) && slices.Contains(a.keyPerms, p) && a.appRoles.Has(role, p)
	}
	if !can(permission) {
		writeForbidden(w, r)
		return
	}
	if row.LastUsedAt == nil || now.Sub(*row.LastUsedAt) >= keyTouchEvery {
		ip, _ := httpapi.Client(r, a.trusted)
		usedBefore := now.Add(-keyTouchEvery)
		if err := a.q.TouchAPIKey(ctx, db.TouchAPIKeyParams{Now: &now, Ip: ip, ID: row.ID, UsedBefore: &usedBefore}); err != nil {
			httpapi.WriteInternalError(w, r, a.log, fmt.Errorf("recording API key use: %w", err))
			return
		}
	}
	h.ServeHTTP(w, withCurrent(r, current{user: userFromRow(user), apiKey: &key, can: can}))
}

func apiKeyFromRow(r db.AuthApiKey) APIKey {
	perms := make([]rbac.Permission, len(r.Permissions))
	for i, p := range r.Permissions {
		perms[i] = rbac.Permission(p)
	}
	k := APIKey{
		ID:          r.ID,
		UserID:      r.UserID,
		Name:        r.Name,
		Hint:        r.Hint,
		Permissions: perms,
		ExpiresAt:   r.ExpiresAt.UTC(),
		LastUsedIP:  r.LastUsedIp,
		CreatedAt:   r.CreatedAt.UTC(),
	}
	if r.LastUsedAt != nil {
		t := r.LastUsedAt.UTC()
		k.LastUsedAt = &t
	}
	return k
}

func apiKeyError(doing string, err error) error {
	for _, known := range []error{ErrAPIKeyPermission, ErrTooManyAPIKeys} {
		if errors.Is(err, known) {
			return fmt.Errorf("auth: %s: %w", doing, known)
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("auth: %s: %w", doing, ErrUserNotFound)
	}
	return fmt.Errorf("auth: %s: %w", doing, err)
}
