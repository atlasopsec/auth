package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/atlasopsec/auth/internal/httpapi"
	"github.com/atlasopsec/auth/internal/session"
)

type contextKey struct{}

// current is what Authenticated puts in the request context.
type current struct {
	user    User
	session session.Session
}

// Authenticated wraps h so it only runs for a request with a valid session
// token in its Authorization: Bearer header. Otherwise it responds 401 with
// the standard error format. Inside h, UserFrom and SessionFrom return the
// logged-in user and their session.
func (a *Auth) Authenticated(h http.Handler) http.Handler {
	return httpapi.WithRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := bearerToken(r)
		if !ok {
			writeUnauthenticated(w, r)
			return
		}
		s, err := a.sessions.Validate(r.Context(), tok)
		if errors.Is(err, session.ErrInvalid) {
			writeUnauthenticated(w, r)
			return
		}
		if err != nil {
			httpapi.WriteInternalError(w, r, a.log, err)
			return
		}
		row, err := a.q.GetUserByID(r.Context(), s.UserID)
		if errors.Is(err, pgx.ErrNoRows) {
			// The user was deleted between the two queries; their sessions
			// went with them.
			writeUnauthenticated(w, r)
			return
		}
		if err != nil {
			httpapi.WriteInternalError(w, r, a.log, err)
			return
		}
		ctx := context.WithValue(r.Context(), contextKey{}, current{user: userFromRow(row), session: s})
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
}

// Public marks h as intentionally open to logged-out users. It doesn't
// change how h behaves; it makes the choice explicit where routes are
// registered, so a route that's open by accident stands out.
func (a *Auth) Public(h http.Handler) http.Handler {
	return public{h}
}

type public struct{ http.Handler }

// UserFrom returns the logged-in user. ok is false outside Authenticated,
// which is a bug in the calling code.
func UserFrom(ctx context.Context) (u User, ok bool) {
	c, ok := ctx.Value(contextKey{}).(current)
	return c.user, ok
}

// SessionFrom returns the current session. ok is false outside
// Authenticated, which is a bug in the calling code.
func SessionFrom(ctx context.Context) (s Session, ok bool) {
	c, ok := ctx.Value(contextKey{}).(current)
	if !ok {
		return Session{}, false
	}
	return sessionFromInternal(c.session), true
}

func currentFrom(ctx context.Context) (current, bool) {
	c, ok := ctx.Value(contextKey{}).(current)
	return c, ok
}

// bearerToken returns the token in an "Authorization: Bearer <token>"
// header. The scheme is case-insensitive, as HTTP requires.
func bearerToken(r *http.Request) (string, bool) {
	scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || tok == "" {
		return "", false
	}
	return tok, true
}

func writeUnauthenticated(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	httpapi.WriteError(w, r, http.StatusUnauthorized, "unauthenticated", "You need to log in.", nil)
}
