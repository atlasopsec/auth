package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/httpapi"
	"github.com/atlasopsec/auth/internal/session"
	"github.com/atlasopsec/auth/rbac"
)

// OwnerRole is the organization role that always has every permission.
// Config.OrgRoles must define it, and every organization keeps at least
// one owner.
const OwnerRole = "owner"

// OrgHeader names the organization a RequireOrg request is for.
const OrgHeader = "X-Organization-ID"

type contextKey struct{}

// current is what the auth wrappers put in the request context.
type current struct {
	user    User
	session session.Session
	// org is set by RequireOrg.
	org *Org
	// can checks a permission against the role Require or RequireOrg
	// looked up. It's nil under Authenticated, where Can is always false.
	can func(rbac.Permission) bool
}

// guarded marks a handler as wrapped by one of the module's access rules,
// for Protect.
type guarded struct{ http.Handler }

// Authenticated wraps h so it only runs for a request with a valid session
// token in its Authorization: Bearer header. Otherwise it responds 401 with
// the standard error format. Inside h, UserFrom and SessionFrom return the
// logged-in user and their session.
func (a *Auth) Authenticated(h http.Handler) http.Handler {
	return guarded{httpapi.WithRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := a.authenticate(w, r)
		if !ok {
			return
		}
		h.ServeHTTP(w, withCurrent(r, c))
	}))}
}

// authenticate checks the request's session. If it isn't valid, it writes
// the error response and returns false.
func (a *Auth) authenticate(w http.ResponseWriter, r *http.Request) (current, bool) {
	tok, ok := bearerToken(r)
	if !ok {
		writeUnauthenticated(w, r)
		return current{}, false
	}
	s, err := a.sessions.Validate(r.Context(), tok)
	if errors.Is(err, session.ErrInvalid) {
		writeUnauthenticated(w, r)
		return current{}, false
	}
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return current{}, false
	}
	row, err := a.q.GetUserByID(r.Context(), s.UserID)
	if errors.Is(err, pgx.ErrNoRows) {
		// The user was deleted between the two queries; their sessions
		// went with them.
		writeUnauthenticated(w, r)
		return current{}, false
	}
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return current{}, false
	}
	return current{user: userFromRow(row), session: s}, true
}

func withCurrent(r *http.Request, c current) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), contextKey{}, c))
}

// Require wraps h so it only runs for a logged-in user whose app role
// (Config.AppRoles) grants permission. Otherwise it responds 401 or
// 403 forbidden.
//
// It panics if no app role lists permission, which catches a misspelled
// permission when the route is registered rather than denying it silently.
func (a *Auth) Require(permission rbac.Permission, h http.Handler) http.Handler {
	if !a.appRoles.Mentions(permission) {
		panic(fmt.Sprintf("auth: Require(%q): no role in Config.AppRoles has this permission; is it misspelled?", permission))
	}
	return guarded{httpapi.WithRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := a.authenticate(w, r)
		if !ok {
			return
		}
		role, err := a.q.GetUserRole(r.Context(), c.user.ID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			httpapi.WriteInternalError(w, r, a.log, err)
			return
		}
		a.warnUndefinedRole(r, a.appRoles, role, c.user.ID)
		c.can = func(p rbac.Permission) bool { return a.appRoles.Has(role, p) }
		if !c.can(permission) {
			writeForbidden(w, r)
			return
		}
		h.ServeHTTP(w, withCurrent(r, c))
	}))}
}

// RequireOrg wraps h so it only runs for a logged-in member of the
// organization named in the X-Organization-ID header, whose role there
// (Config.OrgRoles) grants permission. It responds 400 if the header is
// missing or malformed, 404 if the organization doesn't exist or the user
// isn't a member (so outsiders can't tell which), and 403 forbidden if the
// role lacks the permission. Inside h, OrgFrom returns the organization.
//
// It panics if Config.OrgRoles isn't set, or if no role lists permission.
func (a *Auth) RequireOrg(permission rbac.Permission, h http.Handler) http.Handler {
	if a.orgRoles == nil {
		panic("auth: RequireOrg needs Config.OrgRoles")
	}
	if !a.orgRoles.Mentions(permission) {
		panic(fmt.Sprintf("auth: RequireOrg(%q): no role in Config.OrgRoles has this permission; is it misspelled?", permission))
	}
	return a.orgRoute(permission, orgFromHeader, h)
}

// orgSource is where a request names its organization.
type orgSource struct {
	id func(*http.Request) (uuid.UUID, error)
	// bad writes the response for a missing or malformed ID.
	bad func(http.ResponseWriter, *http.Request)
}

// orgFromHeader reads the X-Organization-ID header, for project routes.
var orgFromHeader = orgSource{
	id: func(r *http.Request) (uuid.UUID, error) { return uuid.Parse(r.Header.Get(OrgHeader)) },
	bad: func(w http.ResponseWriter, r *http.Request) {
		httpapi.WriteError(w, r, http.StatusBadRequest, "bad_request", "Set the X-Organization-ID header to an organization ID.", nil)
	},
}

// orgFromPath reads the {id} path value, for the module's own
// /v1/organizations/{id} endpoints. A malformed ID can't name an
// organization, so it's a 404 like any other.
var orgFromPath = orgSource{
	id:  func(r *http.Request) (uuid.UUID, error) { return uuid.Parse(r.PathValue("id")) },
	bad: writeNotFound,
}

// orgRoute checks the user is a member of the organization src names and,
// unless permission is empty, that their role there grants it.
func (a *Auth) orgRoute(permission rbac.Permission, src orgSource, h http.Handler) http.Handler {
	return guarded{httpapi.WithRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := a.authenticate(w, r)
		if !ok {
			return
		}
		orgID, err := src.id(r)
		if err != nil {
			src.bad(w, r)
			return
		}
		role, err := a.q.GetMembershipRole(r.Context(), db.GetMembershipRoleParams{OrganizationID: orgID, UserID: c.user.ID})
		if errors.Is(err, pgx.ErrNoRows) {
			writeNotFound(w, r)
			return
		}
		if err != nil {
			httpapi.WriteInternalError(w, r, a.log, err)
			return
		}
		a.warnUndefinedRole(r, a.orgRoles, role, c.user.ID)
		c.org = &Org{ID: orgID, Role: role}
		c.can = func(p rbac.Permission) bool { return a.orgCan(role, p) }
		if permission != "" && !c.can(permission) {
			writeForbidden(w, r)
			return
		}
		h.ServeHTTP(w, withCurrent(r, c))
	}))}
}

// orgCan reports whether an organization role grants p. Owners always
// can, so an organization can't be locked out of its own settings.
func (a *Auth) orgCan(role string, p rbac.Permission) bool {
	return role == OwnerRole || a.orgRoles.Has(role, p)
}

// warnUndefinedRole logs a stored role that's no longer defined in code.
// It grants nothing, but someone should clean it up.
func (a *Auth) warnUndefinedRole(r *http.Request, roles rbac.Roles, role string, userID uuid.UUID) {
	if role != "" && !roles.Defines(role) {
		a.log.WarnContext(r.Context(), "auth: user has a role that's no longer defined; it grants nothing",
			slog.String("request_id", httpapi.RequestIDFrom(r.Context())),
			slog.String("user_id", userID.String()),
			slog.String("role", role))
	}
}

// Public marks h as intentionally open to logged-out users. It doesn't
// change how h behaves; it makes the choice explicit where routes are
// registered, which Protect requires.
func (a *Auth) Public(h http.Handler) http.Handler {
	return guarded{h}
}

// redirectType is the type of the handlers ServeMux uses to redirect, e.g.
// from /v1/things/ to /v1/things. They run no project code.
var redirectType = reflect.TypeOf(http.RedirectHandler("/", http.StatusMovedPermanently))

// Protect wraps the project's whole router and enforces deny by default:
// a request whose route wasn't wrapped by Public, Authenticated, Require,
// or RequireOrg gets a 500 and an error in the log, and the route's
// handler never runs. A forgotten permission makes a route unusable
// instead of open to everyone.
//
// The access rule must be the outermost wrapper on each route:
// a.RequireOrg("x:y", logging(h)), not logging(a.RequireOrg("x:y", h)).
// Middleware for every route goes around Protect instead.
func (a *Auth) Protect(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h, pattern := mux.Handler(r)
		_, ok := h.(guarded)
		// No pattern means the mux answers 404 or 405 itself.
		if ok || pattern == "" || reflect.TypeOf(h) == redirectType {
			mux.ServeHTTP(w, r)
			return
		}
		httpapi.WithRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			httpapi.WriteInternalError(w, r, a.log, fmt.Errorf(
				"route %q has no access rule: wrap its handler with Public, Authenticated, Require, or RequireOrg", pattern))
		})).ServeHTTP(w, r)
	})
}

// UserFrom returns the logged-in user. ok is false outside the module's
// access rules, which is a bug in the calling code.
func UserFrom(ctx context.Context) (u User, ok bool) {
	c, ok := ctx.Value(contextKey{}).(current)
	return c.user, ok
}

// SessionFrom returns the current session. ok is false outside the
// module's access rules, which is a bug in the calling code.
func SessionFrom(ctx context.Context) (s Session, ok bool) {
	c, ok := ctx.Value(contextKey{}).(current)
	if !ok {
		return Session{}, false
	}
	return sessionFromInternal(c.session), true
}

// Org is the organization a RequireOrg request is for, and the user's role
// in it.
type Org struct {
	ID   uuid.UUID
	Role string
}

// OrgFrom returns the organization the request is for. ok is false outside
// RequireOrg. Every query on organization data must filter by its ID.
func OrgFrom(ctx context.Context) (o Org, ok bool) {
	c, ok := ctx.Value(contextKey{}).(current)
	if !ok || c.org == nil {
		return Org{}, false
	}
	return *c.org, true
}

// Can reports whether the current user has permission: against their
// organization role under RequireOrg, or their app role under Require.
// It's for finer checks inside a handler, such as whether to offer a
// delete button. It's false anywhere else.
func Can(ctx context.Context, permission rbac.Permission) bool {
	c, ok := ctx.Value(contextKey{}).(current)
	return ok && c.can != nil && c.can(permission)
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

func writeForbidden(w http.ResponseWriter, r *http.Request) {
	httpapi.WriteError(w, r, http.StatusForbidden, "forbidden", "You don't have permission to do this.", nil)
}
