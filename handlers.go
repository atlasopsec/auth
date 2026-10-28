package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/atlasopsec/auth/internal/db"
	"github.com/atlasopsec/auth/internal/httpapi"
	"github.com/atlasopsec/auth/internal/password"
	"github.com/atlasopsec/auth/internal/session"
)

// maxEmailLength matches the limit on auth.users.email.
const maxEmailLength = 254

// Register adds the module's endpoints to mux. Defining a route the module
// already owns makes mux panic at startup, which surfaces the clash
// immediately.
func (a *Auth) Register(mux *http.ServeMux) {
	mux.Handle("POST /v1/users", endpoint(http.HandlerFunc(a.signUp)))
	mux.Handle("POST /v1/sessions", endpoint(http.HandlerFunc(a.logIn)))
	mux.Handle("GET /v1/users/me", endpoint(a.Authenticated(http.HandlerFunc(a.me))))
	mux.Handle("GET /v1/sessions", endpoint(a.Authenticated(http.HandlerFunc(a.listSessions))))
	mux.Handle("DELETE /v1/sessions/current", endpoint(a.Authenticated(http.HandlerFunc(a.logOut))))
	mux.Handle("DELETE /v1/sessions/{id}", endpoint(a.Authenticated(http.HandlerFunc(a.endSession))))
	mux.Handle("DELETE /v1/sessions", endpoint(a.Authenticated(http.HandlerFunc(a.logOutEverywhere))))
}

// endpoint adds what every module endpoint needs. Responses carry tokens
// and account details, so nothing may cache them.
func endpoint(h http.Handler) http.Handler {
	return httpapi.WithRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	}))
}

type credentialsRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Client   string `json:"client"`
}

type loginResponse struct {
	User      userJSON  `json:"user"`
	Token     string    `json:"token"`
	ExpiresAt timestamp `json:"expires_at"`
}

func (a *Auth) signUp(w http.ResponseWriter, r *http.Request) {
	var req credentialsRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return
	}
	req.Email = strings.TrimSpace(req.Email)

	var details []httpapi.FieldError
	if fe, ok := checkEmail(req.Email); !ok {
		details = append(details, fe)
	}
	if fe, ok := checkNewPassword(req.Password); !ok {
		details = append(details, fe)
	}
	if fe, ok := checkClient(req.Client); !ok {
		details = append(details, fe)
	}
	if details != nil {
		writeValidationFailed(w, r, details)
		return
	}

	hash, err := password.Hash(req.Password, password.DefaultParams)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	user, tok, s, err := a.createUser(r, req.Email, hash, session.Client(req.Client))
	if errors.Is(err, errEmailTaken) {
		httpapi.WriteError(w, r, http.StatusConflict, "email_taken", "An account with this email already exists.", nil)
		return
	}
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	a.logEvent(r, "auth: user signed up", user.ID)
	httpapi.WriteJSON(w, r, http.StatusCreated, loginResponse{User: toUserJSON(user), Token: tok, ExpiresAt: timestamp(s.ExpiresAt)})
}

var errEmailTaken = errors.New("email taken")

// createUser creates the user, runs OnUserCreated, and starts their first
// session, all in one transaction.
func (a *Auth) createUser(r *http.Request, email, hash string, client session.Client) (User, string, session.Session, error) {
	ctx := r.Context()
	id, err := uuid.NewV7()
	if err != nil {
		return User{}, "", session.Session{}, fmt.Errorf("generating user ID: %w", err)
	}

	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return User{}, "", session.Session{}, fmt.Errorf("beginning sign-up: %w", err)
	}
	// After Commit this is a no-op.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	row, err := db.New(tx).CreateUser(ctx, db.CreateUserParams{
		ID:           id,
		Email:        email,
		PasswordHash: &hash,
		Now:          a.now().UTC().Truncate(time.Microsecond),
	})
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" && pgErr.ConstraintName == "idx_users_email" {
		return User{}, "", session.Session{}, errEmailTaken
	}
	if err != nil {
		return User{}, "", session.Session{}, fmt.Errorf("creating user: %w", err)
	}
	user := userFromRow(row)

	if a.hooks.OnUserCreated != nil {
		if err := a.hooks.OnUserCreated(ctx, tx, user); err != nil {
			return User{}, "", session.Session{}, fmt.Errorf("OnUserCreated hook: %w", err)
		}
	}

	ip, ua := httpapi.Client(r, a.trusted)
	tok, s, err := session.NewManager(tx, a.now).Create(ctx, user.ID, session.Meta{Client: client, IP: ip, UserAgent: ua}, session.Standard)
	if err != nil {
		return User{}, "", session.Session{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, "", session.Session{}, fmt.Errorf("committing sign-up: %w", err)
	}
	return user, tok, s, nil
}

func (a *Auth) logIn(w http.ResponseWriter, r *http.Request) {
	var req credentialsRequest
	if err := httpapi.Decode(w, r, &req); err != nil {
		httpapi.WriteDecodeError(w, r, err)
		return
	}
	req.Email = strings.TrimSpace(req.Email)

	var details []httpapi.FieldError
	if req.Email == "" {
		details = append(details, httpapi.FieldError{Field: "email", Code: "required", Message: "Enter your email address."})
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

	row, err := a.q.GetUserByEmail(r.Context(), req.Email)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && row.PasswordHash == nil {
		// Unknown email, or an account that only signs in with OAuth. Do a
		// password check's worth of work so the response takes as long as
		// a wrong password would.
		password.SimulateVerify(req.Password)
		writeInvalidCredentials(w, r)
		return
	}
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	ok, err := password.Verify(req.Password, *row.PasswordHash)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, fmt.Errorf("verifying password for user %s: %w", row.ID, err))
		return
	}
	if !ok {
		writeInvalidCredentials(w, r)
		return
	}
	a.rehashIfNeeded(r, row, req.Password)

	ip, ua := httpapi.Client(r, a.trusted)
	tok, s, err := a.sessions.Create(r.Context(), row.ID, session.Meta{Client: session.Client(req.Client), IP: ip, UserAgent: ua}, session.Standard)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	a.logEvent(r, "auth: user logged in", row.ID)
	httpapi.WriteJSON(w, r, http.StatusCreated, loginResponse{User: toUserJSON(userFromRow(row)), Token: tok, ExpiresAt: timestamp(s.ExpiresAt)})
}

// rehashIfNeeded upgrades a password hash made with older cost settings,
// now that the password is known. Failing only means it's tried again on
// the next login, so it doesn't fail the login.
func (a *Auth) rehashIfNeeded(r *http.Request, row db.AuthUser, pw string) {
	needs, err := password.NeedsRehash(*row.PasswordHash, password.DefaultParams)
	if err != nil || !needs {
		return
	}
	hash, err := password.Hash(pw, password.DefaultParams)
	if err == nil {
		err = a.q.UpdatePasswordHash(r.Context(), db.UpdatePasswordHashParams{
			ID:           row.ID,
			PasswordHash: &hash,
			Now:          a.now().UTC().Truncate(time.Microsecond),
		})
	}
	if err != nil {
		a.log.WarnContext(r.Context(), "auth: rehashing password",
			slog.String("request_id", httpapi.RequestIDFrom(r.Context())),
			slog.String("user_id", row.ID.String()),
			slog.String("error", err.Error()))
	}
}

func (a *Auth) me(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	httpapi.WriteJSON(w, r, http.StatusOK, toUserJSON(c.user))
}

type sessionJSON struct {
	ID         uuid.UUID `json:"id"`
	Client     string    `json:"client"`
	IP         *string   `json:"ip"`
	UserAgent  *string   `json:"user_agent"`
	LastUsedAt timestamp `json:"last_used_at"`
	ExpiresAt  timestamp `json:"expires_at"`
	CreatedAt  timestamp `json:"created_at"`
	IsCurrent  bool      `json:"is_current"`
}

type sessionList struct {
	Data       []sessionJSON `json:"data"`
	NextCursor *string       `json:"next_cursor"`
}

func (a *Auth) listSessions(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	sessions, err := a.sessions.List(r.Context(), c.user.ID)
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	list := sessionList{Data: make([]sessionJSON, len(sessions))}
	for i, s := range sessions {
		j := sessionJSON{
			ID:         s.ID,
			Client:     string(s.Client),
			LastUsedAt: timestamp(s.LastUsedAt),
			ExpiresAt:  timestamp(s.ExpiresAt),
			CreatedAt:  timestamp(s.CreatedAt),
			IsCurrent:  s.ID == c.session.ID,
		}
		if s.IP != nil {
			ip := s.IP.String()
			j.IP = &ip
		}
		if s.UserAgent != "" {
			j.UserAgent = &s.UserAgent
		}
		list.Data[i] = j
	}
	httpapi.WriteJSON(w, r, http.StatusOK, list)
}

func (a *Auth) logOut(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	// ErrNotFound means a concurrent request already ended it, which is the
	// outcome the caller wants.
	if err := a.sessions.Revoke(r.Context(), c.user.ID, c.session.ID); err != nil && !errors.Is(err, session.ErrNotFound) {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	a.logEvent(r, "auth: user logged out", c.user.ID)
	w.WriteHeader(http.StatusNoContent)
}

func (a *Auth) endSession(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeNotFound(w, r)
		return
	}
	err = a.sessions.Revoke(r.Context(), c.user.ID, id)
	if errors.Is(err, session.ErrNotFound) {
		writeNotFound(w, r)
		return
	}
	if err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	a.logEvent(r, "auth: session ended", c.user.ID)
	w.WriteHeader(http.StatusNoContent)
}

func (a *Auth) logOutEverywhere(w http.ResponseWriter, r *http.Request) {
	c, _ := currentFrom(r.Context())
	if _, err := a.sessions.RevokeAll(r.Context(), c.user.ID); err != nil {
		httpapi.WriteInternalError(w, r, a.log, err)
		return
	}
	a.logEvent(r, "auth: user logged out everywhere", c.user.ID)
	w.WriteHeader(http.StatusNoContent)
}

// logEvent logs an auth event with only IDs: never emails, passwords, or
// tokens.
func (a *Auth) logEvent(r *http.Request, msg string, userID uuid.UUID) {
	a.log.InfoContext(r.Context(), msg,
		slog.String("request_id", httpapi.RequestIDFrom(r.Context())),
		slog.String("user_id", userID.String()))
}

func checkEmail(email string) (httpapi.FieldError, bool) {
	fe := httpapi.FieldError{Field: "email"}
	switch {
	case email == "":
		fe.Code, fe.Message = "required", "Enter your email address."
	case len(email) > maxEmailLength:
		fe.Code, fe.Message = "too_long", "Email addresses can be at most 254 characters."
	case !validEmail(email):
		fe.Code, fe.Message = "invalid_format", "Enter a valid email address."
	default:
		return fe, true
	}
	return fe, false
}

// validEmail accepts a single plain address, like ada@example.com: no
// display name ("Ada <ada@example.com>"), no list, no quoting tricks.
func validEmail(email string) bool {
	addr, err := mail.ParseAddress(email)
	return err == nil && addr.Name == "" && addr.Address == email && strings.Contains(email[strings.LastIndex(email, "@"):], ".")
}

func checkNewPassword(pw string) (httpapi.FieldError, bool) {
	fe := httpapi.FieldError{Field: "password"}
	switch err := password.Validate(pw); {
	case err == nil:
		return fe, true
	case pw == "":
		fe.Code, fe.Message = "required", "Enter a password."
	case errors.Is(err, password.ErrTooShort):
		fe.Code, fe.Message = "too_short", fmt.Sprintf("Passwords must be at least %d characters.", password.MinLength)
	case errors.Is(err, password.ErrTooLong):
		fe.Code, fe.Message = "too_long", fmt.Sprintf("Passwords can be at most %d characters.", password.MaxLength)
	default:
		fe.Code, fe.Message = "invalid_format", "The password contains invalid characters."
	}
	return fe, false
}

func checkClient(client string) (httpapi.FieldError, bool) {
	fe := httpapi.FieldError{Field: "client"}
	switch session.Client(client) {
	case session.ClientWeb, session.ClientMobile:
		return fe, true
	case "":
		fe.Code, fe.Message = "required", `Set client to "web" or "mobile".`
	default:
		fe.Code, fe.Message = "invalid_value", `Set client to "web" or "mobile".`
	}
	return fe, false
}

func writeValidationFailed(w http.ResponseWriter, r *http.Request, details []httpapi.FieldError) {
	httpapi.WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", "Some fields are invalid.", details)
}

func writeInvalidCredentials(w http.ResponseWriter, r *http.Request) {
	httpapi.WriteError(w, r, http.StatusUnauthorized, "invalid_credentials", "The email or password is incorrect.", nil)
}

func writeNotFound(w http.ResponseWriter, r *http.Request) {
	httpapi.WriteError(w, r, http.StatusNotFound, "not_found", "Not found.", nil)
}

type userJSON struct {
	ID            uuid.UUID `json:"id"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     timestamp `json:"created_at"`
}

func toUserJSON(u User) userJSON {
	return userJSON{ID: u.ID, Email: u.Email, EmailVerified: u.EmailVerified, CreatedAt: timestamp(u.CreatedAt)}
}

// timestamp marshals as RFC 3339 in UTC to the second, per the API design
// standard.
type timestamp time.Time

func (t timestamp) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Time(t).UTC().Format(time.RFC3339) + `"`), nil
}
