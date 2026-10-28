# API

The module's public Go API and the HTTP endpoints it serves.

> **Status: approved.** Covers build step 3 (sign up, log in, log out, sessions), plus how sign-up changes when email verification arrives in step 4. Later steps (RBAC, 2FA, OAuth) add to it but don't change what's here. Sections marked **(Decision)** were confirmed in review; see §5.

Once a name below is released, changing or removing it is a breaking change (a new major version), so this is the moment to get it right.

---

## 1. Go API

### Setup

```go
package auth

// Config configures the module. Only DB is required.
type Config struct {
	DB *pgxpool.Pool

	// TrustedProxies are the networks allowed to set X-Forwarded-For and
	// X-Forwarded-User-Agent, normally the Next.js server on Railway's
	// private network. Requests from anywhere else use the connection's
	// own address and User-Agent.
	TrustedProxies []netip.Prefix

	Hooks  Hooks
	Logger *slog.Logger     // default: slog.Default()
	Now    func() time.Time // default: time.Now; for tests

	// AllowUnverifiedLogin lets users log in before verifying their email,
	// and makes sign-up log them in immediately. Off by default: see
	// "Verify first" in §2. Added in step 4.
	//   AllowUnverifiedLogin bool

	// Added in later steps: Mailer, AppURL, Roles, OAuth, EncryptionKey.
}

// Hooks let a project react to auth events.
type Hooks struct {
	// OnUserCreated runs inside the sign-up transaction. Returning an error
	// cancels the sign-up, so a project's own rows (e.g. a profile) are
	// created together with the user or not at all.
	//
	// The hook must write through tx, not the project's own pool: writes
	// through the pool aren't part of the transaction and wouldn't be
	// undone. Keep it quick, since the transaction stays open while it
	// runs. It runs for every new user, including OAuth sign-ups (step 7).
	OnUserCreated func(ctx context.Context, tx pgx.Tx, u User) error
}

// New validates cfg and returns a ready Auth. It doesn't touch the
// database; call Migrate first.
func New(cfg Config) (*Auth, error)
```

### Mounting the endpoints (Decision)

```go
// Register adds the module's endpoints (§2) to mux.
func (a *Auth) Register(mux *http.ServeMux)
```

```go
mux := http.NewServeMux()
a.Register(mux)
mux.Handle("GET /v1/invoices", a.Authenticated(listInvoices))
```

`Register` adds each route to the project's own `ServeMux` using Go's method-and-path patterns. If a project accidentally defines a route the module already owns, Go panics at startup, which surfaces the clash immediately. The alternative, a single `Handler()` mounted under a prefix, doesn't work well because the module's routes (`/v1/users/...`, `/v1/sessions/...`) share prefixes with project routes.

### Protecting routes (Decision)

```go
// Authenticated wraps h so it only runs for a valid session. Otherwise it
// responds 401 with the standard error format.
func (a *Auth) Authenticated(h http.Handler) http.Handler

// Public marks h as intentionally open to logged-out users.
func (a *Auth) Public(h http.Handler) http.Handler

// Added in the RBAC step, without changing the two above:
//   func (a *Auth) Require(permission string, h http.Handler) http.Handler
//   func (a *Auth) CheckRoutes(...) error  // fails if a route is neither
```

`Authenticated` is for apps or routes where "logged in" is enough, which is permanent for simple consumer apps. `Require(permission, h)` comes with RBAC and also checks a permission. Adding it later only adds a name, so nothing here breaks.

### Reading the current user

```go
// UserFrom returns the logged-in user. ok is false outside Authenticated
// (and later Require), which is a bug in the calling code.
func UserFrom(ctx context.Context) (u User, ok bool)

// SessionFrom returns the current session.
func SessionFrom(ctx context.Context) (s Session, ok bool)

type User struct {
	ID            uuid.UUID
	Email         string
	EmailVerified bool
	CreatedAt     time.Time
}

type Session struct {
	ID         uuid.UUID
	Client     string // "web" or "mobile"
	ExpiresAt  time.Time
	CreatedAt  time.Time
}
```

`User` and `Session` are small on purpose, so fields can be added later without breaking anything. They never contain password hashes or tokens.

## 2. HTTP endpoints

All follow the [API design standard](https://github.com/jakefrenzel/engineering-standards/blob/main/standards/api-design.md): `/v1` paths, `snake_case` JSON, the standard error format, `X-Request-ID`. Request bodies are limited to 64 KB.

| Endpoint | Purpose | Auth | Success |
|---|---|---|---|
| `POST /v1/users` | Sign up | Public | `202` (`201` with `AllowUnverifiedLogin`) |
| `POST /v1/sessions` | Log in | Public | `201` |
| `GET /v1/users/me` | Current user | Session | `200` |
| `GET /v1/sessions` | My active sessions | Session | `200` |
| `DELETE /v1/sessions/current` | Log out | Session | `204` |
| `DELETE /v1/sessions/{id}` | End one of my sessions | Session | `204` |
| `DELETE /v1/sessions` | Log out everywhere | Session | `204` |

The session token goes in `Authorization: Bearer <token>`, from Next.js (read from the `__Host-session` cookie) or a mobile app (from secure storage).

### `POST /v1/users`: sign up

```json
{ "email": "ada@example.com", "password": "correct horse battery staple", "client": "web" }
```

- `client` is required: `web` or `mobile`.
- The email is trimmed and validated (a single address, at most 254 characters) and stored as entered. Uniqueness ignores case.
- The password must pass the length policy (12–256 characters).

#### Verify first: the default (Decision)

Sign-up creates the account and emails a verification link. It doesn't log the user in.

```json
202 Accepted
{ "verification_required": true }
```

- **The response is identical whether or not the email is already in use**, in body, status, and timing. If it's in use, nothing is created and the owner of that address gets an email instead ("someone tried to sign up with your email; log in or reset your password"). So sign-up never reveals whether an account exists.
- Nobody can claim an account for an email they don't control.
- Logging in to an unverified account with the correct password returns `403 email_not_verified`, so the client can offer to resend the link. A wrong password still returns `invalid_credentials`, so this reveals nothing to someone who doesn't know the password.

| Error | Status | When |
|---|---|---|
| `validation_failed` | 422 | Bad email, password too short or long, bad `client`. `details` lists each field |
| `bad_request` | 400 | Malformed JSON or unknown fields |

#### Immediate login: `AllowUnverifiedLogin`

For projects that choose a faster first experience over these protections. Sign-up logs the user in, unverified:

```json
201 Created
{
  "user": { "id": "0192d4e1-…", "email": "ada@example.com", "email_verified": false, "created_at": "2026-10-28T13:00:00Z" },
  "token": "q3J…",
  "expires_at": "2026-11-27T13:00:00Z"
}
```

| Error | Status | When |
|---|---|---|
| `validation_failed` | 422 | As above |
| `email_taken` | 409 | An account already uses that email. This reveals that the account exists, which is part of the trade-off |
| `bad_request` | 400 | As above |

Unverified accounts can't do anything sensitive in either mode.

#### Build order

Step 3 has no mailer, so it ships the immediate-login behavior only. Step 4 adds the mailer and verification, makes verify first the default, and adds `AllowUnverifiedLogin`. Both happen before `v1.0.0`, so no released version ever defaults to immediate login.

#### Account pre-hijacking (rule for step 7)

With `AllowUnverifiedLogin`, an attacker can sign up with someone else's email and a password they know. If the real owner later signs in with Google using that email and the accounts were linked, the attacker's password would still work. So when OAuth finds an existing account with the same email that **isn't verified**, it must not link to it as-is: it deletes that account's password and sessions first, or refuses. Verified accounts link only when the provider also says the email is verified, as the standard already requires.

### `POST /v1/sessions`: log in

```json
{ "email": "ada@example.com", "password": "correct horse battery staple", "client": "mobile" }
```

```json
201 Created
{ "user": { … }, "token": "q3J…", "expires_at": "2026-11-27T13:00:00Z" }
```

| Error | Status | When |
|---|---|---|
| `invalid_credentials` | 401 | Unknown email, wrong password, or an OAuth-only account. **Same response and same timing for all three** |
| `email_not_verified` | 403 | Correct password, but the email isn't verified yet (verify first mode only, from step 4) |
| `validation_failed` | 422 | Missing fields, bad `client` |

- The response time doesn't reveal whether the email exists (`SimulateVerify` for unknown emails).
- The 2FA step adds a second response shape later, `{ "two_factor_required": true, "challenge_id": "…" }`, used only by accounts with 2FA turned on. Clients that handle it can be written now.

### `GET /v1/users/me`

`200` with the `user` object above. `401 unauthenticated` without a valid session.

### `GET /v1/sessions`

```json
200 OK
{
  "data": [
    {
      "id": "0192d4e1-…",
      "client": "web",
      "ip": "203.0.113.7",
      "user_agent": "Mozilla/5.0 …",
      "last_used_at": "2026-10-28T13:00:00Z",
      "expires_at": "2026-11-27T13:00:00Z",
      "created_at": "2026-10-20T09:00:00Z",
      "is_current": true
    }
  ],
  "next_cursor": null
}
```

Most recently used first. `next_cursor` is always `null`: a user has a handful of sessions, so this list isn't paginated, but it keeps the standard list shape in case that ever changes.

### `DELETE /v1/sessions/current`, `/v1/sessions/{id}`, `/v1/sessions`

`204 No Content`. Ending a session that doesn't exist or isn't the caller's returns `404 not_found`. Log out everywhere includes the current session.

## 3. Request handling details

- **Unknown JSON fields are rejected** with `400 bad_request` **(Decision)**. A typo like `"pasword"` fails loudly instead of being silently ignored.
- **Client IP and user agent:** requests reach the Go API through Next.js, so the connection's own address and `User-Agent` belong to the Next.js server. Next.js forwards the real values in `X-Forwarded-For` and `X-Forwarded-User-Agent` **(Decision)**, and the module only trusts them from `Config.TrustedProxies`. Mobile apps connect directly, so their own address and `User-Agent` are used.
- **Request IDs:** an incoming `X-Request-ID` is reused, otherwise a UUIDv7 is generated. Either way it's returned in the response header, included in error bodies, and logged.
- **Logging:** each auth event logs the user ID and request ID. Never emails, passwords, or tokens.
- **OpenAPI:** the endpoints are documented in `api/openapi.yaml`, shipped with the module so projects can merge it into their own API docs.

## 4. Not in this step

| Feature | Step |
|---|---|
| Email verification, verify first as the default, `AllowUnverifiedLogin`, password reset and change, the `Mailer` | 4 |
| Roles, organizations, `Require`, `CheckRoutes` | 5 |
| 2FA (the second login response shape) | 6 |
| OAuth | 7 |
| **Rate limiting** and the security event log | 8 |
| Breached-password check on sign-up | 4, with the mailer and outbound HTTP |

**Until step 8, there's no rate limiting.** Nothing should be deployed for real users before `v1.0.0` anyway, but it's the biggest gap in the meantime.

## 5. Decisions

Confirmed in review on 2026-10-28:

1. **`Register(mux)`** adds routes to the project's `ServeMux`, rather than a single mounted `Handler()`.
2. **`Authenticated(h)` now, `Require(permission, h)` with RBAC**, plus `Public(h)`.
3. **`OnUserCreated` runs inside the sign-up transaction**, so a hook failure cancels the sign-up. Hooks write through `tx` and stay quick.
4. **Verify first is the default; immediate login is opt-in** with `AllowUnverifiedLogin`. Step 3 ships immediate login until step 4 adds verification.
5. **`client` is a required body field** on sign-up and login.
6. **Unknown JSON fields are rejected.** Deploy the API before app versions that send new fields.
7. **The forwarded user agent header is named `X-Forwarded-User-Agent`.**
