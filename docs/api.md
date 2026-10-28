# API

The module's public Go API and the HTTP endpoints it serves.

> **Status:** §1–5 (build step 3) are approved and built. §6 (build step 4: email) is a **sketch for review**; its **(Decision)** items need sign-off before code is written. Later steps (RBAC, 2FA, OAuth) add to this but don't change what's here.

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

---

## 6. Step 4: email (sketch for review)

Step 4 adds everything that needs email: verification (and verify first as the default), password reset, password change, email change, and the breached-password check. It follows the [auth standard](https://github.com/jakefrenzel/engineering-standards/blob/main/standards/auth.md) §3 and §11.

### Configuration

```go
type Config struct {
	// ...everything from §1, plus:

	// Mailer sends the module's emails. Required.
	Mailer mail.Mailer

	// AppURL is the web app's base URL, for links in emails,
	// e.g. "https://app.example.com".
	AppURL string

	// AppName appears in email subjects and text, e.g. "Acme".
	AppName string

	// AllowUnverifiedLogin lets users log in before verifying their email,
	// and makes sign-up log them in immediately. Off by default (§2).
	AllowUnverifiedLogin bool

	// DisableBreachCheck turns off the Have I Been Pwned check on new
	// passwords. On by default.
	DisableBreachCheck bool

	// Emails overrides the default email templates. Any nil field uses the
	// default.
	Emails Emails
}

// Close waits for emails still being sent, up to ctx's deadline. Call it
// when the server shuts down.
func (a *Auth) Close(ctx context.Context) error
```

The `mail` package is public, because projects choose or write the mailer:

```go
package mail

type Mailer interface {
	Send(ctx context.Context, m Message) error
}

type Message struct {
	To      string
	Subject string
	Text    string // always set
	HTML    string // optional
	// IdempotencyKey lets a provider drop duplicates when a send is retried.
	IdempotencyKey string
}
```

- **`mail/resend`:** `resend.New(apiKey, from string) mail.Mailer`, using Resend's Go SDK as the standard says. It's in its own package, so only projects that import it compile it.
- **`mailtest.Recorder`:** a fake that records messages, for project tests.
- **`mail.NewWriter(w io.Writer)`** for local development: prints each email, links included, to `w`. It logs a warning at startup, because links contain live tokens and must never be printed in production.

### Sending happens in the background (Decision)

Endpoints that send email respond first and send afterwards, in a background goroutine with up to 3 retries.

- **No timing leak:** "send a reset link" takes the same time whether or not the account exists. Sending synchronously would make real accounts noticeably slower (Resend takes 200–500 ms).
- **Why not an outbox table** (store emails in Postgres, send from a worker): the emails contain live tokens, so the table would hold working reset links in plain text, which is exactly what hashing tokens avoids.
- **Trade-off:** an email in flight when the server stops is lost, and the user clicks "resend". `Close` keeps that window small on a normal deploy.

### Emails and templates (Decision)

| Email | Sent when |
|---|---|
| Verify your email | Sign-up (verify first mode), or a resend request |
| Someone tried to sign up with your email | Sign-up with an email that already has a verified account |
| Reset your password | Reset requested for an existing account |
| Your password was changed | After a password change or reset |
| Confirm your new email | Email change requested (sent to the new address) |
| Your email was changed | Email change completed (sent to the old address) |

Defaults are **plain text, brandless, and short**: plain text reaches inboxes most reliably and needs no design. Projects override any of them:

```go
type Emails struct {
	VerifyEmail, SignUpAttempt, PasswordReset, PasswordChanged,
	EmailChange, EmailChanged func(EmailData) (subject, text, html string)
}

type EmailData struct {
	AppName   string
	Link      string        // empty for notices
	ExpiresIn time.Duration // how long Link works
}
```

### Links carry the token in the fragment (Decision)

Links point at the **Next.js app** (the Go API isn't public), with the token after `#`:

```
https://app.example.com/verify-email#token=q3J…
https://app.example.com/reset-password#token=q3J…
```

- Browsers never send the fragment to servers, so tokens stay out of Railway's access logs, analytics, and `Referer` headers. A query string (`?token=`) would leak into all three.
- The cost: the page reads the token in a small client component and posts it to a server action. That fits the standard's "small leaf components" rule, and the Next.js template (step 9) includes these pages.
- The API's confirm endpoints take the token in the JSON body, never in the path. This changes the `.../{token}/confirm` paths in design.md §5.

### Tokens

Stored in a new `auth.email_tokens` table (only the SHA-256 hash, like sessions). Every token is single-use, and requesting a new one cancels the user's earlier unused tokens of the same kind.

| Kind | Lifetime |
|---|---|
| Verify email | 24 hours |
| Reset password | 30 minutes (the standard) |
| Change email | 1 hour |

A bad, used, or expired token returns `422 token_invalid_or_expired`, with the same response for all three.

### Endpoints

| Endpoint | Purpose | Auth | Success |
|---|---|---|---|
| `POST /v1/email-verifications` | Send a verification email | Public | `202` |
| `POST /v1/email-verifications/confirm` | Verify, and log in | Public | `201` |
| `POST /v1/password-resets` | Send a reset email | Public | `202` |
| `POST /v1/password-resets/confirm` | Set a new password | Public | `204` |
| `POST /v1/users/me/password` | Change password | Session | `204` |
| `POST /v1/email-changes` | Start changing email | Session | `202` |
| `POST /v1/email-changes/confirm` | Finish changing email | Public | `204` |

#### Sign-up in verify first mode

As approved in §2: `202 { "verification_required": true }`, identical whether or not the email exists. Behind that response:

| The email… | What happens |
|---|---|
| Is new | Account created, unverified. Verification email sent |
| Belongs to an unverified account | Nothing changes. A new verification email is sent, which also offers a password reset |
| Belongs to a verified account | Nothing changes. "Someone tried to sign up" email sent |

#### Verification asks for the password (Decision)

```json
POST /v1/email-verifications/confirm
{ "token": "q3J…", "password": "correct horse battery staple", "client": "web" }
```

`201` with the same body as login: the user is verified **and** logged in.

**Why ask for the password:** it closes the last squatting hole in verify first. Without it, an attacker signs up with your email and a password they know, and the verification email lands in your inbox. If you click it, you've verified *their* account, and they can log in. With the password required, clicking their link does nothing, because you don't know their password. Their unverified account doesn't lock you out either: a password reset (below) takes it over.

- The UX is "click link, enter password, you're in", which is the login you'd do next anyway.
- A wrong password returns `401 invalid_credentials`. After 5 wrong passwords the token stops working, so a stolen link can't be used to guess passwords.

`POST /v1/email-verifications` takes `{ "email": "…" }` and always returns `202`. It sends only if the account exists and isn't verified.

#### Password reset

- `POST /v1/password-resets` with `{ "email": "…" }` always returns `202`. It sends only if the account exists.
- `POST /v1/password-resets/confirm` with `{ "token": "…", "password": "…" }` then:
  - sets the new password (policy and breach check apply),
  - **marks the email verified**, since the user just proved they control it,
  - **ends all sessions** (the standard),
  - sends "your password was changed".
- It doesn't log the user in. They log in with the new password.
- **(Decision)** Marking the email verified is what lets a reset take over a squatted account: the attacker's password is replaced and their sessions end.
- Accounts that only use OAuth can use reset to add a password.

#### Password change

`POST /v1/users/me/password` with `{ "current_password": "…", "new_password": "…" }`:

- A wrong current password returns `422 validation_failed` with `current_password: incorrect`. It isn't `401`, which would make the app think the user was logged out.
- Ends all **other** sessions (the standard) and sends "your password was changed".
- OAuth-only accounts have no current password, so they use reset instead.

#### Email change (Decision)

The standard requires verifying the new address and notifying the old one, so this is part of step 4.

1. `POST /v1/email-changes` with `{ "email": "new@example.com", "current_password": "…" }`. The account must already be verified.
   - Returns `202`, even if the new address belongs to another account. In that case the new address gets the "someone tried to sign up" email instead, so this endpoint can't be used to find accounts.
2. The new address gets a link. `POST /v1/email-changes/confirm` with `{ "token": "…" }`:
   - switches the email,
   - **ends all sessions**,
   - emails the old address.
   - Returns `204`.

#### Login changes

In verify first mode, logging in to an unverified account with the correct password returns `403 email_not_verified`, as approved in §2.

### Breached passwords (Decision)

New passwords (sign-up, reset, change) are checked against [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords):

- **Privacy:** only the first 5 characters of the password's SHA-1 hash leave the server ("k-anonymity"), with response padding turned on so the response size doesn't hint at the result either.
- **Result:** a found password returns `422 validation_failed` with `password: breached` ("This password has appeared in a data breach. Choose a different one."). It's a field detail like the length rules, not a separate top-level code. This replaces `password_breached` in design.md's code list.
- **Fails open:** if HIBP doesn't answer within 2 seconds, the check is skipped and logged, rather than blocking sign-ups (design.md §8).

### Abuse until step 8 (Decision)

Rate limiting comes in step 8, but these endpoints can send email to anyone's address. Until then, a simple **cooldown**: each account gets at most one email of each kind per 60 seconds, enforced from `email_tokens`.

- The response is unchanged (`202`), so the cooldown reveals nothing.
- It stops someone flooding an inbox, or burning through the Resend quota, from a single loop.

### Database

One new migration, `00002_email_tokens.sql` (a new table only, so it's backward compatible):

```
auth.email_tokens   id, user_id, kind (verify_email|reset_password|change_email),
                    token_hash, new_email (change_email only), failed_attempts,
                    expires_at, used_at, created_at
```

### New error codes

| Code | Status | When |
|---|---|---|
| `email_not_verified` | 403 | Login before verifying (verify first mode) |
| `token_invalid_or_expired` | 422 | Bad, used, or expired email token |

New `details` codes: `breached`, `incorrect`.

### PRs

1. `mail`, `mail/resend`, `mailtest`, `email_tokens`, background sending, `Close`.
2. Verification and verify first as the default, `AllowUnverifiedLogin`.
3. Password reset and change, plus the breach check.
4. Email change.

### Decisions to confirm

1. **Emails are sent in the background** after responding, not through an outbox table; `Close` waits for them on shutdown.
2. **Plain-text default emails**, overridable per email.
3. **Tokens go in the link's fragment** (`#token=`), and API confirm endpoints take them in the body.
4. **Verifying requires the password, then logs the user in.**
5. **A password reset also verifies the email** and ends all sessions.
6. **Email change is part of step 4**, and ends all sessions when it completes.
7. **The breach check is on by default, fails open, and is a field-level `breached` detail.**
8. **A 60-second per-account cooldown** on sending each kind of email, until step 8.
