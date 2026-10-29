# API

The module's public Go API and the HTTP endpoints it serves.

> **Status:** §1–9 cover build steps 3–7 (approved and built). §10 covers build step 8 (rate limiting and the event log), approved and built. §11 covers build step 9 (the Next.js template), approved and being built. Sections marked **(Decision)** were confirmed in review. Later steps add to this but don't change what's here.

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

	// Added in step 8: OnEvent, run after each security event is recorded
	// (§10).
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

// Added in the RBAC step (§7), without changing the two above:
//   func (a *Auth) Require(permission string, h http.Handler) http.Handler
//   func (a *Auth) RequireOrg(permission string, h http.Handler) http.Handler
//   func (a *Auth) Protect(mux *http.ServeMux) http.Handler  // deny by default
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
  "expires_at": "2026-11-27T13:00:00Z",
  "absolute_expires_at": "2027-01-26T13:00:00Z"
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
{ "user": { … }, "token": "q3J…", "expires_at": "2026-11-27T13:00:00Z", "absolute_expires_at": "2027-01-26T13:00:00Z" }
```

- `expires_at` is when the session ends if it isn't used; `absolute_expires_at` is the latest it can last however often it's used (90 days, or 12 hours for privileged users). The second was added in step 9, for the web app's cookie (§11). Every login response has both: sign-up with `AllowUnverifiedLogin`, verification links, 2FA, and OAuth.

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
| Roles, organizations, `Require`, `RequireOrg`, `Protect` (see §7) | 5 |
| 2FA (the second login response shape) | 6 |
| OAuth | 7 |
| **Rate limiting** and the security event log | 8 |
| Breached-password check on sign-up | 4, with the mailer and outbound HTTP |

Rate limiting arrived in step 8 (§10).

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

## 6. Step 4: email

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
	Invitation func(EmailData) (subject, text, html string) // step 5
}

type EmailData struct {
	AppName   string
	AppURL    string        // for links without a token, e.g. AppURL + "/reset-password"
	Link      string        // empty for notices
	ExpiresIn time.Duration // how long Link works
	OrgName   string        // invitations only (step 5)
}
```

### Links carry the token in the fragment (Decision)

Links point at the **Next.js app** (the Go API isn't public), with the token after `#`:

```
https://app.example.com/verify-email#token=q3J…
https://app.example.com/reset-password#token=q3J…
https://app.example.com/confirm-email-change#token=q3J…
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

New `details` codes: `breached`, `incorrect`, and `unchanged` (an email change to the current address).

### PRs

1. `mail`, `mail/resend`, `mailtest`, `email_tokens`, background sending, `Close`.
2. Verification and verify first as the default, `AllowUnverifiedLogin`.
3. Password reset and change, plus the breach check.
4. Email change.

### Decisions

Confirmed in review on 2026-10-28:

1. **Emails are sent in the background** after responding, not through an outbox table; `Close` waits for them on shutdown.
2. **Plain-text default emails**, overridable per email.
3. **Tokens go in the link's fragment** (`#token=`), and API confirm endpoints take them in the body.
4. **Verifying requires the password, then logs the user in.**
5. **A password reset also verifies the email** and ends all sessions.
6. **Email change is part of step 4**, and ends all sessions when it completes.
7. **The breach check is on by default, fails open, and is a field-level `breached` detail.**
8. **A 60-second per-account cooldown** on sending each kind of email, until step 8.

---

## 7. Step 5: roles, permissions, and organizations

Step 5 adds the permission checks from the [auth standard](https://github.com/jakefrenzel/engineering-standards/blob/main/standards/auth.md) §7: permissions named `resource:action`, roles defined in Go, checks on permissions (never role names), deny by default, and `404` for anything a user isn't allowed to see. It also adds organizations, members, and invitations.

### Two kinds of roles (Decision)

Your projects need two different things, so there are two role sets, and a project uses either or both:

| | Organization roles | App roles |
|---|---|---|
| **For** | B2B apps and client portals: "Ada is an admin **of Acme**" | Consumer apps and your own staff: "Ada is a support agent **for the whole app**" |
| **Stored in** | `auth.memberships` (one role per user per organization) | `auth.user_roles` (one role per user) |
| **Checked by** | `a.RequireOrg("invoices:create", h)` | `a.Require("users:ban", h)` |
| **Configured in** | `Config.OrgRoles` | `Config.AppRoles` |

The alternative, organizations only, would make every consumer app create a fake one-person organization per user just to have an admin role.

```go
var orgRoles = rbac.Roles{
	"owner":  {rbac.All},
	"admin":  {"invoices:read", "invoices:create", "members:read", "members:manage", "organization:update"},
	"member": {"invoices:read", "invoices:create", "members:read"},
	"viewer": {"invoices:read"},
}

var appRoles = rbac.Roles{
	"support": {"users:read", "users:ban"},
}
```

- **Validation:** `New` checks every permission has the form `resource:action` (lowercase letters, digits, `_`), so a typo like `invoice:create` vs `invoices:create` is caught in a test, not silently denied in production. `Require` and `RequireOrg` panic at startup if given a permission that no role has, for the same reason.
- **Removed roles:** roles live in code, and a role stored in the database but no longer in code grants nothing (and is logged), so deleting a role from code can't leave anyone with stale access.
- **Default app role:** users have no app role, and so no app permissions, until one is set with `a.SetAppRole(ctx, userID, "support")`. That's a Go call for seed scripts and admin tooling, not an endpoint.

### Checking permissions

```go
mux.Handle("GET /v1/invoices",  a.RequireOrg("invoices:read", listInvoices))
mux.Handle("POST /v1/invoices", a.RequireOrg("invoices:create", createInvoice))
mux.Handle("POST /v1/users/{id}/ban", a.Require("users:ban", banUser))
```

- **`RequireOrg`** reads the organization from the **`X-Organization-ID`** header (design.md decision 3), checks the user is a member, and checks their role has the permission.
  - Not a member, or no such organization: `404 not_found`, so outsiders can't tell whether an organization exists.
  - A member without the permission: `403 forbidden`.
  - A missing or malformed header: `400 bad_request`.
- **`Require`** does the same against the user's app role: `403 forbidden` without the permission.
- **Inside a handler:**

  ```go
  org, _ := auth.OrgFrom(ctx)            // org.ID, org.Role
  db.ListInvoices(ctx, org.ID)           // every query on org data filters by organization_id
  if auth.Can(ctx, "invoices:delete") {  // finer checks, e.g. show a delete button
  ```

  `Can` checks the organization role under `RequireOrg`, and the app role under `Require`.
- Removing someone or changing their role takes effect on their **next request**: permissions are looked up per request, not stored in the session.

### Deny by default: `Protect` (Decision)

The standard says a route without a declared permission is a bug that tests must catch. Go's `ServeMux` can't list its routes, so instead of a `CheckRoutes` test helper, the module checks every request:

```go
mux := http.NewServeMux()
a.Register(mux)
mux.Handle(...)
http.ListenAndServe(addr, a.Protect(mux))
```

`Protect` looks up which route a request matches. If that route's handler wasn't wrapped by `Public`, `Authenticated`, `Require`, or `RequireOrg`, the request gets a `500` and an error is logged, and **the handler never runs**.

- A forgotten permission **fails closed**: the route is unusable instead of open to everyone. The first test or manual check that touches it shows the error.
- **One rule for projects:** the auth wrapper must be the outermost wrapper on each route (`a.RequireOrg("x:y", logging(h))`, not `logging(a.RequireOrg(...))`). Middleware for every route goes around the whole mux instead (`logging(a.Protect(mux))`).
- `Authenticated` stays for routes where "logged in" is enough.

### Organizations

- **Who can create one (Decision):** any user with a verified email, through `POST /v1/organizations`. They become its `owner`.
  - Apps that create organizations themselves (for example, when a client signs a contract) set `Config.DisableOrganizationCreation` and call `a.CreateOrganization(ctx, name, ownerID)` from Go.
- **Owners (Decision):** `OrgRoles` must define `owner`. Owners always have every permission, whatever the definition says, so an organization can never be locked out of its own settings.
  - **Every organization keeps at least one owner:** the last owner can't leave, be removed, or be changed to another role (`409 last_owner`).
- **No privilege escalation (Decision):** you can give someone a role only if you already have every permission in it, and only owners can make someone an owner. Otherwise an admin with `members:manage` could promote themselves or a friend to owner.
- **Deleting organizations is left out of step 5 (Decision).** It deletes everything the organization owns. Projects decide how that should work (grace periods, data export, support involvement) and can add it later. The module's tables cascade, so it's a single `DELETE` when needed.

### Invitations (Decision)

Members are added by email invitation:

1. Someone with `members:manage` invites an address with a role (subject to the no-escalation rule). The invitation works for **7 days**.
2. The address gets an email with `{AppURL}/accept-invitation#token=…`.
3. The link is accepted by a **logged-in user whose verified email matches the invitation**. Someone without an account signs up first (with the same address), then accepts.

**Why the email must match:** invitation links get forwarded, and a forwarded link shouldn't let the wrong person into a client's organization. Verifying the email first is what proves the person controls the invited address.

- Inviting someone who's already a member: `409 already_member`.
- Invitations can be listed and cancelled. Inviting the same address again replaces the earlier invitation.
- The same 60-second cooldown applies per organization and address, until step 8's rate limiting.

### Endpoints

| Endpoint | Purpose | Requires |
|---|---|---|
| `POST /v1/organizations` | Create an organization; you become owner | Verified email |
| `GET /v1/organizations` | My organizations, with my role in each | Session |
| `GET /v1/organizations/{id}` | One organization | Member |
| `PATCH /v1/organizations/{id}` | Rename it | `organization:update` |
| `GET /v1/organizations/{id}/members` | Members and their roles | `members:read` |
| `PATCH /v1/organizations/{id}/members/{user_id}` | Change a member's role | `members:manage` |
| `DELETE /v1/organizations/{id}/members/{user_id}` | Remove a member, or leave (your own ID) | `members:manage`, or yourself |
| `POST /v1/organizations/{id}/invitations` | Invite by email | `members:manage` |
| `GET /v1/organizations/{id}/invitations` | Pending invitations | `members:manage` |
| `DELETE /v1/organizations/{id}/invitations/{invitation_id}` | Cancel one | `members:manage` |
| `POST /v1/invitations/accept` | Accept, with the token in the body | Session, matching verified email |

- Permission names the module uses itself: `organization:update`, `members:read`, `members:manage`. Projects give them to roles like any other permission.
- For anyone who isn't a member, every `/v1/organizations/{id}/...` endpoint returns `404`.
- Lists use the standard shape. Members and invitations are paginated (cursor, default 20, max 100), since a client organization can be large.

### Database

Migrations `00003` (organizations, memberships, app roles) and `00004` (invitations, with the invitations PR). New tables only:

```
auth.organizations   id, name, created_at, updated_at
auth.memberships     id, organization_id, user_id, role, created_at, updated_at
                     unique (organization_id, user_id)
auth.invitations     id, organization_id, email, role, token_hash, invited_by,
                     expires_at, accepted_at, created_at, updated_at
auth.user_roles      user_id (primary key), role, created_at, updated_at
```

Deleting a user deletes their memberships, app role, and the invitations they sent. Projects' own tables reference `auth.organizations(id)` for their organization-scoped data.

### Later steps

- **2FA for roles** (step 6): `rbac.Roles{...}.RequireTwoFactor("owner", "admin")`. Those users must set up 2FA and get 12-hour sessions. Nothing in step 5 blocks this.
- **Rate limiting** (step 8) on invitations.

### New error codes

| Code | Status | When |
|---|---|---|
| `forbidden` | 403 | Missing permission |
| `last_owner` | 409 | Removing or demoting the only owner |
| `already_member` | 409 | Inviting an existing member |
| `invitation_email_mismatch` | 403 | Accepting an invitation sent to a different address |

`token_invalid_or_expired` (422) is reused for bad invitation links.

### PRs

1. `rbac`, the schema, `Require`, `RequireOrg`, `Can`, `OrgFrom`, `SetAppRole`, `Protect`.
2. Organizations and members endpoints, `CreateOrganization`.
3. Invitations.

### Decisions

Confirmed in review on 2026-10-28:

1. **Two role sets:** organization roles (`RequireOrg`) and app roles (`Require`), each optional.
2. **`Protect(mux)`** enforces deny by default on every request, instead of a `CheckRoutes` test helper.
3. **Any verified user can create an organization** and becomes its owner; `DisableOrganizationCreation` turns this off.
4. **`owner` always has every permission**, and every organization keeps at least one.
5. **No privilege escalation:** you can only grant roles whose permissions you already have; only owners grant owner.
6. **Invitations require a logged-in user with a matching verified email**, and expire after 7 days.
7. **Deleting organizations isn't in step 5.**

---

## 8. Step 6: two-factor authentication

Step 6 adds 2FA from the [auth standard](https://github.com/jakefrenzel/engineering-standards/blob/main/standards/auth.md) §6:
- **TOTP** (authenticator apps like 1Password or Google Authenticator), implemented in-house per design.md decision 5.
- **10 single-use recovery codes.**
- **Secrets stored encrypted** with AES-GCM.
- **2FA required for elevated roles** and for individual users an admin marks.
- **A working code before 2FA turns on.**
- **Password and code to turn it off.**

### Encryption key (Decision)

```go
type Config struct {
	// ...everything so far, plus:

	// EncryptionKey encrypts 2FA secrets: 32 random bytes, base64-encoded,
	// from an environment variable (e.g. AUTH_ENCRYPTION_KEY). Required.
	// Generate one with: openssl rand -base64 32
	EncryptionKey string
}
```

- **Required for every project,** so 2FA is always available to users, as you wanted ("at least as an option").
- **AES-256-GCM**, with the user's ID as associated data. A secret copied onto another user's row won't decrypt.
- **Every ciphertext starts with a key ID,** so key rotation (an `EncryptionKeys` list for old keys) can be added later without migrating anything.
- **Losing the key** means every user has to set up 2FA again. It lives in Railway's variables like any other secret, and the README will say to back it up.

### Setting up 2FA

| Endpoint | Body | Returns |
|---|---|---|
| `POST /v1/users/me/two-factor` | `{ current_password }` | `201 { secret, otpauth_uri }`. Pending until confirmed |
| `POST /v1/users/me/two-factor/confirm` | `{ code }` | `200 { recovery_codes: [10] }`. 2FA is now on |
| `DELETE /v1/users/me/two-factor` | `{ current_password, code }` | `204`. Refused (`403 two_factor_required`) if the user must have 2FA |
| `POST /v1/users/me/two-factor/recovery-codes` | `{ current_password, code }` | `200 { recovery_codes: [10] }`, replacing the old ones |

- **Setup needs the current password,** like other account-security changes. Confirming needs a working code from the app, so a bad scan can't lock anyone out (the standard).
- **`otpauth_uri`** is the standard `otpauth://totp/…` link with the app name as issuer. The client turns it into a QR code; `secret` is for typing in by hand. Both are shown only during setup.
- **Code settings:** 6 digits, 30-second steps, SHA-1. That's what every authenticator app supports.
- **`GET /v1/users/me` gains two fields:** `two_factor_enabled` and `two_factor_required`. Adding fields isn't a breaking change.

### Logging in with 2FA (Decision)

For a user with 2FA on, a correct password no longer returns a session:

```json
POST /v1/sessions  →  200
{ "two_factor_required": true, "challenge_token": "q3J…", "expires_at": "2026-10-28T13:05:00Z" }
```

```json
POST /v1/two-factor-challenges/verify
{ "challenge_token": "q3J…", "code": "123456" }
→ 201, the usual login response
```

- **The challenge token proves the password step happened,** so it's a random secret (stored hashed) sent in the body, not an ID in the URL. This changes design.md's `/v1/two-factor-challenges/{id}/verify` and the `challenge_id` name promised in §2.
- **A challenge works for 5 minutes and allows 5 wrong codes.** After that, the user starts over with their password.
- **Codes are accepted for the current 30-second step and one either side,** to allow for clock drift. A code that's been used is never accepted again, so a code someone watched you type is useless.
- **`code` takes a TOTP code or a recovery code.** The format tells them apart.
- **Every way into a session goes through the challenge.** That includes the verification link (§6), which returns a challenge instead of a session when 2FA is on.
- **A wrong code** returns `401 invalid_two_factor_code`. A used or expired challenge, or one with 5 wrong codes, returns `401 two_factor_challenge_invalid`.
- **Changing or resetting the password ends pending challenges,** since each proves the old password.

### Recovery codes (Decision)

- **Ten codes,** each 16 random characters shown as `xxxx-xxxx-xxxx-xxxx` (80 bits). Each works once.
- **Stored as SHA-256 hashes, not argon2.** The standard says "hashed, like passwords"; the point is that they're never stored readable.
  - Argon2 exists to slow down guessing of *human-chosen* passwords. An 80-bit random code can't be guessed either way.
  - Argon2 would make every recovery login check up to 10 slow hashes, about half a second.
- **They're shown once,** at confirm or regenerate, and never again.

### Required 2FA (Decision)

```go
auth.Config{
	OrgRoles:       orgRoles,
	AppRoles:       appRoles,
	TwoFactorRoles: []string{"owner", "admin", "support"}, // org or app roles
}

a.SetTwoFactorRequired(ctx, userID, true) // an individual user (the standard)
```

- **A config list, not `rbac.Roles{…}.RequireTwoFactor(…)` as design.md sketched.** `Roles` is a plain map, so the method version couldn't carry the extra information.
- **It applies to the whole account.** Being an admin of one organization means 2FA everywhere. That's simpler, and nobody has to reason about which organization a request touches.
- **Users who must have 2FA but haven't set it up** can still log in. Until they finish setup, every request except the 2FA setup endpoints, `GET /v1/users/me` and logging out gets `403 two_factor_setup_required`. That's the standard's "can't use the app until they do", and the app can send them straight to setup.
- **Privileged sessions last 12 hours** (the standard, §4). That's enforced on every request, so promoting someone takes effect on their next request, not their next login.
- **"Privileged" means holding one of `TwoFactorRoles`.** A user marked with `SetTwoFactorRequired` must have 2FA but keeps regular sessions, since the standard ties the 12 hours to roles.
- **`TwoFactorRoles` must name roles defined in `OrgRoles` or `AppRoles`,** so a typo fails at startup instead of leaving a role unprotected.
- **Which roles to list** follows the auth standard §6: staff roles such as `support` always, and `owner` and `admin` when organizations are shared by teams. In apps where each user gets their own workspace, everyone who signs up is an owner, so listing `owner` would force 2FA and 12-hour sessions on every customer; those apps may leave it out. The module doesn't add `owner` by itself for that reason.

### Guessing codes, until step 8 (Decision)

Rate limiting arrives in step 8. Until then, someone who already has the password could keep starting new challenges and guessing.

- **The limit:** after **10 wrong codes in 15 minutes** across all of a user's challenges and password resets, logging in for that user stops issuing challenges until the 15 minutes pass (`429 rate_limited`, with `Retry-After`). Codes sent to challenges started earlier, and to password resets, get the same `429`, so challenges opened ahead of time can't be used to keep guessing.
- **It's a temporary pause, not a lockout,** in line with the standard's "slow down, don't lock out".
- **The user is emailed when it trips:** "someone entered your password correctly but not your 2FA code; change your password". By then someone has their password.

### Password reset with 2FA (Decision)

A reset never logs anyone in, so it can't get past 2FA: the next login asks for a code either way. On top of that, **when 2FA is on, finishing a reset also takes a code**, so someone with access only to the user's inbox can't change their password (and log them out everywhere) either.

```json
POST /v1/password-resets/confirm
{ "token": "…", "password": "…", "code": "123456" }
```

- **Without a code,** the response is `422 validation_failed` with `code: required`, and nothing changes. The reset page then shows a code field and sends again.
- **A wrong code** returns `401 invalid_two_factor_code`. It counts toward the guessing limit above and toward the reset link's 5 failed attempts, like wrong passwords on a verification link.
- **A recovery code works here too,** for a user who has lost their phone.

**A user who has lost both their phone and their recovery codes** can't recover the account by themselves; otherwise 2FA wouldn't protect anything. For that case:

```go
// ResetTwoFactor turns off a user's 2FA and ends all their sessions. It's
// for admin tooling and support, after confirming who the user is some
// other way. There's no endpoint for it.
func (a *Auth) ResetTwoFactor(ctx context.Context, userID uuid.UUID) error
```

The user is emailed that 2FA was turned off. If 2FA is required for them, they're asked to set it up again at their next login.

### Notices

Users are emailed when 2FA is turned on or off, when recovery codes are regenerated, and when a recovery code is used (with how many are left). The standard says users SHOULD be told about new 2FA settings. The templates join `Emails`: `TwoFactorEnabled`, `TwoFactorDisabled`, and `RecoveryCodesRegenerated` (PR 1), then `RecoveryCodeUsed` and `TwoFactorGuessing`, the guessing-limit warning (PR 2).

### Database

Migrations `00005` (PR 1) and `00006` (PR 2):

```
auth.totp_secrets            user_id (primary key), secret_encrypted, last_used_step,
                             confirmed_at, created_at, updated_at
auth.recovery_codes          id, user_id, code_hash, used_at, created_at, updated_at
auth.two_factor_challenges   id, user_id, token_hash, client, failed_attempts,
                             expires_at, used_at, created_at, updated_at
auth.two_factor_failures     id, user_id, created_at, updated_at
```

- **Challenges don't store an IP or user agent.** The session takes them from the verify request, which comes from the device that will use it.
- **`two_factor_failures` has a row per wrong code** for the guessing limit, which counts across challenges and password resets. Rows older than 15 minutes are deleted as new ones are added.

`auth.users.two_factor_required` already exists (migration `00001`).

### New error codes

| Code | Status | When |
|---|---|---|
| `invalid_two_factor_code` | 401 | Wrong TOTP or recovery code at login or password reset. The logged-in setup endpoints use `422 validation_failed` with `code: incorrect` instead, since a 401 would tell the app the user was logged out |
| `two_factor_challenge_invalid` | 401 | The challenge is used, expired, or had 5 wrong codes. Log in with the password again |
| `two_factor_already_enabled` | 409 | Starting or confirming setup when 2FA is already on |
| `two_factor_not_enabled` | 409 | Turning off 2FA, or regenerating codes, when it's off |
| `two_factor_setup_not_started` | 409 | Confirming before starting setup |
| `two_factor_setup_required` | 403 | 2FA required but not set up yet |
| `two_factor_required` | 403 | Turning off 2FA that's required |
| `rate_limited` | 429 | Too many wrong codes (above) |

### PRs

1. `internal/totp` (with RFC 6238's test vectors), encryption, the schema, and the setup, confirm, disable and regenerate endpoints.
2. The login challenge, verifying codes, recovery codes at login, the guessing limit, the notices, the code on password reset, and `ResetTwoFactor`.
3. Required 2FA (`TwoFactorRoles`, `SetTwoFactorRequired`), the setup-only restriction, and 12-hour privileged sessions.

### Decisions

Confirmed in review on 2026-10-28:

1. **`EncryptionKey` is required for every project.** AES-256-GCM, the user ID bound in, and a key ID for future rotation.
2. **Login with 2FA returns a secret challenge token,** which works for 5 minutes and 5 wrong codes. Codes are allowed ±30 s and are never reused.
3. **Recovery codes are 80-bit random, stored as SHA-256** rather than argon2.
4. **Required 2FA comes from `TwoFactorRoles` and a per-user flag, and covers the whole account.** Until it's set up, the user can only set it up.
5. **Privileged sessions last 12 hours, checked on every request.**
6. **10 wrong codes in 15 minutes pauses challenges for that user,** and emails them.
7. **The verification link returns a challenge, not a session, when 2FA is on.**
8. **Finishing a password reset takes a 2FA code (or recovery code) when 2FA is on.** `ResetTwoFactor` is for users who've lost both.

---

## 9. Step 7: sign in with Google, GitHub, and Apple

Step 7 adds OAuth from the [auth standard](https://github.com/jakefrenzel/engineering-standards/blob/main/standards/auth.md) §5 and the [mobile standard](https://github.com/jakefrenzel/engineering-standards/blob/main/standards/mobile.md) §5:
- **PKCE and `state` always.**
- **Users are matched by the provider's user ID, never by email.**
- **Linking by email only when the provider says it's verified.**
- **Linking and unlinking from settings,** but never removing the last way to log in.
- **Sign in with Apple** on iOS, which Apple requires when an app offers Google or GitHub.

### Configuration

```go
auth.Config{
	// ...everything so far, plus:
	OAuth: auth.OAuth{
		Google: &auth.Google{ClientID: "…", ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET")},
		GitHub: &auth.GitHub{ClientID: "…", ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET")},
		Apple:  &auth.Apple{BundleIDs: []string{"com.example.app"}}, // native iOS sign-in only
	},
}
```

- **A nil provider is turned off.** Starting a flow for it answers `422` with `provider: invalid_value`, since the provider is a body field rather than part of the path.
- **Secrets come from Railway variables,** like every other secret. Apple needs none: native sign-in only checks Apple's signed token.
- **Providers redirect to the web app,** at `{AppURL}/oauth/callback` and `{AppURL}/oauth/callback/mobile`, which are registered with each provider. The Go API isn't public, so it can't receive the redirect itself. Step 9's Next.js template provides both pages.
- **The mobile app's deep link is the web app's setting,** not the Go API's: only the mobile callback page uses it. So `Config.OAuth` has no `MobileRedirectURL`.

### One flow for web and mobile (Decision)

The Go API runs the whole exchange: it creates `state` and the PKCE verifier, holds the client secrets, swaps the code for tokens, and reads the user's identity. The web app and the mobile app only open a URL and pass back what the provider returns.

```json
POST /v1/oauth-flows
{ "provider": "google", "client": "web", "client_challenge": "…" }
→ 201 { "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?…", "expires_at": "…" }
```

1. **The client starts a flow.**
   - **Web:** Next.js keeps a random `client_verifier` in an `HttpOnly` cookie and sends its SHA-256 as `client_challenge`, then redirects the browser to `authorization_url`.
   - **Mobile:** the app keeps the verifier in memory and opens the URL in the system browser (`WebBrowser.openAuthSessionAsync`). Never an embedded web view.
2. **The user signs in at the provider,** which redirects to the callback page with `code` and `state`.
   - **Web:** the page finishes the flow.
   - **Mobile:** `/oauth/callback/mobile` passes them on to `MobileRedirectURL`, which reopens the app.
3. **The client finishes:**

```json
POST /v1/oauth-flows/complete
{ "state": "…", "code": "…", "client_verifier": "…" }
→ 201, the usual login response, or 200 with a 2FA challenge (§8)
```

- **The secrets stay on the server.** A mobile app can't keep a client secret: anything in the app bundle is public.
- **This replaces design.md's `GET /v1/oauth/{provider}/start` and `POST .../callback`.** A `GET` that redirects can't work from a private API, and the callback has to land on the web app.
- **`client_verifier` ties the flow to the device that started it.** PKCE alone doesn't, because the server holds that verifier. Without the client verifier:
  - another app that registered the same deep-link scheme could catch the redirect, send the code to the API, and get the user's session; and
  - an attacker could get a victim's browser to finish the attacker's flow and log in as the attacker (login CSRF).

  The client verifier blocks both, because only the device that started the flow has it.
- **A flow works once, for 10 minutes.** Its PKCE verifier is stored encrypted with `EncryptionKey`.
- **The flow is spent before the provider is called,** so it can't be finished twice even if that call fails. A wrong client verifier doesn't spend it, so a stray request can't cancel the real device's sign-in.

### Sign in with Apple on iOS (Decision)

On iOS, the native Apple sheet (`expo-apple-authentication`) is what users and App Review expect. It returns a signed identity token instead of a redirect:

```json
POST /v1/apple-sign-ins
{ "identity_token": "eyJ…", "nonce": "…" }
→ 201, the usual login response, or 200 with a 2FA challenge
```

- **The token is checked against Apple's published keys:** issuer, audience (one of `BundleIDs`), expiry, and the nonce.
- **The nonce:** the app generates a random nonce, gives Apple its hex SHA-256, and sends the nonce itself here. The token carries only the hash, so someone holding just the token can't use it.
- **The session is always a `mobile` one,** so the body has no `client`.
- **Apple is iOS only: no web or Android sign-in** (confirmed in review on 2026-10-29). Apple's sign-in API doesn't document PKCE, which the auth standard requires, and Apple only requires its sign-in on iOS. Someone who signed up with Apple on an iPhone uses a password on the web: a password reset sends them a link, through Apple's relay if they hid their address.
- **Linking Apple from settings isn't offered.** A first Apple sign-in links by verified email like any provider; with Hide My Email the address won't match, so it makes a new account. Unlinking Apple works as for any provider.
- **Checking signed tokens needs a JWT library.** Google's and Apple's ID tokens from the redirect flow are checked the same way. I'd use `github.com/coreos/go-oidc/v3`, the standard Go OpenID Connect library, rather than write signature checking ourselves. It's the one new dependency besides `golang.org/x/oauth2` (planned in design.md).

### Who gets logged in (Decision)

When a provider confirms who the user is:
1. **A linked account** (same provider, same provider user ID) → log in as its user.
2. **Otherwise, the provider must say the email is verified.**
   - **Google and Apple:** the ID token's `email_verified`.
   - **GitHub:** the primary email from `/user/emails`, if it's marked verified.
   - **Not verified:** refused with `403 oauth_email_not_verified` ("Verify your email with Google first"). Nothing is created.
3. **An existing account with that email:**
   - **If its email is verified,** the provider is linked to it and the user is logged in. That's the same trust as a password reset link to that inbox.
   - **If its email isn't verified,** this is §2's pre-hijacking case: someone may have signed up with this address first. Its password, sessions, 2FA, and pending email tokens are deleted. Then the email is marked verified, the provider is linked, and the real owner is logged in. A password reset already takes back such an account the same way.
4. **No account** → a new user with that email, already verified, with no password. `OnUserCreated` runs, as for any sign-up.

Then, like every other way in:
- **2FA applies:** a user with 2FA gets a challenge, not a session.
- **Sessions follow the user's roles:** privileged roles get 12-hour sessions.
- **Only the email is stored, no names.** The module has never stored names; projects that want one ask for it in their own profile.
- **Apple's private relay addresses** (`…@privaterelay.appleid.com`) are treated like any other verified email.
- **The provider's email isn't kept in sync.** The account is matched by provider user ID from then on, so a later email change at the provider changes nothing here.

### Linking and unlinking (Decision)

| Endpoint | Body | Returns |
|---|---|---|
| `GET /v1/users/me/oauth-accounts` | | `200 { data: [{ id, provider, email, created_at }] }` |
| `POST /v1/users/me/oauth-accounts` | `{ provider, client, client_challenge, current_password }` | `201 { authorization_url, expires_at }`. Finished with `POST /v1/oauth-flows/complete`, sent with the session |
| `DELETE /v1/users/me/oauth-accounts/{id}` | `{ current_password }` | `204`. `409 last_login_method` if it's the only way left to log in |

- **Linking needs the current password, if the account has one.** Linking adds a way in, and it's how someone with a stolen session would make their access last. That's the same rule as other account-security changes.
- **Accounts without a password** (OAuth only) link and unlink with their session alone. The only other proof they could give is another provider round trip, which adds a lot of flow for little gain. The notices below cover them.
- **A provider account already linked to another user** returns `409 oauth_account_in_use`. Accounts are never moved silently.
- **One account per provider per user.** Trying a second answers `409 oauth_already_linked`.
- **Linking doesn't need a verified provider email.** The user is logged in and asked for it, and the account is matched by provider user ID from then on. The provider's address is kept only to show in settings, and may be empty.
- **Linking finishes only with the same user's session,** and that user's flow.
- **Notices:** the user is emailed when a provider is linked or unlinked, with new `Emails` templates `OAuthLinked` and `OAuthUnlinked`.

### Accounts without a password (Decision)

Setting up or turning off 2FA, changing the password, and linking all need `current_password`. Today an OAuth-only account just gets `current_password: incorrect`, which is confusing.

These endpoints (starting 2FA setup, turning 2FA off, regenerating recovery codes, changing the password, and changing the email) answer `409 password_not_set` instead, and the app can offer "set a password" through the existing reset flow, which already adds a password to OAuth-only accounts (§6). That's an additive change: a new error code on existing endpoints.

### Database

Migration `00007`:

```
auth.oauth_accounts   id, user_id, provider, provider_user_id, email,
                      created_at, updated_at
                      unique (provider, provider_user_id), unique (user_id, provider)
auth.oauth_flows      id, state_hash, provider, purpose (login|link), user_id (link only),
                      client, client_challenge, pkce_verifier_encrypted, nonce,
                      expires_at, used_at, created_at, updated_at
```

- **`email` on `oauth_accounts`** is the provider's address when linked, shown in settings ("Google: ada@gmail.com"). It's never used for matching.
- **Expired flows** are cleared as new ones start, like 2FA challenges.

### New error codes

| Code | Status | When |
|---|---|---|
| `oauth_failed` | 401 | The flow is unknown, used, or expired; the client verifier doesn't match; or the provider refused the code or token. Already listed in design.md |
| `oauth_email_not_verified` | 403 | The provider doesn't vouch for the email, and no account is linked yet |
| `oauth_account_in_use` | 409 | Linking a provider account that belongs to another user |
| `oauth_already_linked` | 409 | Linking a second account with a provider the user already linked (one per provider) |
| `last_login_method` | 409 | Unlinking the only way left to log in |
| `password_not_set` | 409 | An endpoint needs the current password, but the account has none |

### Testing

- **Fake providers:** the providers are `httptest` servers in tests, with their URLs set internally. They're never exported in `Config` and never called over the network.
- **Signed tokens:** the fakes sign ID tokens with test keys and serve them as JWKS, so signature, audience, nonce, and expiry checks run for real.
- **Failure cases:**
  - Wrong or missing client verifier, and a replayed flow.
  - An unverified provider email, and a provider account belonging to another user.
  - Taking back an unverified account, and 2FA users getting a challenge.

### PRs

1. Schema, the flow endpoints, Google and GitHub on web and mobile, the matching rules, and 2FA and session rules at the end.
2. Linking, unlinking, the account list, notices, and `password_not_set`.
3. Apple: native iOS sign-in.

### Decisions

Confirmed in review on 2026-10-29:

1. **One redirect flow for web and mobile, run by the Go API,** with the callback on web app pages and a mobile page that hands off to the app's deep link.
2. **A client verifier on top of `state` and PKCE,** so only the device that started a flow can finish it.
3. **Native Sign in with Apple on iOS** through `POST /v1/apple-sign-ins`, with `go-oidc` as a new dependency for checking signed tokens. Later narrowed to iOS only, with no Apple redirect flow (see above).
4. **The matching rules:**
   - Link by provider user ID first.
   - Link to an existing account only for a provider-verified email.
   - Take back an unverified local account by wiping its password and sessions.
   - Refuse unverified provider emails.
   - Store no names.
5. **Linking needs the current password when the account has one.** Linking and unlinking send notices, and the last login method can't be removed.
6. **`409 password_not_set`** for OAuth-only accounts on endpoints that need a password.

---

## 10. Step 8: rate limiting and the security event log

Step 8 adds the [auth standard](https://github.com/jakefrenzel/engineering-standards/blob/main/standards/auth.md)'s §9 and §10:
- **Rate limits:** on logins per account and per IP, password resets, 2FA attempts, and sign-ups.
- **Growing delays instead of lockouts:** repeated failed logins slow down further attempts, but never lock the account.
- **An `auth_events` table:** logins, logouts, password, 2FA, OAuth, and role changes, without secrets.
- **Optional: an email on login from a new device.** The standard says SHOULD.

It also replaces §4's "no rate limiting until step 8" warning. The step 4 and 6 stopgaps stay (§6 and §8): the 60-second email cooldown and the 2FA guessing limit are per account, so they still add something per-IP limits don't.

### Where limits live (Decision)

In Postgres, as design.md planned, in one small table:

```
auth.rate_limits   key, window_start, count      primary key (key, window_start)
```

- **One statement per check:** `INSERT … ON CONFLICT DO UPDATE SET count = count + 1 RETURNING count`. It's atomic, so concurrent requests can't slip past, and it works across several API instances on Railway without Redis.
- **Fixed windows:** a limit of "10 per hour" counts per clock hour. At the edge of two windows, up to twice the limit can get through in a short burst. That's the usual trade for a single statement, and fine for these numbers.
- **Keys** name the limit and what's counted, e.g. `login:ip:203.0.113.0`. Emails in keys are stored as SHA-256 hashes, so the table holds no addresses.
- **Old windows** are deleted by the cleanup job below.

### Which limits (Decision)

Every limit answers `429 rate_limited` with `Retry-After`, the code §8 already added.

| What | Counted per | Limit |
|---|---|---|
| Login attempts (`POST /v1/sessions`, the verification link, 2FA challenge codes, OAuth completion, Apple sign-in) | IP | 30 per 10 minutes |
| Sign-ups | IP | 10 per hour |
| Emails to an address (verification, password reset, email change, invitation) | IP | 10 per hour |
| | Address | 10 per day, on top of the 60-second cooldown |
| Starting OAuth flows | IP | 30 per 10 minutes |
| Wrong 2FA codes | IP | 30 per hour, on top of §8's per-user limit |
| Wrong current passwords on logged-in endpoints (2FA setup, password change, email change, linking) | User | 10 per hour |

- **Per IP, generously:** offices and mobile carriers put many people behind one address, so per-IP limits stop scripts, not crowds.
- **IPv6 is counted per `/64`,** since one device can use many addresses in its block. IPv4 counts per address.
- **The IP is the client's,** from `X-Forwarded-For` through `Config.TrustedProxies` (§3).
- **No configuration at first.** These are defaults every project gets; knobs can be added later if one needs different numbers.
- **The last row** covers a gap left in step 6, where a stolen session plus repeated password guesses on the logged-in endpoints had no limit.
- **The login limit also covers `POST /v1/password-resets/confirm`,** which takes 2FA codes too.
- **Per-IP limits count every request; the wrong-code limit counts only wrong codes.** Once a limit is reached, requests are refused without being checked.

### Failed logins slow down, never lock (Decision)

The standard: "slow down further attempts (growing delays) instead of locking the account outright, since a hard lock lets anyone lock a user out."

- **Per account and IP:** after **5 wrong passwords** for an email from one IP, each further attempt must wait: 1 second after the 6th, then 2, 4, 8… up to **15 minutes**.
- **Per account from anywhere:** the same delays start after **20 wrong passwords in an hour** from all IPs together, against attacks spread over many addresses.
- **Waiting attempts aren't checked:** an attempt that comes early gets `429 rate_limited` with `Retry-After`, without checking the password, so waiting attempts can't be used to guess.
- **A correct password clears** that IP's count for the account.
- **Unknown emails are counted exactly like real ones,** so the delays don't reveal whether an account exists.
- **The real owner on another network** is only slowed by the per-account delays, which need many failures from everywhere. An attacker hammering the account from one IP only slows themselves.
- **Counts start over after an hour without failures** for that key. The exact schedule: no wait after the first 5 failures (20 per account); after the next failure 1 second, then 2, 4, and so on, capped at 15 minutes.
- **Stored in `auth.login_failures`** (migration `00009`), one row per key with its count and the time the next attempt is allowed. Emails appear only as hashes. The cleanup job deletes rows an hour after their last failure, once their wait is over.
- **Concurrent attempts** that arrive in the same instant can each be checked before either failure is counted. The per-IP login limit (30 per 10 minutes) bounds that.

### The event log (Decision)

```
auth.auth_events   id, user_id, actor_id, event, ip, user_agent, metadata, created_at
```

| Event | When |
|---|---|
| `login_succeeded`, `login_failed` | Password, link, OAuth, and Apple logins; `metadata.method` says which: `password`, `verification_link`, `two_factor`, `google`, `github`, or `apple`. A login finished with a 2FA code is `two_factor`. Only `password` and `two_factor` can fail |
| `logout`, `logout_everywhere`, `session_ended` | |
| `password_changed`, `password_reset` | |
| `two_factor_enabled`, `two_factor_disabled`, `two_factor_reset`, `recovery_code_used`, `recovery_codes_regenerated` | |
| `oauth_linked`, `oauth_unlinked` | `metadata.provider` |
| `email_changed` | Never the addresses themselves |
| `app_role_changed`, `org_role_changed`, `member_added`, `member_removed`, `two_factor_required_changed` | `actor_id` is who made the change; `metadata` has the organization and roles |

- **IDs only:** `user_id` and `actor_id` are IDs. Never passwords, tokens, codes, or email addresses.
- **Who made a change:** for an invitation, `member_added`'s actor is whoever sent it. Changes made with Go calls (`SetAppRole`, `SetTwoFactorRequired`, `ResetTwoFactor`, `CreateOrganization`) have no actor and no IP, since the module can't know who called it. Admin tooling that needs that should keep its own record.
- **Failed logins for unknown emails** are recorded with no `user_id`. They're still useful, by IP, for spotting credential stuffing.
- **Recorded after the fact, best effort:** an event that fails to write is logged as an error, but doesn't fail the action that already happened.
- **Kept for 1 year,** then deleted by the cleanup job. Projects with other retention needs can copy events out with the hook below.
- **Read with `a.Events(ctx, userID, cursor)`,** a Go call for admin tooling. There's no endpoint at first. A "recent activity" page for users can be added later on top of it.
- **`Hooks.OnEvent(ctx, Event)`:** runs after each event is recorded. It's for projects that also want events in Sentry, PostHog, or their own alerting. The analytics standard sends business events from the Go API, and this is how auth events would get there.

### Email on login from a new device (Decision)

The standard says users SHOULD be emailed about logins from a new device.

- **What counts as new:** a successful login whose browser or app (the user agent) and network (IPv4 `/24` or IPv6 `/48`) haven't appeared together in that user's successful logins in the last **90 days**.
- **No notice for a brand-new account's first login.**
- **Template:** a new `Emails.NewDeviceLogin`, with the device and approximate time. No location, since there's no IP geolocation. `EmailData.Device` is the user agent as the client sent it (up to 512 characters, empty if none), and `EmailData.LoggedInAt` is when it happened. The user agent is whatever the client says, so templates should present it as quoted text and never as a link.
- **Read from the event log:** there's no separate table. A login checks the user's `login_succeeded` events, before recording its own, so the memory lasts as long as the events do. Every kind of login counts: password, link, 2FA, and OAuth. Logouts and failed logins never send it.
- **`Config.DisableNewDeviceEmails`** turns it off, for projects where it would be noise.
- **It's a heuristic:** a changed browser version or a new Wi-Fi network counts as new. Erring toward telling the user is the point.

### Cleanup (Decision)

Expired sessions, email tokens, 2FA challenges, OAuth flows, old rate-limit windows, and events over a year old all pile up today.

- **A background job,** started by `New` and stopped by `Close` like the email sender, deletes them **once an hour**. It first runs 5 minutes after start, so a deploy doesn't set every instance off at once.
- **Several API instances** each run it, which is harmless, since the deletes don't conflict.
- **`Config.DisableCleanup`** is for projects that would rather schedule it themselves, with `a.Cleanup(ctx)`.

### Database

Migration `00008` (PR 1): `auth.rate_limits`, with an `expires_at` column (the window's end) for cleanup, plus the `id`, `created_at`, and `updated_at` every table has. Migration `00010` (PR 3): `auth.auth_events`, with indexes on `(user_id, created_at)` and `(created_at)`. `user_id` and `actor_id` become `NULL` when the user is deleted, so the record of what happened stays.

### New error codes

None: `rate_limited` (429) already exists from §8.

### PRs

1. `internal/ratelimit`, the IP keys, the per-IP and per-address limits, and the cleanup job.
2. Failed-login delays, and the limit on wrong current passwords.
3. The event log, `a.Events`, and `Hooks.OnEvent`.
4. New-device emails.

### Decisions

Confirmed in review on 2026-10-29:

1. **Rate limits in Postgres,** with fixed windows and one atomic statement per check.
2. **The limits in the table above:** generous per IP, with IPv6 counted per `/64`, and no configuration at first.
3. **Failed logins:** delays doubling up to 15 minutes, after 5 failures per account and IP, or 20 per account per hour from everywhere. Never a lockout, and unknown emails are treated the same.
4. **The event log:** the events listed, IDs only, best effort, kept for 1 year, `a.Events` for tooling, and `Hooks.OnEvent`.
5. **New-device emails:** on by default, a 90-day memory of user agent and network, and a config switch to turn them off.
6. **An hourly cleanup job** for everything that expires, on by default.

## 11. Step 9: the Next.js template

Step 9 adds the web half of the [auth standard](https://github.com/jakefrenzel/engineering-standards/blob/main/standards/auth.md): the `__Host-session` cookie, `proxy.ts`, a session helper every protected page and server action calls, and the pages a user needs. Until now the module has worked only for mobile apps and tests; the links in its emails and the OAuth redirects all point at pages that don't exist yet.

The auth standard says these pieces are **copied** into projects, not installed, since they're small and get restyled anyway.

### What the template is (Decision)

- **A complete, runnable Next.js app** in `templates/nextjs/`: Next.js 16 (App Router), React 19, TypeScript, Tailwind, and shadcn/ui, the stack standard's choices, with pnpm.
- **Projects copy parts of it,** not the whole app. Its README lists what to copy: `src/proxy.ts`, `src/lib/auth/`, `src/lib/api/`, `src/app/(auth)/`, `src/app/account/`, and `src/components/auth/`. They're kept separate from the rest of the template so a project can copy them into its own app.
- **It's runnable so it can be tested.** CI builds it and runs its unit tests and a small Playwright suite against a real Go API and Postgres, the same way a project's would.
- **Versioned with the module.** The template's README says which module version it was written for, and its own `CHANGELOG.md` notes what changed, so projects know when to copy again. Copied files carry a one-line header naming the template version.
- **An example Go API** in `examples/api/` (a `main` package, outside the module's public packages) serves the template in development and in the Playwright tests. It's also the reference for wiring `auth.New` in a project. It uses `mail.Writer`, which prints emails instead of sending them, and the Playwright tests read the links from its output.

### Pages (Decision)

| Path | What it does | Logged in? |
|---|---|---|
| `/login` | Email and password, plus "Sign in with Google / GitHub" buttons for the providers the project turned on | No |
| `/login/two-factor` | Enter a 2FA or recovery code after the password or provider | No (holds a challenge) |
| `/sign-up` | Email and password. Then "check your email", or logged in if the project allows unverified logins | No |
| `/forgot-password`, `/reset-password` | Request a link; set a new password from it (with a 2FA code if the user has 2FA) | No |
| `/verify-email` | Confirm the address from the email link, which also logs in | No |
| `/confirm-email-change` | Confirm a new address from the email link | Either |
| `/accept-invitation` | Join an organization from the invitation link; asks to log in or sign up first | Yes |
| `/oauth/callback`, `/oauth/callback/mobile` | Where Google and GitHub send the browser back (§9) | No |
| `/account` | Change password and email; turn 2FA on or off and regenerate recovery codes; see and end sessions, or log out everywhere; link and unlink providers | Yes |
| `/dashboard` | A stand-in protected page, showing how a project's own pages use the session helper | Yes |

- **Plain and unbranded,** built from shadcn/ui's form components. Projects restyle them.
- **No Apple button:** Apple sign-in is native iOS only (§9).
- **Required 2FA:** a user who must set up 2FA (§8) is sent to `/account/two-factor` from every protected page until they do, by `requireSession`. The Go API already refuses everything else for them; this just avoids showing them errors. The page also offers them a way to log out.
- **The 2FA setup page shows a QR code** of the `otpauth://` URI, made on the server with the `qrcode` package and shown as an image, plus the key to type in by hand.

### The session cookie (Decision)

| Setting | Value |
|---|---|
| Name | `__Host-session` |
| `HttpOnly`, `Secure`, `SameSite` | On, on, `Lax` |
| `Path` | `/` |
| `Max-Age` | Until the session's **absolute** expiry: 90 days, or 12 hours for privileged users |

- **Why the absolute expiry:** the standard says `Max-Age` matches the session's expiry, but sessions slide: each use can push the 30-day idle expiry later, and Next.js can't rewrite cookies while rendering a page. A cookie set to the idle expiry would vanish while its session was still valid. Setting it to the latest the session can ever last means the cookie never outlives a session that's still usable, and the Go API ends it sooner when it's idle.
- **This needs one addition to the Go API:** the login responses gain `absolute_expires_at` beside `expires_at`. Adding a field is backward compatible.
- **A cookie whose session has ended** is treated as logged out: the session helper finds no user, and the page redirects to `/login`. Logging in again replaces the cookie.
- **Development on `http://localhost` works:** browsers treat localhost as secure, so `Secure` and `__Host-` cookies are kept there.

### Calling the Go API (Decision)

- **`src/lib/api/`** is the typed client. It's server-only (`import "server-only"`), so it can't end up in the browser bundle.
- **Every call sends** the token as `Authorization: Bearer`, the browser's IP as `X-Forwarded-For`, and the browser's user agent as `X-Forwarded-User-Agent` (§3). Without the last two, every rate limit would count the web server as one client, and every login would look like it came from the same device.
- **The browser's IP** is read from one header the hosting edge sets, named by the `CLIENT_IP_HEADER` setting, defaulting to Railway's `X-Real-IP`. Railway's edge overwrites that header on every request, according to its staff, but this is something to check on a real deploy before trusting it: the template's README says how. The Go API's `Config.TrustedProxies` must list Railway's private network, so it believes these headers only from the web app.
- **Responses are checked with Zod,** as the code-style standard recommends for our own API.
- **Errors:** the API's `message` is safe to show (§3), so forms show it as-is. Field errors in `details` are shown next to their field. `429` shows the message and how long to wait.

### Sessions in pages (Decision)

- **`getSession()`** calls `GET /v1/users/me` with the cookie's token and returns the user, or `null`. It's wrapped in React's `cache()`, so a page and its components share one call per request.
- **`requireSession()`** is what protected pages and server actions call. With no session, it redirects to `/login?next=<the current path>`. If 2FA setup is required, it redirects to the setup page.
- **`proxy.ts`** only checks that the cookie is there, and redirects to `/login` if not, before anything renders. It never calls the Go API: it's the fast first filter, and `requireSession()` is the real check.
- **`next` only accepts a path on this site** (starting with a single `/`), so the login page can't be used to send people to another site.

### Forms (Decision)

- **Every form posts to a server action,** which validates its input with Zod, calls the Go API, and sets or clears cookies. Server actions check the `Origin` header themselves, which with `SameSite=Lax` covers CSRF (the auth standard's §8).
- **The forms are small client components** using `useActionState`, to show errors without losing what was typed. They also work before JavaScript loads.
- **Logging out** deletes the session through the Go API, then clears the cookie. If the API can't be reached, the cookie is kept and the user is told to try again: the standard says clearing only the cookie isn't enough. A `401` means the session already ended, so the cookie is cleared.

### Tokens in email links (Decision)

- The token is after `#` (§6), which never reaches the server. So each link page has a small client component that reads it, removes it from the address bar with `history.replaceState`, and posts it to a server action.
- Pages that need more than the token (a new password, a 2FA code) show their form first and send the token with it.
- **Nothing happens on opening a link alone:** each page waits for a button press (verifying also asks for the password, as §6 requires), so mail scanners that open links don't change anything.
- **Invitations for a logged-out user** have to survive logging in or signing up first. The page moves the token into a 24-hour `HttpOnly` cookie, `__Host-invitation`, and the login and verification pages come back to `/accept-invitation` while it's set. It's cleared once accepted, or when the Go API says it's used up; an invitation for a different address is kept, so the user can log in with the right one.
- **After a password reset or email change**, which end every session, the session cookie is cleared and the login page says what happened. It only shows fixed messages, never text from the URL.

### 2FA at login (Decision)

- When a login answers with a 2FA challenge, the server action stores the challenge token in a second `HttpOnly` cookie, `__Host-two-factor`, that lasts as long as the challenge (5 minutes), and redirects to `/login/two-factor`.
- The code form sends the challenge token from that cookie. On success, the cookie is cleared and the session cookie set.
- The token stays out of the address bar and the page, and a reload doesn't lose it.

### OAuth on the web (Decision)

- **Starting:** the "Sign in with Google" button posts to a server action. It makes a random client verifier, keeps it in a 10-minute `HttpOnly` cookie, `__Host-oauth`, sends its SHA-256 to `POST /v1/oauth-flows`, and redirects the browser to the provider.
- **Finishing:** `/oauth/callback` is a route handler, not a page, since only route handlers and server actions can set cookies. It sends `code`, `state`, and the verifier from the cookie to `POST /v1/oauth-flows/complete`, clears the verifier cookie, and then sets the session cookie, or the 2FA cookie, and redirects.
- **No `Origin` check on the callback,** although the standard asks for one on route handlers that change data. The provider's redirect is a plain navigation, so there's no `Origin` to check. The verifier cookie protects it instead: only the browser that started the flow has it, which is what stops someone finishing their own flow in a victim's browser (§9). The handler's comment says so.
- **Linking** a provider from `/account` works the same way, with the user's session.
- **`/oauth/callback/mobile`** is a route handler that redirects to `MOBILE_OAUTH_REDIRECT_URL` (the app's deep link, e.g. `exampleapp://oauth`) with the same `code` and `state`. Without that setting it answers `404`.

### Settings

`src/lib/env.ts` validates these with Zod at startup:

| Variable | Example | Required |
|---|---|---|
| `API_URL` | `http://api.railway.internal:8080` | Yes |
| `OAUTH_PROVIDERS` | `google,github` | No (none) |
| `MOBILE_OAUTH_REDIRECT_URL` | `exampleapp://oauth` | No |
| `CLIENT_IP_HEADER` | `x-real-ip` | No (`x-real-ip`) |

None are `NEXT_PUBLIC_`, and none are secrets. They go in `.env.example` with fake values.

### Testing

- **Vitest** for `src/lib/` (the API client, the session helpers, the `next` check, cookie settings, error mapping), with **MSW** faking the Go API.
- **React Testing Library** for the form components: errors shown on the right field, the fragment token read and removed.
- **Playwright** against `examples/api` and Postgres, for the critical flows only:
  - logged out, `/dashboard` and `/account` redirect to `/login` without showing anything;
  - sign up, verify the email, and log in;
  - log in with 2FA;
  - log out, and the old cookie no longer works;
  - reset a password from the emailed link.
- **CI** gets a `web` job: `pnpm lint`, `tsc --noEmit`, Prettier, Vitest, `next build`, and Playwright. Dependabot updates the template's npm packages weekly, like the Go modules.

### PRs

1. **Go:** `absolute_expires_at` in the login responses, and `examples/api`.
2. **The template's base:** the app, `lib/env`, `lib/api`, the session helpers, the cookie, `proxy.ts`, log in, sign up, log out, 2FA at login, `/dashboard`, the CI job, and the first Playwright tests.
3. **Email-link pages:** verify email, forgot and reset password, confirm email change, accept invitation.
4. **`/account`:** password, email, 2FA, sessions, and the required-2FA redirect.
5. **OAuth:** the buttons, both callbacks, and linking and unlinking.

### Decisions

Confirmed in review on 2026-10-29:

1. **A runnable template app** in `templates/nextjs/`, of which projects copy the auth parts, versioned with the module, plus an `examples/api` Go server for development and tests.
2. **The pages in the table above,** plain and unbranded, including `/account`, and no Apple button.
3. **The session cookie lasts until the session's absolute expiry,** with `absolute_expires_at` added to the login responses.
4. **The API client forwards the browser's IP and user agent,** reading the IP from one header (`X-Real-IP` by default on Railway), to be checked on a real deploy.
5. **Server actions for every form,** a short-lived cookie for the 2FA challenge, and a route handler for the OAuth callback, protected by its verifier cookie instead of an `Origin` check.
6. **Tests:** Vitest and MSW for `lib/`, React Testing Library for forms, and Playwright against the example API for the five critical flows.
