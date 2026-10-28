# Design

How the auth module is structured, and how a project's Go API uses it. The **what** (security requirements) is defined in the [auth standard](https://github.com/jakefrenzel/engineering-standards/blob/main/standards/auth.md); this doc is the **how**.

> **Status: approved.** The design decisions are recorded in [§13](#13-decisions). Details may still change as the code is built; any change to the exported API or the database layout updates this doc in the same PR.

---

## 1. The big picture

```
                         Project's Go API (one binary)
 ┌──────────────┐  Bearer  ┌───────────────────────────────────────────────┐
 │ Next.js      │  token   │  project routes          auth module          │
 │ (server)     ├─────────▶│  ┌──────────────┐        ┌──────────────────┐ │
 └──────────────┘          │  │ /v1/invoices │──uses─▶│ a.Require(perm)  │ │
 ┌──────────────┐  Bearer  │  └──────────────┘        │ auth.UserFrom()  │ │
 │ Mobile app   ├─────────▶│  ┌──────────────┐        │                  │ │
 └──────────────┘  token   │  │ /v1/users    │◀─mount─│ a.Register(mux)  │ │
                           │  │ /v1/sessions │        │ (signup, login,  │ │
                           │  │ ...          │        │  2FA, OAuth...)  │ │
                           │  └──────────────┘        └────────┬─────────┘ │
                           └───────────────────────────────────┼───────────┘
                                                               ▼
                                   Postgres:  auth.*  tables   +  project's public.* tables
```

- The module is a **library** compiled into each project's Go API. No separate service, no network hop.
- It provides **ready-made HTTP endpoints** for everything auth (sign up, log in, 2FA, OAuth, password reset), plus **middleware** projects wrap their own routes in.
- **The Go API only understands `Authorization: Bearer <token>`.** It never sets cookies. The browser never talks to the Go API, so cookies are handled entirely by Next.js:
  - Next.js receives the token from the login endpoint and stores it in the `__Host-session` cookie.
  - On each request, Next.js reads the cookie and forwards the token as a bearer header.
  - Mobile apps send the same header from secure storage.

  One code path for web and mobile.

## 2. How a project uses it

```go
import (
    "github.com/atlasopsec/auth"
    "github.com/atlasopsec/auth/mail/resend"
)

func main() {
    pool := mustConnectPostgres(ctx, os.Getenv("DATABASE_URL"))

    // Run the module's migrations (auth.* tables) before the project's own.
    if err := auth.Migrate(ctx, pool); err != nil { ... }

    a, err := auth.New(auth.Config{
        DB:       pool,                                       // *pgxpool.Pool
        Mailer:   resend.New(os.Getenv("RESEND_API_KEY"), "Example <no-reply@mail.example.com>"),
        AppURL:   "https://app.example.com",                  // for links in emails
        AppName:  "Example",
        OrgRoles: orgRoles,                                   // see §6
        AppRoles: appRoles,
        Hooks: auth.Hooks{
            OnUserCreated: func(ctx context.Context, tx pgx.Tx, u auth.User) error { ... }, // e.g. create a profile row
        },
        // Added in later steps: EncryptionKey (2FA), OAuth.
    })
    if err != nil { ... }
    defer a.Close(ctx)                                       // waits for emails still being sent

    mux := http.NewServeMux()
    a.Register(mux)                                          // the module's auth endpoints (§5)
    mux.Handle("GET /v1/invoices", a.RequireOrg("invoices:read", listInvoices))  // project routes
    mux.Handle("POST /v1/invoices", a.RequireOrg("invoices:create", createInvoice))

    http.ListenAndServe(":"+os.Getenv("PORT"), a.Protect(mux)) // deny by default (§6)
}

func listInvoices(w http.ResponseWriter, r *http.Request) {
    user, _ := auth.UserFrom(r.Context())   // always present behind RequireOrg
    org, _ := auth.OrgFrom(r.Context())
    // ... query invoices WHERE organization_id = org.ID
}
```

- `a.RequireOrg(permission, handler)` loads the session, rejects missing or expired ones (`401`), checks the user is a member of the organization in `X-Organization-ID` (`404` if not), checks the permission (`403`), and only then calls the handler. `a.Require` does the same with the user's app role. See api.md §7.
- **Deny by default:** `a.Protect(mux)` refuses any request whose route isn't wrapped by `Public`, `Authenticated`, `Require`, or `RequireOrg`.
- `auth.UserFrom(ctx)` gives handlers the current user. Its `ok` result is always true behind those wrappers.

## 3. Package layout

| Package | Exported? | What's in it |
|---|---|---|
| `auth` (root) | Yes | `New`, `Config`, `Migrate`, `User`, `Organization`, `Require`/`Public`, `UserFrom`, `Handler`, hooks, error codes |
| `auth/rbac` | Yes | `Permission`, `Role`, role definitions, `Can` |
| `auth/mail` | Yes | The `Mailer` interface, `Message`, and `Writer` for local development |
| `auth/mail/resend` | Yes | Resend adapter, in its own package so projects that don't use Resend don't pull it in |
| `auth/mail/mailtest` | Yes | `Recorder`, a fake `Mailer` for tests |
| `internal/password` | No | argon2id hashing, verification, re-hash detection, breached-password check |
| `internal/token` | No | Random tokens, SHA-256 hashing, constant-time compare |
| `internal/session` | No | Create, validate, extend, revoke sessions |
| `internal/emailtoken` | No | Single-use email tokens (verify, reset, change email), with the send cooldown |
| `internal/sender` | No | Sends email in the background, with retries |
| `internal/httpapi` | No | Error format, strict JSON decoding, request IDs, client IP behind proxies |
| `internal/totp` | No | TOTP and recovery codes |
| `internal/oauth` | No | Google, GitHub, Apple flows with PKCE and `state` |
| `internal/ratelimit` | No | Postgres-backed rate limiting |
| `internal/db` | No | sqlc-generated queries |
| `internal/migrate` | No | Applies the embedded migrations; `auth.Migrate` wraps it |
| `internal/migrations` | No | goose SQL migrations, embedded and applied by `auth.Migrate` |

Keeping almost everything in `internal/` means projects **can't** reach into the security-critical parts directly. The public API stays small, which also makes it easier to keep backward compatible.

## 4. Database

### Tables live in their own Postgres schema

All module tables live in a Postgres **schema** named `auth`, separate from the project's tables in `public`:

```
auth.users              id, email, email_verified_at, password_hash, two_factor_required, created_at, updated_at
auth.sessions           id, user_id, token_hash, client (web|mobile), ip, user_agent, last_used_at, expires_at, absolute_expires_at, created_at
auth.oauth_accounts     id, user_id, provider, provider_user_id, created_at
auth.totp_secrets       user_id, secret_encrypted, confirmed_at, created_at
auth.recovery_codes     id, user_id, code_hash, used_at, created_at
auth.email_tokens       id, user_id, purpose (verify|reset|change), token_hash, expires_at, used_at, created_at
auth.organizations      id, name, created_at, updated_at
auth.memberships        id, user_id, organization_id, role, created_at, updated_at
auth.auth_events        id, user_id, event, ip, user_agent, metadata, created_at
auth.rate_limits        key, window_start, count
```

- **Why a schema:** no name collisions (a fitness app can still have its own `public.sessions` table), and it's obvious which tables the module owns.
- **Projects never `ALTER` module tables.** To store extra data about a user or organization, a project creates its own table that references the module's:

  ```sql
  CREATE TABLE user_profiles (
      user_id    uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
      full_name  text,
      ...
  );
  ```

  The `OnUserCreated` hook is where a project creates that row.
- All IDs are UUIDv7 and all timestamps `timestamptz`, per the [API design standard](https://github.com/jakefrenzel/engineering-standards/blob/main/standards/api-design.md).

### Migrations

- SQL migrations are embedded in the module (`embed.FS`) and run by `auth.Migrate(ctx, pool)`, using goose with its own version table (`auth.goose_db_version`), so they never interfere with the project's own migrations.
- Projects call `auth.Migrate` in their pre-deploy step, before their own migrations.
- Module migrations follow the same rule as projects: always backward compatible with the previous release.

## 5. HTTP endpoints

`a.Register(mux)` adds these, following the [API design standard](https://github.com/jakefrenzel/engineering-standards/blob/main/standards/api-design.md) (resource URLs, error format, `/v1`). Logging in is "creating a session"; signing up is "creating a user".

| Endpoint | What it does | Auth |
|---|---|---|
| `POST /v1/users` | Sign up with email + password | Public |
| `GET /v1/users/me` | Current user, their organizations and roles | Session |
| `POST /v1/sessions` | Log in with email + password. Returns a token, or a 2FA challenge | Public |
| `POST /v1/two-factor-challenges/{id}/verify` | Finish login with a TOTP or recovery code | Public (challenge ID) |
| `GET /v1/sessions` | List my active sessions | Session |
| `DELETE /v1/sessions/current` | Log out | Session |
| `DELETE /v1/sessions/{id}` | End one of my other sessions | Session |
| `DELETE /v1/sessions` | Log out everywhere | Session |
| `POST /v1/email-verifications` / `.../confirm` | Send / confirm email verification. Sending takes an email and always returns `202`, like password reset, so it works before the user can log in. Confirming takes the token and password in the body (see api.md §6) | Public |
| `POST /v1/password-resets` / `.../confirm` | Request / complete password reset. The token goes in the body, never the path | Public |
| `POST /v1/email-changes` / `.../confirm` | Start / finish changing email | Session / Public |
| `POST /v1/users/me/password` | Change password (requires current password) | Session |
| `POST /v1/users/me/two-factor` / `.../confirm` / `DELETE` | Set up, confirm, turn off 2FA | Session |
| `GET /v1/oauth/{provider}/start` / `POST .../callback` | Sign in with Google, GitHub, Apple | Public |
| `GET /v1/organizations/{id}/members` and related | Manage members and roles | `members:manage` |

Login responses return the token **once**, in the JSON body:

```json
{ "token": "…", "expires_at": "2026-11-27T05:00:00Z", "user": { "id": "…", "email": "…" } }
```

Next.js puts it in the cookie; mobile puts it in secure storage. The module never sees it again in plain form; only its hash is stored.

### Error codes

All errors use the standard format. The module's stable codes include: `invalid_credentials`, `email_taken`, `email_not_verified`, `two_factor_required`, `invalid_two_factor_code`, `session_expired`, `unauthenticated`, `forbidden`, `token_invalid_or_expired`, `oauth_failed`, `rate_limited`.

## 6. Roles and permissions

Projects define their roles in Go. There are two optional sets: **organization roles** (a user's role in each organization) and **app roles** (one role per user, across the whole app). See api.md §7.

```go
var orgRoles = rbac.Roles{
    "owner":  {rbac.All},                                                    // every permission
    "admin":  {"invoices:read", "invoices:create", "members:read", "members:manage", "organization:update"},
    "member": {"invoices:read", "invoices:create", "members:read"},
    "viewer": {"invoices:read"},
}.RequireTwoFactor("owner", "admin")   // step 6: privileged roles must use 2FA, with 12-hour sessions

var appRoles = rbac.Roles{
    "support": {"users:read", "users:ban"},
}
```

- `RequireOrg` checks the user's role **in the current organization**. The organization comes from the `X-Organization-ID` request header, and the module verifies the user is actually a member.
- `Require` checks the user's app role.
- **Deny by default:** `a.Protect(mux)` wraps the project's whole router and refuses (`500`, logged) any request whose route wasn't wrapped by `Public`, `Authenticated`, `Require`, or `RequireOrg`, so a forgotten permission fails closed. Go's `ServeMux` can't list its routes, which rules out a `CheckRoutes` test helper. See api.md §7.
- Projects without organizations (simple consumer apps) use only app roles.

## 7. Email

The module sends verification, password reset, and security notice emails through the `mail.Mailer` interface:

```go
type Mailer interface {
    Send(ctx context.Context, m Message) error
}
```

- `auth/mail/resend` is the standard implementation. Tests use a fake that records messages.
- Default templates are plain and brandless. Projects **MAY** override subject and body per email type with their own branding.

## 8. Other design choices

- **Rate limiting is stored in Postgres**: it works across multiple API instances without adding Redis. Auth endpoints are low-volume, so the database load is small.
- **TOTP is implemented in the module**, about 50 lines of standard library code (RFC 6238), instead of adding a dependency.
- **Breached-password checks** call the Have I Been Pwned range API. If it's unreachable, the check is skipped and logged, rather than blocking sign-up.
- **Client IP:** rate limits and the event log need the real user's IP, but requests arrive via Next.js. Next.js forwards it in `X-Forwarded-For`, and the module only trusts that header from configured private-network sources (`Config.TrustedProxies`).
- **Time is injectable** (`Config.Now`) so tests can control expiry without sleeping.

## 9. Dependencies

| Dependency | Why |
|---|---|
| `github.com/jackc/pgx/v5` | Postgres driver (the stack standard) |
| `github.com/pressly/goose/v3` | Running embedded migrations |
| `golang.org/x/crypto` | argon2id |
| `golang.org/x/oauth2` | OAuth flows |
| `github.com/google/uuid` | UUIDv7 |
| `github.com/resend/resend-go` | Only in `auth/mail/resend` |
| `github.com/google/go-cmp`, `github.com/testcontainers/testcontainers-go` | Tests only |

`sqlc` is a code generator; its generated code is committed, so it isn't a runtime dependency.

## 10. The Next.js side

A small template in this repo (`templates/nextjs/`), copied into projects, provides:

- `proxy.ts`: redirects to `/login` when the `__Host-session` cookie is missing,
- `lib/auth.ts`: `getSession()`, which calls `GET /v1/users/me` with the token from the cookie. Every protected page and server action calls it,
- server actions for log in, log out, and sign up, which call the Go API and set or clear the cookie,
- basic login, sign-up, and 2FA pages to restyle per project.

## 11. Testing

- Pure logic (password hashing, tokens, TOTP) has table-driven unit tests, including known test vectors (e.g. RFC 6238 for TOTP).
- Everything touching the database is tested against a real Postgres via `testcontainers-go`.
- Endpoints are tested through `httptest` against a mux with `a.Register`, covering every failure case in the auth standard: wrong password, unknown email, expired sessions, reused tokens, denied permissions, cross-organization access.

## 12. Build order

Each step is one or more small PRs:

1. `internal/token` and `internal/password`
2. Migrations, `internal/db`, `internal/session`
3. `auth.New`, `Require`, `UserFrom`, plus sign up, log in, log out, sessions endpoints, and the error format
4. Email verification, password reset, password change, email change, `auth/mail`, `auth/mail/resend`
5. RBAC: `auth/rbac`, organizations, memberships, invitations, `Protect`
6. 2FA (TOTP, recovery codes, challenges)
7. OAuth (Google, GitHub, Apple)
8. Rate limiting, the event log, security notice emails
9. The Next.js template
10. `v1.0.0`

## 13. Decisions

Decided on 2026-10-28:

| # | Question | Decision | Why |
|---|---|---|---|
| 1 | Where module tables live | **A separate Postgres schema, `auth`** | No collisions with project tables, and it's obvious which tables the module owns |
| 2 | Who owns organizations | **The module owns a minimal `auth.organizations` table** (id, name). Projects store extra organization data in their own tables | Team management is security-adjacent, so it belongs in the shared, tested code instead of being rebuilt per project |
| 3 | How a request names its organization | **The `X-Organization-ID` header** | Short URLs, one place that checks membership, and it fits the API standard's one-level nesting limit |
| 4 | Where rate limits are stored | **Postgres** | Works across multiple API instances without adding Redis |
| 5 | TOTP | **Implemented in-house** (RFC 6238), tested against the RFC's official test vectors | One less dependency in security-critical code |
