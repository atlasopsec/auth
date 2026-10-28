# CLAUDE.md

## About this project

- **What it is:** `github.com/atlasopsec/auth`, the shared, versioned Go authentication module that every project's Go API imports: passwords, sessions, OAuth, 2FA, and RBAC. Its spec is `standards/auth.md` in `jakefrenzel/engineering-standards`.
- **Stack:** Go library (no `main`), PostgreSQL via `pgx`, `sqlc`, `goose` migrations embedded with `embed.FS`.
- **Run locally:** n/a (library). Use the examples and tests.
- **Run tests:** `go test -race ./...`
- **Lint / format:** `gofmt -l .` (must print nothing) and `golangci-lint run`

### Working in this repo

- **This repo is public.** Never commit secrets, real credentials, or real user data, not even in tests, examples, or fixtures. Use obviously fake values.
- **This is a library, not an app.** The standards on hosting, Next.js, mobile, and analytics apply to the projects that import it, not to this repo. It has no `cmd/` and no `internal/http` server. Exported Go API lives at the module root and in clearly named packages.
- **Every exported identifier is a public API.** Adding is fine. Removing, renaming, or changing the behavior of anything exported is a breaking change and needs a major version bump. Keep the exported surface small, and document every exported identifier with a doc comment.
- **Releases are semver tags** (`v1.4.0`). Don't tag releases; the user does.
- **Security first:** follow `standards/auth.md` exactly. If a requirement there is unclear or seems wrong, stop and ask the user instead of guessing. Every change needs tests for the failure cases, not just the happy path.
- **Dependencies:** prefer the standard library and `golang.org/x/crypto`. Every new dependency needs a reason in the PR description, since every project that imports this module inherits it.

## Engineering standards

Standards version: 2026-10-28

This project follows the shared standards in the `jakefrenzel/engineering-standards` repo.
The rules below are a summary. If something here is unclear, ask the user rather than guessing.

### Git workflow

- **Never push directly to `main`.** GitHub does not block it on our plan, so you must not do it. All changes go through a pull request.
- **Never force-push** to `main` or to a branch someone else is working on. Never rewrite history on `main`.
- Branch from the latest `main`. Branch names: `<type>/<short-description>`, lowercase and hyphenated (e.g. `feat/user-login`, `fix/crash-on-save`). Types: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `hotfix`.
- Commit messages and PR titles follow Conventional Commits: `<type>(<optional scope>): <summary>`
  - Types: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `perf`, `build`, `ci`, `style`, `revert`
  - Summary: imperative mood, lowercase, no trailing period, 72 characters max.
  - Breaking changes: add `!` after the type/scope and a `BREAKING CHANGE:` footer.
- PRs are squash-merged, so the PR title becomes the commit message on `main`. Get it right.
- Fill in every section of the PR template (`.github/pull_request_template.md`), and tick "Yes" under **AI assistance**.
- Keep PRs focused. Aim for under ~400 changed lines when practical.

### Merging

- **Do not merge PRs yourself unless the user explicitly tells you to.** AI-written changes must be reviewed by a human before merging.
- Never merge with failing CI. GitHub won't stop you on our plan, so check.

### Code style

Applies to Go and TypeScript (Next.js / Astro) code. Full rules: `standards/code-style.md`.

- Formatting is done by tools (`gofmt`/`goimports`, Prettier). Never hand-format or argue style. Run the formatter.
- Fix lint errors; don't silence them. Any `//nolint` or `eslint-disable` must name the rule and give a reason.
- Comments explain *why*, not *what*.
- **Go:**
  - App code goes in `internal/`, entry points in `cmd/`. No `util`/`helpers`/`common` packages.
  - Always check errors, wrap them with `%w`, compare with `errors.Is`/`errors.As`. No panics on bad input. Never send internal error details to clients.
  - `ctx context.Context` is the first parameter of anything doing I/O.
  - Log with `log/slog`. No package-level mutable state.
- **TypeScript:**
  - No `any`. Use `unknown` and narrow it.
  - Server components by default. `"use client"` only on small leaf components that need it.
  - Validate user input and env vars with Zod. Never put a secret in a `NEXT_PUBLIC_` variable.
  - Files `kebab-case`, components `PascalCase`, named exports (default exports only where Next.js/Astro require them).
- **Database / API:** tables plural `snake_case` with `id`, `created_at`, `updated_at`. Use `timestamptz`, never `timestamp`. JSON fields are `snake_case`; use them as-is on the frontend.
- **Architecture:** the Go API owns the database. Next.js never connects to Postgres directly.

### API design

Full rules: `standards/api-design.md`.

- All endpoints under `/v1/` (except `/healthz`). Plural `kebab-case` resources, nesting at most one level, actions as `POST /v1/<resource>/{id}/<verb>`. Methods: `GET`, `POST`, `PATCH`, `DELETE`; no `PUT`.
- Single items are returned as a plain object; lists as `{ "data": [...], "next_cursor": ... }` with cursor pagination (default 20, max 100). Never offset pagination.
- IDs are UUIDv7 strings. Timestamps RFC 3339 UTC. Money as integer cents plus a currency code, never floats. Fields are always present, `null` when empty.
- Errors always use `{ "error": { "code", "message", "request_id", "details" } }`. Codes are stable `snake_case` and never change. Messages never contain internals. `422` for validation failures, `404` for resources the user may not see.
- Changes must be backward compatible: add fields and endpoints freely; removing, renaming, or changing a field needs a new `/v2` endpoint.
- No CORS headers on the Go API.
- Update `api/openapi.yaml` in the same PR as any endpoint change.

### Dependencies

Full rules: `standards/dependencies.md`.

- Prefer the standard library and the chosen stack. Explain any new dependency in the PR description.
- Never edit lockfiles by hand.

### Testing

Full rules: `standards/testing.md`.

- Every bug fix comes with a test that fails without the fix.
- **A new test must be shown to fail without the change it covers.** Run it against the old code, or break the code temporarily, and confirm it fails.
- **Never change, weaken, skip, or delete an existing test to make it pass.** If a test looks wrong, stop and ask the user.
- Test behavior, not implementation. No tests that only check a mock was called.
- Tests are deterministic: no `sleep`, and no dependence on test order, the clock, or the network.
- **Go:** standard `testing` + `go-cmp`, table-driven tests, always `-race`. Database code is tested against a real Postgres (`testcontainers-go`), never a mock. Use hand-written fakes, not generated mocks.
- **TypeScript:** Vitest + React Testing Library, MSW to fake the Go API, Playwright for critical flows. Keep logic out of server components so it can be unit tested.
- Never use real customer data or real credentials in tests.

### Hosting

Full rules: `standards/hosting.md`.

- Everything runs on Railway: `web` (Next.js/Astro), `api` (Go), `postgres`. Don't add other hosting providers or services (Vercel, Supabase, Firebase, etc.).
- Next.js calls the Go API over Railway's private network. The Go API is not public unless the user says so. Postgres is never public.
- Every app has a `Dockerfile`, reads all config from environment variables, and listens on `PORT`. The Go API has a `GET /healthz` health check.
- Merging to `main` deploys to production automatically. Never deploy manually.
- Migrations must work with both the old and new code during a deploy. Rename or remove columns in two steps (add new and stop using old, then remove old later).
- Secrets live only in Railway variables. When adding a new environment variable, also add it to `.env.example` with a fake value.

### Auth and sessions

Full rules: `standards/auth.md`. Auth is security-critical. When in doubt, ask the user.

- Auth comes from the shared, versioned Go auth module, imported by the Go API. Never fork or edit its code in a project; changes go into the module and a new release. Don't add auth providers (Clerk, Auth0, Firebase Auth, Supabase Auth) or Next.js auth libraries (Auth.js, Better Auth), and don't write a second auth system.
- Passwords: argon2id, stored as the encoded `$argon2id$...` string in `users.password_hash`. Never log, store, or return a password, token, or 2FA code.
- Session tokens: 32 random bytes from `crypto/rand`, with only the SHA-256 hash stored. No JWTs for sessions. Cookie `__Host-session`, `HttpOnly`, `Secure`, `SameSite=Lax`. Logging out deletes the session in the database.
- OAuth: PKCE and `state` always. Match users by provider user ID, never by email. Link by email only when the provider says it's verified.
- 2FA is TOTP with recovery codes. Never SMS.
- **Permissions are enforced only in the Go API.** Check permissions (`can(user, "invoices:create")`), never role names. Every handler declares its permission, and access is denied by default. Queries on organization data always filter by `organization_id`.
- The Next.js proxy (`proxy.ts`) redirects logged-out users, but every protected page and server action must still verify the session with the Go API.
- Error messages never reveal whether an account exists.
- Auth changes need tests for the failure cases: wrong password, expired session, denied permission, another organization's data.

### Mobile apps

Full rules: `standards/mobile.md`. Applies to projects with a mobile app.

- React Native + Expo (TypeScript), Expo Router, development builds. Don't hand-edit or commit `ios/` and `android/`; use config plugins.
- Companion apps live in the same repo (`apps/mobile`) and share Zod schemas from `packages/shared`.
- Everything in the app bundle is public. No secrets in the app; only non-secret values use `EXPO_PUBLIC_`.
- Session token as `Authorization: Bearer`, stored only in `expo-secure-store`. Never AsyncStorage or logs.
- API changes must stay backward compatible with older app versions still in use. Add fields; never rename or remove them.
- OTA updates (EAS Update) for JavaScript bug fixes only. Native changes need a new store build.
- Push goes through Expo Push from the Go API. Firebase is used only for FCM credentials; never add other Firebase SDKs.
- Tests: Jest (`jest-expo`) + React Native Testing Library, MSW, and Maestro for end-to-end flows.

### Analytics and crash reporting

Full rules: `standards/analytics.md`.

- Errors and crashes go to **Sentry**; analytics go to **PostHog**. Don't add Google Analytics, Firebase Analytics, Crashlytics, or other tracking tools.
- Report only unexpected errors to Sentry (not validation failures or `404`s). Tag environment and release. Never serve source maps publicly.
- Important business events (sign-up, purchase, invite) are sent from the Go API, not the frontend.
- Event names are `object_action`, past tense, `snake_case` (`invoice_created`). Properties are `snake_case`. Add every new event to `docs/analytics.md`; never rename an existing event.
- **Never send personal data:** no passwords, tokens, payment details, message contents, emails, or names. Identify users by internal ID only. Sentry keeps `sendDefaultPii` off and scrubs `Authorization`/`Cookie` headers.
- PostHog stays cookieless until the user consents. Session replay is off unless the user says otherwise. Feature flags are never used for permissions.

### Before opening or updating a PR

- Run lint, formatting, and tests locally (see commands above) and make sure they pass.
- Review your own diff.
- Never commit secrets, credentials, API keys, or `.env` files. If you find one already committed, stop and tell the user so it can be rotated.
