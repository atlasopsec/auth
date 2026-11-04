# Changelog

What changed in each release of `github.com/atlasopsec/auth`. The Next.js template has its own: [templates/nextjs/CHANGELOG.md](templates/nextjs/CHANGELOG.md).

The exported Go API and the HTTP endpoints follow [semantic versioning](https://semver.org): a minor release only adds, and anything removed or changed waits for the next major version.

## v1.5.0

The fixes from a security audit.

- **Run `Migrate` before deploying.** This release adds migrations `00012`, indexes built with `CREATE INDEX CONCURRENTLY`, and `00013`, a nullable column on `auth.two_factor_failures`. Neither changes existing rows.
- **Signing in with Google, GitHub, or Apple** to an existing account by its email now needs an address the provider runs; see below.
- **Mobile apps** should send `device_token` to the 2FA step and keep the one it returns.
- **If you use the Next.js template,** its 0.5.0 needs this release.

### Security

- **Login delays hold under concurrent attempts.** The delay was checked before the password and the failure counted after it, so attempts sent at once, from many IPs, were all checked: about one guess per IP each time the account-wide delay ended, instead of one. Each attempt is now counted before its password is checked, under a lock, and taken back if the password is right.
- **A provider signs in to an existing account by its email only when it runs that address,** answering `409 oauth_link_required` otherwise. A provider's "verified" can be years old: a work address stays verified at Google or GitHub after it's given to someone else, and whoever had it before could sign in to the new holder's account.
  - **Counts as the provider's own:**
    - **Google:** `@gmail.com`, and Google Workspace accounts (`hd`).
    - **Apple:** Hide My Email and iCloud Mail addresses.
    - **GitHub:** never.
  - **Otherwise,** the user logs in the way they usually do and links the provider from settings. An account whose email isn't verified is no longer taken back by such a provider either. New accounts are still created from any verified address.
  - **Apple can't be linked from settings,** so someone whose Apple ID uses another address that an account here already uses can't sign in with Apple.
- **Devices where a 2FA code was entered get their own guessing limit.** Ten wrong codes in 15 minutes paused 2FA for the whole account, so anyone with the password could keep the owner from ever logging in.
  - `POST /v1/two-factor-challenges/verify` now takes the `device_token` from the challenge. With a right code, it answers with a new one that records a code was entered on the device.
  - Wrong codes sent with such a token count only toward that device's limit.
  - A device token from the password alone doesn't count, since someone guessing codes has the password too.
- **Inviting an address again no longer replaces an invitation you couldn't cancel,** such as an owner's invitation for a role you couldn't grant. The check runs under the organization's lock, with your current role.
- **Finishing a link flow applies the 12-hour limit for privileged roles,** as every other request does.
- **`POST /v1/email-changes` looks up the new address after responding,** like password resets and verification, so the response and its timing don't show whether it's taken. A database error there is logged instead of returning `500`.
- **Email subjects are kept to one line:** control characters, such as a line break in an organization's name, become spaces. A `Mailer` that writes headers itself could otherwise be given extra ones.
- **The cleanup job deletes accepted and expired invitations,** which hold email addresses and were kept forever.

### Added

- `device_token` in the request to, and the response from, `POST /v1/two-factor-challenges/verify`.
- The `oauth_link_required` error code (`409`), from `POST /v1/oauth-flows/complete` and `POST /v1/apple-sign-ins`.

### Changed

- `GET /v1/sessions` returns at most the 100 most recently used sessions.
- `Migrate` runs migrations on connections of its own, made from the pool's settings and closed afterwards. The pool's hooks, such as `AfterConnect`, don't run on them.

### Fixed

- **Migrations no longer leave a 5-second `lock_timeout` on a project's pool connection.** Since v1.4.0, migration `00011`'s `SET lock_timeout` outlasted its transaction on a connection `Migrate` had borrowed from the pool, so some of the project's queries gave up after waiting 5 seconds for a lock. A restart, such as deploying this release, clears it.
- **Indexes on foreign keys that had none:** `auth.auth_events (actor_id)`, `auth.invitations (organization_id)`, and `auth.oauth_flows (user_id)`. Deleting a user or an organization no longer reads those whole tables.
- **Signing in with a second account at a provider** returns `401 oauth_failed` instead of `500`. This is a second account whose verified email belongs to a user who already linked another account with that provider.
- **Finishing a 2FA login no longer deadlocks** with a 2FA or password reset for the same user, which answered `500`.
- **A panic in a project's `Mailer`** counts as a failed send, and is retried, instead of stopping the process.
- **A client that disconnects mid-request** is logged at debug, not as an error.

## v1.4.0

Run `Migrate` before deploying: this release adds the `auth.used_apple_nonces` table. In verify first mode (the default), `Hooks.OnUserCreated` now runs just after the sign-up response; see below.

### Security

- An Apple identity token now signs in only once. `POST /v1/apple-sign-ins` records each token's nonce (as a SHA-256 hash) until the token expires, and refuses a token whose nonce was already used with `401 oauth_failed`. Before, a captured token and nonce could sign in again until the token expired. Apps must make a new nonce for every sign-in. Adds the `auth.used_apple_nonces` table; run `Migrate`.
- `POST /v1/password-resets` and `POST /v1/email-verifications` now look up the account and create its link after responding, so the response time no longer shows whether the address has an account. A database error there is now logged instead of answered with `500`.
- In verify first mode (the default), `POST /v1/users` now answers `202` right after hashing the password, and creates the user (or emails the existing account's owner) afterwards, so the response time no longer shows whether the address has an account. This changes when `Hooks.OnUserCreated` runs: just after the response rather than before it, with the request's context values. A hook error other than `ErrSignUpNotAllowed`, or a database error, is now logged as an error instead of answered with `500`. A project test that signs up and immediately reads the new user may need to wait for it. With `AllowUnverifiedLogin` nothing changes.

## v1.3.0

If you use the Next.js template, see its 0.4.0 changes for an option that requires an https mobile deep link.

### Security

- Turning 2FA on or off, or replacing the recovery codes, now ends every other session, as a password change does.
- An invitation now stops working once whoever sent it is removed from the organization, or no longer has `members:manage` and every permission in the invited role. Accepting it fails like an expired link (`422 token_invalid_or_expired`).
- Changing a member's role or removing a member now checks `members:manage` again under the organization's lock, so someone demoted at the same moment can't still make the change.
- The breached-password check's errors, which are logged as a warning, no longer include the request URL, which ended in the first 5 characters of the password's SHA-1 hash.

### Fixed

- Two first sign-ins with a provider for the same address at the same time, such as two tabs or Google and GitHub, both succeed as the same user. The slower one used to fail with `500 internal_error`.

## v1.2.0

### Security

- A password reset, or a password change, now cancels every unused email link sent for the account. Before, an email change asked for by someone with the password, or a reset link someone else had asked for, kept working after the owner reset or changed the password, and confirming it could hand over the account.
- Taking back an account whose email was never verified, with a password reset or by signing in with a provider, now also removes its linked providers. With `AllowUnverifiedLogin`, someone who signed up first with another person's address could link their own provider and keep logging in after the owner took the account back. A reset of such an account also turns off its 2FA, and no longer asks for a 2FA code.
- Turning on 2FA and linking a provider now need a verified email (`403 email_not_verified`).
- Wrong 2FA codes on `POST /v1/users/me/two-factor/confirm`, `DELETE /v1/users/me/two-factor`, and `POST /v1/users/me/two-factor/recovery-codes` now count toward the same per-user and per-IP guessing limits as logging in. Before, a stolen session could guess codes there without limit.
- The limit on wrong current passwords is now counted before the password is checked, so concurrent requests can't get past it, and `POST /v1/users/me/password` has the per-IP login limit.
- Linking a provider to an existing account by its verified email at sign-in now emails the `OAuthLinked` notice, as linking one from settings does.
- The daily limit on emails to one address is now counted per address and IP, so nobody can use it up to stop the owner getting their own reset and verification emails.
- Anyone could keep the account-wide login delay running for an email with a wrong password every 15 minutes, which kept its owner from logging in with their password. A login with the password now returns a `device_token`, in the session and in the 2FA challenge; sent with the next `POST /v1/sessions` as `device_token`, it replaces the account-wide count with one for that token alone (5 failures, then the same delays). Web apps keep it in a `__Host-device` cookie (see the Next.js template's changelog), and mobile apps in secure storage. Apps that don't send it work as before.

### Added

- `device_token` in the request to `POST /v1/sessions`, and in login and 2FA challenge responses (`null` except after a login with the password).

## v1.1.0

Includes the security fix from v1.0.2.

### Added

- `ErrSignUpNotAllowed`. Return it from `Hooks.OnUserCreated` to refuse a sign-up, for example from an address that isn't on an allowlist. The sign-up is rolled back and logged at Info instead of Error. In verify first mode the response is the same `202 {"verification_required": true}` an accepted sign-up gets, with no email sent, so the endpoint doesn't reveal which addresses are allowed. With `AllowUnverifiedLogin`, and for sign-ups with Google, GitHub, or Apple, the answer is `403 sign_up_not_allowed`. Until now, any error from the hook, including a deliberate refusal, was a `500 internal_error` logged as an error, which told callers which addresses were allowed.

## v1.0.2

### Security

- Upgrade `github.com/go-jose/go-jose/v4` (an indirect dependency, through `coreos/go-oidc`) from v4.1.4 to v4.1.6. v4.1.4 is affected by GHSA-mgcc-cww5-fp2q (denial of service from crafted RSA keys in JWKs), GHSA-4w3g-jfj2-cw2q (panic in CBC-HMAC decryption), and GHSA-vvm8-gf78-28g4 (panics in JSON parsing). govulncheck didn't report them, but image scanners such as Trivy do.

## v1.0.1

### Security

- Build with Go 1.26.10 (`toolchain go1.26.10`). govulncheck found 32 vulnerabilities in the Go 1.26.0 standard library that the module's code can reach, in `net/http`, `crypto/tls`, `crypto/x509`, `net/url`, `net/mail`, and others.
- Upgrade `github.com/moby/go-archive` (an indirect dependency, through testcontainers) from v0.2.0 to v0.3.0, for GO-2026-6253: tar extraction could write outside the target folder.

### Changed

- The Go tools used to develop the module (goimports, golangci-lint, govulncheck, sqlc, goose) are pinned in `tools/go.mod`, so projects that import the module don't inherit them.

## v1.0.0

The first stable release, implementing the [auth standard](https://github.com/jakefrenzel/engineering-standards/blob/main/standards/auth.md):

- **Sign-up and login** with email and password: argon2id, breached-password checks, and verify first by default (`AllowUnverifiedLogin` to opt out).
- **Sessions:** 32-byte random tokens stored as SHA-256 hashes, 30 days idle and 90 days at most, 12 hours for privileged roles. Listing and ending sessions, and logging out everywhere.
- **Email:** verification, password reset, email change, invitations, and security notices, through `mail.Mailer` (`mail/resend` in production). Templates can be overridden.
- **Roles and permissions:** app roles and organization roles (`rbac`), `Require`, `RequireOrg`, `Can`, deny by default with `Protect`, organizations, members, and invitations.
- **Two-factor authentication:** TOTP with recovery codes, required for privileged roles (`TwoFactorRoles`) or individual users, and `ResetTwoFactor` for support.
- **Sign in with Google, GitHub, and Apple** (native iOS), with PKCE, a client verifier, and linking and unlinking.
- **Abuse protection:** per-IP and per-address rate limits, growing delays after failed logins (never a lockout), and responses that never reveal whether an account exists.
- **Security event log** (`auth.auth_events`), with `Events` for admin tooling, `Hooks.OnEvent`, and `Actor` to record who made admin changes.
- **New-device emails,** and an hourly cleanup job.
- Migrations embedded and run with `Migrate`, in their own `auth` schema.
- [`examples/api`](examples/api/main.go), an example Go API, and the [Next.js template](templates/nextjs/README.md).
