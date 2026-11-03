# Changelog

What changed in each release of `github.com/atlasopsec/auth`. The Next.js template has its own: [templates/nextjs/CHANGELOG.md](templates/nextjs/CHANGELOG.md).

The exported Go API and the HTTP endpoints follow [semantic versioning](https://semver.org): a minor release only adds, and anything removed or changed waits for the next major version.

## Unreleased

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
