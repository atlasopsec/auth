# Changelog

What changed in each release of `github.com/atlasopsec/auth`. The Next.js template has its own: [templates/nextjs/CHANGELOG.md](templates/nextjs/CHANGELOG.md).

The exported Go API and the HTTP endpoints follow [semantic versioning](https://semver.org): a minor release only adds, and anything removed or changed waits for the next major version.

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
