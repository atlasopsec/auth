# auth

Shared Go authentication module: sessions, passwords, OAuth, 2FA, and RBAC.

> **Status: pre-release.** Under active development. The API will change until `v1.0.0`. Don't use it in production yet.

```go
import "github.com/atlasopsec/auth"
```

## What it does

Built for Go APIs that own their own Postgres database, with Next.js web apps and React Native mobile apps as clients.

- **Passwords:** argon2id hashing, breached-password checks, reset and email verification flows
- **Sessions:** random opaque tokens (only hashes stored), cookie and bearer-token support, expiry, "log out everywhere"
- **Sign in with Google, GitHub, and Apple:** OAuth with PKCE, safe account linking
- **Two-factor authentication:** TOTP with recovery codes
- **Roles and permissions (RBAC):** `resource:action` permissions, organizations, deny by default
- **Abuse protection:** rate limiting, no account enumeration, security event log

The design follows the auth standard in [`jakefrenzel/engineering-standards`](https://github.com/jakefrenzel/engineering-standards).

## Encryption key

Every project needs an `AUTH_ENCRYPTION_KEY`: 32 random bytes, base64-encoded, passed as `Config.EncryptionKey`. It encrypts users' 2FA secrets, and the PKCE verifiers of sign-ins in progress.

```sh
openssl rand -base64 32
```

Keep it in Railway's variables with the other secrets, and **back it up**. If it's lost, every user who has 2FA on has to set it up again. Until then they can't log in; turn their 2FA off with `ResetTwoFactor`.

## Sign in with Google, GitHub, and Apple

Turn on a provider with its client ID and secret, keeping the secret in a Railway variable:

```go
OAuth: auth.OAuth{
	Google: &auth.Google{ClientID: "…", ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET")},
	GitHub: &auth.GitHub{ClientID: "…", ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET")},
	Apple:  &auth.Apple{BundleIDs: []string{"com.example.app"}},
},
```

At each provider, register these redirect URIs, both served by the web app:
- `{AppURL}/oauth/callback`
- `{AppURL}/oauth/callback/mobile`, which hands the result to the mobile app's deep link

Use a Google OAuth client of type "Web application". For GitHub, register `{AppURL}/oauth/callback` as the callback URL; GitHub accepts paths under it.

Apple is native Sign in with Apple in the iOS app only, which Apple requires when an iOS app offers Google or GitHub. It needs only the app's bundle ID: the app sends Apple's signed token to `POST /v1/apple-sign-ins`.

## Users locked out of 2FA

A user who has lost both their authenticator and their recovery codes can't get back in by themselves. After confirming who they are some other way, support turns their 2FA off from admin tooling:

```go
err := a.ResetTwoFactor(ctx, userID) // also ends their sessions and emails them
```

There's no endpoint for it, on purpose.

## Rate limits and cleanup

The module rate-limits logins, sign-ups, emails, and sign-in starts per client IP, and emails per address, in Postgres, so every API instance shares the counts. Repeated wrong passwords slow down further attempts, growing to 15 minutes, but never lock an account. Limited requests get `429 rate_limited` with `Retry-After`. The limits are in [docs/api.md §10](docs/api.md).

A background job deletes expired sessions, links, and other short-lived rows every hour. To run it on your own schedule instead, set `Config.DisableCleanup` and call `a.Cleanup(ctx)`.

## Design

How the module is structured and how projects use it: [docs/design.md](docs/design.md). The public Go API and HTTP endpoints: [docs/api.md](docs/api.md).

## Roadmap

- [x] Password hashing and secure token generation
- [x] Database schema, embedded migrations, and sessions
- [x] HTTP middleware, sign-up, login, and session endpoints
- [x] Email verification and password reset
- [x] Email change
- [x] Roles, permissions, and organizations
- [x] Two-factor authentication (TOTP)
- [x] OAuth: Google, GitHub, Apple
- [ ] Rate limiting, security event log, and email sending
- [ ] `v1.0.0`

## Security

Found a vulnerability? Please report it privately. See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
