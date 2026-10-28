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

Every project needs an `AUTH_ENCRYPTION_KEY`: 32 random bytes, base64-encoded, passed as `Config.EncryptionKey`. It encrypts users' 2FA secrets.

```sh
openssl rand -base64 32
```

Keep it in Railway's variables with the other secrets, and **back it up**. If it's lost, every user who has 2FA on has to set it up again.

## Design

How the module is structured and how projects use it: [docs/design.md](docs/design.md). The public Go API and HTTP endpoints: [docs/api.md](docs/api.md).

## Roadmap

- [x] Password hashing and secure token generation
- [x] Database schema, embedded migrations, and sessions
- [x] HTTP middleware, sign-up, login, and session endpoints
- [x] Email verification and password reset
- [x] Email change
- [x] Roles, permissions, and organizations
- [ ] Two-factor authentication (TOTP)
- [ ] OAuth: Google, GitHub, Apple
- [ ] Rate limiting, security event log, and email sending
- [ ] `v1.0.0`

## Security

Found a vulnerability? Please report it privately. See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
