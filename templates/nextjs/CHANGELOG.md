# Changelog

Changes to the Next.js template. Projects that copied it can check here what to copy again.

## 0.1.0

The first version, for the auth module's `v1.0.0`:

- The `__Host-session` cookie, lasting until the session's absolute expiry.
- `proxy.ts`, `getSession`, and `requireSession`.
- The Go API client, forwarding the browser's IP and user agent.
- Log in, 2FA at login, sign up, and log out.
- `/account`: change password and email, see sessions and log any of them out, or log out everywhere. `/account/two-factor`: turn 2FA on (with a QR code) or off, and get new recovery codes. Users who must have 2FA are sent there until they set it up.
- Sign in with Google and GitHub: the buttons, `/oauth/callback`, `/oauth/callback/mobile`, and linking and unlinking providers on `/account`.
- The pages email links open: verify email, reset password, confirm an email change, and accept an invitation. Plus forgot password and "send a new verification link".
