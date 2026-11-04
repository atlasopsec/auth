# Changelog

Changes to the Next.js template. Projects that copied it can check here what to copy again.

## 0.5.0

Works with the auth module's `v1.5.0` and later: the 2FA step now sends `device_token`, which earlier versions refuse as an unknown field (`400`). Every copied file's header comment now says 0.5.0, but files not named here are otherwise unchanged.

- **Security:** the security standard's nonce-based Content Security Policy, on every page. Only scripts carrying the response's nonce run, so a script injected through a bug doesn't. See "Content Security Policy" in the README.
  - Copy `src/proxy.ts`, the new `src/lib/csp.ts`, and `next.config.ts`, and add `export const dynamic = "force-dynamic";` to your root layout.
  - **Move your protected paths** from `proxy.ts`'s `matcher` to its new `PROTECTED` list. The proxy now runs on every page, to set the policy, and redirects logged-out visitors only on those paths.
  - **Every page is rendered per request:** `cacheComponents` and `partialPrefetching` are off, since pages built ahead of time can't carry a per-request nonce. That costs some speed.
  - In `pnpm dev`, React logs that it can't use `eval()`, and skips some debugging extras. Pages still work, and production builds never use it.
- **Security:** the security standard's other headers on every response: `Strict-Transport-Security`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `X-Frame-Options`, and the parts of the policy that need no nonce. Before, other sites could frame the app's pages (clickjacking). Copy the new `src/lib/security-headers.ts` and `next.config.ts`.
- **Security:** the safe `next` check no longer lets through paths that resolve to another site, such as `/.//evil.example`. The template checked `next` twice, so this wasn't reachable in it, but a project calling `safeNext` once before redirecting had an open redirect. Copy `src/lib/auth/safe-next.ts`.
- **Added:** the 2FA step sends the `__Host-device` cookie's device token and keeps the one that comes back, which records a code was entered in this browser. Someone else's wrong codes then can't pause 2FA for it. Copy `src/lib/auth/actions.ts` and `src/lib/api/schemas.ts`.
- **Added:** a notice for `409 oauth_link_required`, when a provider's email is an existing account's but the provider doesn't run that address: log in, then link the provider from settings. Copy `src/app/oauth/callback/route.ts` and `src/lib/auth/notices.ts`.

## 0.4.0

Works with the auth module's `v1.0.0` and later. Every copied file's header comment now says 0.4.0, but files not named here are otherwise unchanged.

- **Added:** `MOBILE_OAUTH_REQUIRE_HTTPS=true` refuses a `MOBILE_OAUTH_REDIRECT_URL` that isn't https, so the server won't start with a custom-scheme deep link that another app could register. Off by default. See "Mobile deep links" in the README. Copy `src/lib/env.ts`.

## 0.3.0

Works with the auth module's `v1.0.0` and later; the device token needs `v1.2.0`. Every copied file's header comment now says 0.3.0, but files not named here are otherwise unchanged.

- **Security:** keeps the `device_token` from a login with the password in a `__Host-device` cookie for a year, and sends it with the next login, so other people's wrong passwords for the same email can't make the browser wait. Copy `src/lib/auth/actions.ts`, `src/lib/auth/cookies.ts`, and `src/lib/api/schemas.ts`.

## 0.2.0

Works with the auth module's `v1.0.0` and later. Copy again the files named below. Every copied file's header comment now says 0.2.0, but files not named here are otherwise unchanged.

- **Fixed:** `next build` no longer needs the runtime settings. `/oauth/callback/mobile` was prerendered at build time and read `API_URL` there, so a Docker build without it failed. It now waits for a request (`connection()`). Copy `src/app/oauth/callback/mobile/route.ts`.
- **Fixed:** the unit tests' `server-only` alias works when the project's path has spaces or is on Windows (`fileURLToPath` instead of `URL.pathname`). Copy `vitest.config.mts`.
- **Fixed:** `engines.node` now matches what the test tools need: `^22.22.2 || ^24.15.0 || >=26.0.0`, as jsdom requires. On older Node 22 releases jsdom's test workers crashed. Copy the `engines` field of `package.json`.
- **Added:** `CLIENT_IP_HEADER=none` forwards no client IP, but still the user agent. Use it when nothing in front of the web app overwrites the IP header, so browsers can't choose their own IP for the rate limits and the security event log. See the README. Copy `src/lib/env.ts` and `src/lib/api/client.ts`.
- **Added:** a notice for `sign_up_not_allowed`, the error the module's upcoming `ErrSignUpNotAllowed` gives a refused sign-up with a provider. It used to show "Signing in didn't work". Copy `src/lib/auth/notices.ts` and `src/app/oauth/callback/route.ts`.
- **Docs:** why the template has no Content Security Policy yet (nonces don't work with Cache Components and partial prerendering), and how to add one. See the README.
- Tests: `src/test/` fakes `connection()` from `next/server`.

## 0.1.0

The first version, for the auth module's `v1.0.0`:

- The `__Host-session` cookie, lasting until the session's absolute expiry.
- `proxy.ts`, `getSession`, and `requireSession`.
- The Go API client, forwarding the browser's IP and user agent.
- Log in, 2FA at login, sign up, and log out.
- `/account`: change password and email, see sessions and log any of them out, or log out everywhere. `/account/two-factor`: turn 2FA on (with a QR code) or off, and get new recovery codes. Users who must have 2FA are sent there until they set it up.
- Sign in with Google and GitHub: the buttons, `/oauth/callback`, `/oauth/callback/mobile`, and linking and unlinking providers on `/account`.
- The pages email links open: verify email, reset password, confirm an email change, and accept an invitation. Plus forgot password and "send a new verification link".
