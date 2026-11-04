# Next.js template for the auth module

The web half of [`github.com/atlasopsec/auth`](../../README.md): the session cookie, `proxy.ts`, a session helper, and the auth pages. It follows the [auth standard](https://github.com/jakefrenzel/engineering-standards/blob/main/standards/auth.md), and its design is in [docs/api.md §11](../../docs/api.md).

It's a complete Next.js app so it can be run and tested, but projects **copy parts of it** into their own app rather than starting from it.

**Template version 0.5.0**, for the auth module's `v1.5.0` and later. What changed between versions is in [CHANGELOG.md](CHANGELOG.md). Each copied file starts with a comment naming the version it came from.

## What to copy

| Path                                       | What it is                                                                                                                                                              |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/proxy.ts`, `src/lib/csp.ts`           | Sends logged-out visitors to `/login` before a protected page renders, and sets the Content Security Policy. Add your protected paths to its `PROTECTED` list           |
| `src/lib/env.ts`, `src/instrumentation.ts` | The settings below, checked when the server starts                                                                                                                      |
| `src/lib/security-headers.ts`              | The security headers from the standard, sent on every response by `headers()` in `next.config.ts`. Copy that too                                                        |
| `src/lib/api/`                             | The Go API client. It forwards the browser's IP and user agent, and checks responses with Zod                                                                           |
| `src/lib/auth/`                            | Cookies, `getSession` and `requireSession`, the server actions, and the safe `next` check                                                                               |
| `src/components/auth/`                     | The forms. Restyle them freely                                                                                                                                          |
| `src/app/(auth)/`                          | Log in, 2FA, sign up, forgot and reset password, verify email, confirm an email change, and accept an invitation. The module's emails link to these paths, so keep them |
| `src/app/account/`                         | The account settings: password, email, sessions, and 2FA                                                                                                                |
| `src/app/oauth/`                           | Where Google and GitHub send the browser back, for the web app and the mobile app. Register both URLs with each provider                                                |

The pages use three shadcn/ui-style components from `src/components/ui/` (`Button`, `Input`, `Label`). If your project already has shadcn/ui, use its own.

## Using it in a page

Every protected page and server action calls `requireSession`. `proxy.ts` only checks that the cookie is there; `requireSession` checks the session with the Go API.

```tsx
// src/app/invoices/page.tsx
import { requireSession } from "@/lib/auth/session";

export default async function InvoicesPage() {
  const session = await requireSession("/invoices");
  // ...
}
```

Cache Components are off, since the Content Security Policy needs every page rendered per request (see below). A `loading.tsx`, as `src/app/dashboard/` has, still shows something while the session is checked.

Calls to your own Go API endpoints pass the session token:

```ts
import { callApi } from "@/lib/api/client";
import { getSessionToken } from "@/lib/auth/session";

const invoices = await callApi("/v1/invoices", invoiceListSchema, {
  token: await getSessionToken(),
});
```

## Settings

| Variable                     | Example                            | Required         |
| ---------------------------- | ---------------------------------- | ---------------- |
| `API_URL`                    | `http://api.railway.internal:8080` | Yes              |
| `CLIENT_IP_HEADER`           | `x-real-ip`                        | No (`x-real-ip`) |
| `OAUTH_PROVIDERS`            | `google,github`                    | No (none)        |
| `MOBILE_OAUTH_REDIRECT_URL`  | `exampleapp://oauth`               | No               |
| `MOBILE_OAUTH_REQUIRE_HTTPS` | `true`                             | No (`false`)     |

None are secrets, and none may have the `NEXT_PUBLIC_` prefix. `OAUTH_PROVIDERS` lists the providers turned on in the Go API's `Config.OAuth`; their buttons appear on the login and account pages. `MOBILE_OAUTH_REDIRECT_URL` is the mobile app's deep link; without it, `/oauth/callback/mobile` answers `404`.

### Mobile deep links

Any app can register a custom scheme such as `exampleapp://`, so another app on the same device could catch the sign-in redirect. It can't finish the sign-in, because only the app that started it has the client verifier, but it does see the provider's code. An https link (an Android App Link or iOS Universal Link) is tied to your app through your domain, so no other app gets it. Use one for new apps, and set `MOBILE_OAUTH_REQUIRE_HTTPS=true` so the web app refuses to start with a custom scheme. It's off by default because existing apps use custom schemes; a future major version will turn it on.

The Go API must list Railway's private network in `Config.TrustedProxies`, so it believes the IP and user agent the web app forwards, and only from the web app.

### Check the client IP on a real deploy

`CLIENT_IP_HEADER` names the header the hosting edge puts the browser's IP in. Railway's staff say its edge sets `X-Real-IP` on every request, replacing any copy the browser sent, but Railway doesn't document this as a guarantee. Before relying on it, check on your deploy:

1. Log in from your own browser, then look at the session list (`GET /v1/sessions`): its `ip` should be your public IP.
2. Send a request with a made-up header, e.g. `curl -H "X-Real-IP: 198.51.100.1" https://your-app/login`, then check the Go API's logs or the latest `auth.auth_events` row: the IP must be yours, not `198.51.100.1`.

If the IP is wrong, the rate limits and the security event log are too. Change `CLIENT_IP_HEADER`, or ask Railway.

### No edge that sets the header

Without an edge that overwrites the header on every request, such as behind a plain reverse proxy or through `kubectl port-forward`, its value is whatever the browser sent, so anyone could pick their own IP for the rate limits and the security event log. Set `CLIENT_IP_HEADER=none` there. The web app then forwards no IP (it still forwards the user agent), and the Go API sees every request as coming from the web app. The per-IP rate limits then count all users together, so they're reached sooner; the per-address limits are unaffected.

## Content Security Policy

`src/proxy.ts` sets the [security standard](https://github.com/jakefrenzel/engineering-standards/blob/main/standards/security.md#2-security-headers)'s nonce-based Content Security Policy on every page, built in `src/lib/csp.ts`. Each response gets a new nonce, and only scripts carrying it run, so a script someone manages to inject doesn't. The proxy also sets the policy on the request, which is how Next.js finds the nonce to put on its own scripts. `e2e/security.spec.ts` checks every script carries it and nothing is blocked.

What that takes, if you copy it into an existing app:

- **Every page is rendered per request** (`export const dynamic = "force-dynamic"` in the root layout), and `next.config.ts` doesn't turn on `cacheComponents` or `partialPrefetching`. Those serve pages built ahead of time, and a script built ahead of time can't carry a nonce made per request, so the browser would refuse to run it. The [Next.js CSP guide](https://nextjs.org/docs/app/guides/content-security-policy#static-vs-dynamic-rendering-with-csp) says the same. It costs some speed.
- **The proxy runs on every page,** except Next.js's own files under `/_next/` and prefetches. The logged-out redirect still applies only to the paths in its `PROTECTED` list.
- **`form-action` allows the sign-in providers** in `OAUTH_PROVIDERS` (`https://accounts.google.com`, `https://github.com`): the sign-in button's form ends in a redirect there, and `form-action` covers that redirect too.
- **Loosen the policy only for a specific need, with a comment saying why,** as the standard says: for example, add your file storage's host to `img-src`. Never add `'unsafe-eval'` or `'unsafe-inline'` to `script-src`.
- **In `pnpm dev`, React logs that it can't use `eval()`.** React's development build uses it for debugging extras, such as call stacks from the server; the pages still work. Production builds never use it. The policy doesn't allow it in development either, since the standard forbids `'unsafe-eval'`.

`src/lib/security-headers.ts` still sends the parts of the policy that need no nonce (`frame-ancestors 'none'; object-src 'none'; base-uri 'self'`) from `next.config.ts`, for responses the proxy doesn't run on. A browser applies both policies, so they don't conflict.

## Running it

```bash
pnpm install
cp .env.example .env.local   # point API_URL at a Go API, e.g. examples/api
pnpm dev
```

[`examples/api`](../../examples/api/main.go) is a Go API to run it against. It prints emails to its output instead of sending them.

## Tests

```bash
pnpm lint && pnpm typecheck && pnpm format:check
pnpm test                    # Vitest, with MSW faking the Go API
E2E_DATABASE_URL=postgres://... pnpm test:e2e   # Playwright
```

The end-to-end tests start `examples/api` and the built app themselves. `E2E_DATABASE_URL` must point at an empty Postgres database. To use an already-installed Chromium, set `PLAYWRIGHT_CHROMIUM_PATH`.
