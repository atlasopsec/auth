# Next.js template for the auth module

The web half of [`github.com/atlasopsec/auth`](../../README.md): the session cookie, `proxy.ts`, a session helper, and the auth pages. It follows the [auth standard](https://github.com/jakefrenzel/engineering-standards/blob/main/standards/auth.md), and its design is in [docs/api.md §11](../../docs/api.md).

It's a complete Next.js app so it can be run and tested, but projects **copy parts of it** into their own app rather than starting from it.

**Template version 0.3.0**, for the auth module's `v1.0.0` and later. What changed between versions is in [CHANGELOG.md](CHANGELOG.md). Each copied file starts with a comment naming the version it came from.

## What to copy

| Path                                       | What it is                                                                                                                                                              |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/proxy.ts`                             | Sends logged-out visitors to `/login` before a protected page renders. Add your protected paths to its `matcher`                                                        |
| `src/lib/env.ts`, `src/instrumentation.ts` | The settings below, checked when the server starts                                                                                                                      |
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

With Cache Components on (the default for new Next.js apps), reading the session needs a `<Suspense>` boundary: give the route a `loading.tsx`, as `src/app/dashboard/` does.

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

The template doesn't set a Content Security Policy yet. The [security standard](https://github.com/jakefrenzel/engineering-standards/blob/main/standards/security.md#2-security-headers) asks for a nonce-based one, set in `proxy.ts` with a new nonce per request, and that doesn't work with the template's `cacheComponents` and `partialPrefetching` settings. Those serve a static shell built ahead of time, and a script built ahead of time can't carry a nonce made per request, so the browser refuses to run it. The [Next.js CSP guide](https://nextjs.org/docs/app/guides/content-security-policy#static-vs-dynamic-rendering-with-csp) says the same: nonces need every page rendered per request, and partial prerendering is incompatible with them.

To add the policy, as a project that uses this template has done:

1. In `next.config.ts`, remove `cacheComponents` and `partialPrefetching`.
2. In the root layout, add `export const dynamic = "force-dynamic";`, so every page is rendered per request.
3. Make `proxy.ts` run on every page, except `_next/static`, `_next/image`, and prefetches, as in the Next.js guide. Keep the logged-out redirect for the protected paths only. On each request, make a nonce from `crypto.randomUUID()`, build the policy from the standard's starting point, and set it on both the request (so Next.js puts the nonce on its scripts) and the response.
4. If the sign-in buttons are on, add the providers' sign-in origins to `form-action` (`https://accounts.google.com`, `https://github.com`): the button's form ends in a redirect there, and `form-action` covers that redirect too.

Check it in a production build (`pnpm build && pnpm start`): every `<script>` tag on a page should carry the response's nonce. Pages are then rendered on every request, which costs some speed.

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
