# Next.js template for the auth module

The web half of [`github.com/atlasopsec/auth`](../../README.md): the session cookie, `proxy.ts`, a session helper, and the auth pages. It follows the [auth standard](https://github.com/jakefrenzel/engineering-standards/blob/main/standards/auth.md), and its design is in [docs/api.md §11](../../docs/api.md).

It's a complete Next.js app so it can be run and tested, but projects **copy parts of it** into their own app rather than starting from it.

**Template version 0.1.0**, for the auth module's `v1.0.0`. What changed between versions is in [CHANGELOG.md](CHANGELOG.md). Each copied file starts with a comment naming the version it came from.

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

| Variable                    | Example                            | Required         |
| --------------------------- | ---------------------------------- | ---------------- |
| `API_URL`                   | `http://api.railway.internal:8080` | Yes              |
| `CLIENT_IP_HEADER`          | `x-real-ip`                        | No (`x-real-ip`) |
| `OAUTH_PROVIDERS`           | `google,github`                    | No (none)        |
| `MOBILE_OAUTH_REDIRECT_URL` | `exampleapp://oauth`               | No               |

None are secrets, and none may have the `NEXT_PUBLIC_` prefix. `OAUTH_PROVIDERS` lists the providers turned on in the Go API's `Config.OAuth`; their buttons appear on the login and account pages. `MOBILE_OAUTH_REDIRECT_URL` is the mobile app's deep link; without it, `/oauth/callback/mobile` answers `404`.

The Go API must list Railway's private network in `Config.TrustedProxies`, so it believes the IP and user agent the web app forwards, and only from the web app.

### Check the client IP on a real deploy

`CLIENT_IP_HEADER` names the header the hosting edge puts the browser's IP in. Railway's staff say its edge sets `X-Real-IP` on every request, replacing any copy the browser sent, but Railway doesn't document this as a guarantee. Before relying on it, check on your deploy:

1. Log in from your own browser, then look at the session list (`GET /v1/sessions`): its `ip` should be your public IP.
2. Send a request with a made-up header, e.g. `curl -H "X-Real-IP: 198.51.100.1" https://your-app/login`, then check the Go API's logs or the latest `auth.auth_events` row: the IP must be yours, not `198.51.100.1`.

If the IP is wrong, the rate limits and the security event log are too. Change `CLIENT_IP_HEADER`, or ask Railway.

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
