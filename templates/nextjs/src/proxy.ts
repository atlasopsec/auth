// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.5.0.
import { NextResponse, type NextRequest } from "next/server";

import { SESSION_COOKIE } from "@/lib/auth/cookies";
import { loginPath } from "@/lib/auth/safe-next";
import { contentSecurityPolicy, newNonce } from "@/lib/csp";

// Every protected area. Add your own.
const PROTECTED = ["/dashboard", "/account"];

function isProtected(pathname: string): boolean {
  return PROTECTED.some((p) => pathname === p || pathname.startsWith(p + "/"));
}

// proxy runs on every page. It does two things:
//
// - It sends logged-out visitors to the login page before a protected page
//   starts rendering, so they never see it flash up. It only checks that
//   the cookie is there: it's a fast first filter, not the security check.
//   Every protected page and server action still calls requireSession,
//   which checks the session with the Go API.
// - It sets the Content Security Policy, with a new nonce for each
//   response. It's set on the request too, which is how Next.js finds the
//   nonce to put on its own scripts.
export function proxy(request: NextRequest) {
  const { pathname, search } = request.nextUrl;
  if (isProtected(pathname) && !request.cookies.has(SESSION_COOKIE)) {
    return NextResponse.redirect(
      new URL(loginPath(pathname + search), request.url),
    );
  }

  const policy = contentSecurityPolicy(
    newNonce(),
    process.env.OAUTH_PROVIDERS ?? "",
  );
  const headers = new Headers(request.headers);
  headers.set("Content-Security-Policy", policy);
  const response = NextResponse.next({ request: { headers } });
  response.headers.set("Content-Security-Policy", policy);
  return response;
}

export const config = {
  matcher: [
    {
      // Every page, but not Next.js's own files (static files, images,
      // and the dev server's hot reload), or prefetches, whose responses
      // aren't pages.
      source: "/((?!_next/|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
