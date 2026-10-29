// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { NextResponse, type NextRequest } from "next/server";

import { SESSION_COOKIE } from "@/lib/auth/cookies";
import { loginPath } from "@/lib/auth/safe-next";

// proxy sends logged-out visitors to the login page before a protected page
// starts rendering, so they never see it flash up. It only checks that the
// cookie is there: it's a fast first filter, not the security check. Every
// protected page and server action still calls requireSession, which checks
// the session with the Go API.
export function proxy(request: NextRequest) {
  if (request.cookies.has(SESSION_COOKIE)) {
    return NextResponse.next();
  }
  const { pathname, search } = request.nextUrl;
  return NextResponse.redirect(
    new URL(loginPath(pathname + search), request.url),
  );
}

export const config = {
  // Every protected area. Add your own.
  matcher: ["/dashboard/:path*", "/account/:path*"],
};
