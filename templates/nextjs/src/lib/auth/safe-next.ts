// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
// The page to go to after logging in when there's no "next".
export const DEFAULT_AFTER_LOGIN = "/dashboard";

const BASE = "http://localhost";

// safeNext returns next if it's a path on this site, so the login page
// can't be used to send people to another site. Anything else gives null.
export function safeNext(next: unknown): string | null {
  if (typeof next !== "string" || !next.startsWith("/")) {
    return null;
  }
  let url: URL;
  try {
    url = new URL(next, BASE);
  } catch {
    return null;
  }
  // Browsers read "//evil.example" and "/\evil.example" as other sites,
  // and so does URL.
  if (url.origin !== BASE) {
    return null;
  }
  return url.pathname + url.search + url.hash;
}

// loginPath is the login page, coming back to next afterwards.
export function loginPath(next: string): string {
  return `/login?next=${encodeURIComponent(next)}`;
}
