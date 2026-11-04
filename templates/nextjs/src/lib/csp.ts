// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.4.0.

// Where each provider's sign-in button sends the browser. The button is a
// form, and form-action covers the redirect a form submission ends in.
const PROVIDER_ORIGINS: Record<string, string> = {
  google: "https://accounts.google.com",
  github: "https://github.com",
};

// newNonce returns a new random nonce for one response's scripts.
export function newNonce(): string {
  return btoa(crypto.randomUUID());
}

// contentSecurityPolicy is the security standard's policy
// (standards/security.md §2): only scripts carrying this response's nonce
// run, and the scripts they load ('strict-dynamic'). providers is
// OAUTH_PROVIDERS, whose sign-in pages form-action must allow.
export function contentSecurityPolicy(
  nonce: string,
  providers: string,
): string {
  const formAction = providers
    .split(",")
    .map((p) => PROVIDER_ORIGINS[p.trim()])
    .filter(Boolean);
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    ["form-action 'self'", ...formAction].join(" "),
  ].join("; ");
}
