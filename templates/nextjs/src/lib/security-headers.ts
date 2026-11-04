// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.4.0.

// securityHeaders are sent on every response, from next.config.ts, as the
// security standard asks (standards/security.md §2).
//
// The Content Security Policy here is only the part that needs no nonce:
// no framing by other sites, no plugins, and no <base> pointing elsewhere.
// The nonce-based script-src the standard asks for doesn't work with
// cacheComponents (see "Content Security Policy" in the README). A project
// that adds the full policy in proxy.ts should remove this one, since the
// full policy includes these directives.
export const securityHeaders = [
  {
    key: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains",
  },
  {
    key: "Content-Security-Policy",
    value: "frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
  },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=()",
  },
  { key: "X-Frame-Options", value: "DENY" },
];
