import { describe, expect, it } from "vitest";

import { contentSecurityPolicy, newNonce } from "@/lib/csp";

describe("contentSecurityPolicy", () => {
  it("is the security standard's policy, with the nonce", () => {
    expect(contentSecurityPolicy("abc", "")).toBe(
      "default-src 'self'; script-src 'self' 'nonce-abc' 'strict-dynamic'; " +
        "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; " +
        "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; " +
        "object-src 'none'; base-uri 'self'; form-action 'self'",
    );
  });

  it("lets the sign-in buttons' forms go to their providers", () => {
    expect(contentSecurityPolicy("abc", "google, github")).toContain(
      "form-action 'self' https://accounts.google.com https://github.com",
    );
    expect(contentSecurityPolicy("abc", "github")).toMatch(
      /form-action 'self' https:\/\/github\.com$/,
    );
  });

  it("ignores providers it doesn't know", () => {
    expect(contentSecurityPolicy("abc", "evil.example")).toMatch(
      /form-action 'self'$/,
    );
  });
});

describe("newNonce", () => {
  it("is new every time", () => {
    expect(newNonce()).not.toBe(newNonce());
  });
});
