import { describe, expect, it } from "vitest";

import nextConfig from "../../next.config";

describe("security headers", () => {
  it("are sent on every page", async () => {
    const rules = (await nextConfig.headers?.()) ?? [];
    const everyPage = rules.find((rule) => rule.source === "/:path*");
    expect(everyPage).toBeDefined();
    const headers = Object.fromEntries(
      (everyPage?.headers ?? []).map((h) => [h.key, h.value]),
    );
    expect(headers).toEqual({
      "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
      "Content-Security-Policy":
        "frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
      "X-Frame-Options": "DENY",
    });
  });
});
