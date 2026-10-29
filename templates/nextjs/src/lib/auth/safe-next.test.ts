import { describe, expect, it } from "vitest";

import { loginPath, safeNext } from "@/lib/auth/safe-next";

describe("safeNext", () => {
  it.each([
    ["/dashboard", "/dashboard"],
    ["/account?tab=security#2fa", "/account?tab=security#2fa"],
    ["/a/../b", "/b"],
  ])("keeps the path %s on this site", (input, want) => {
    expect(safeNext(input)).toBe(want);
  });

  it.each([
    ["another site", "https://evil.example/"],
    ["a protocol-relative URL", "//evil.example/"],
    ["a backslash URL", "/\\evil.example"],
    ["a tab-split URL", "/\t/evil.example"],
    ["a javascript: URL", "javascript:alert(1)"],
    ["a relative path", "dashboard"],
    ["nothing", null],
    ["a file from a form", new Blob()],
  ])("rejects %s", (_name, input) => {
    expect(safeNext(input)).toBeNull();
  });
});

describe("loginPath", () => {
  it("encodes the page to come back to", () => {
    expect(loginPath("/a?b=c&d")).toBe("/login?next=%2Fa%3Fb%3Dc%26d");
  });
});
