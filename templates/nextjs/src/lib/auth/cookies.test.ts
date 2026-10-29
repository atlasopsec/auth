import { describe, expect, it } from "vitest";

import { clearedCookie, cookieOptions } from "@/lib/auth/cookies";

describe("cookieOptions", () => {
  const now = new Date("2026-01-01T12:00:00Z");

  it("lasts until the given time, with the auth standard's settings", () => {
    expect(cookieOptions("2026-04-01T12:00:00Z", now)).toEqual({
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/",
      maxAge: 90 * 24 * 60 * 60,
    });
  });

  it("never has a negative age", () => {
    expect(cookieOptions("2025-12-31T12:00:00Z", now).maxAge).toBe(0);
  });
});

describe("clearedCookie", () => {
  it("is Secure with Path=/, so browsers accept it for __Host- cookies", () => {
    expect(clearedCookie).toMatchObject({ secure: true, path: "/", maxAge: 0 });
  });
});
