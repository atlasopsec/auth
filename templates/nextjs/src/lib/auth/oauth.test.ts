import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  challengeOf,
  decodeFlow,
  encodeFlow,
  newVerifier,
} from "@/lib/auth/oauth";

describe("newVerifier", () => {
  it("makes a fresh 32-byte verifier and its SHA-256 challenge", () => {
    const a = newVerifier();
    const b = newVerifier();
    expect(a.verifier).not.toBe(b.verifier);
    expect(Buffer.from(a.verifier, "base64url")).toHaveLength(32);
    expect(a.challenge).toBe(
      createHash("sha256").update(a.verifier).digest("base64url"),
    );
    expect(challengeOf(a.verifier)).toBe(a.challenge);
  });
});

describe("the flow cookie", () => {
  const flow = {
    verifier: "v".repeat(43),
    purpose: "login" as const,
    next: "/account",
  };

  it("round-trips", () => {
    expect(decodeFlow(encodeFlow(flow))).toEqual(flow);
  });

  it.each([
    ["nothing", undefined],
    ["garbage", "not base64 json"],
    ["a short verifier", encodeFlow({ ...flow, verifier: "short" })],
    [
      "an unknown purpose",
      Buffer.from(JSON.stringify({ ...flow, purpose: "admin" })).toString(
        "base64url",
      ),
    ],
  ])("rejects %s", (_name, value) => {
    expect(decodeFlow(value)).toBeNull();
  });
});
