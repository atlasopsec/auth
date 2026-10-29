import { describe, expect, it, vi } from "vitest";

import { ApiError } from "@/lib/api/client";
import { stateFromError } from "@/lib/auth/form-state";

describe("stateFromError", () => {
  it("shows the first error for each field", () => {
    const e = new ApiError(
      422,
      "validation_failed",
      "Check the form.",
      [
        { field: "password", code: "too_short", message: "Too short." },
        { field: "password", code: "breached", message: "Found in a breach." },
      ],
      null,
    );
    expect(stateFromError(e, { email: "a@example.com" })).toEqual({
      fieldErrors: { password: "Too short." },
      values: { email: "a@example.com" },
    });
  });

  it("never shows other errors' messages", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect(stateFromError(new Error("connect ECONNREFUSED 10.0.0.1"))).toEqual({
      message: "Something went wrong. Please try again.",
    });
  });
});
