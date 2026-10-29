import { describe, expect, it } from "vitest";

import { noticeText } from "@/lib/auth/notices";

describe("noticeText", () => {
  it("shows a known notice", () => {
    expect(noticeText("password-reset")).toMatch(/password was changed/);
  });

  it.each([
    ["anything else"],
    ["toString"],
    ["__proto__"],
    [undefined],
    [["password-reset"]],
  ])("shows nothing for %j, never text from the URL", (notice) => {
    expect(noticeText(notice)).toBeNull();
  });
});
