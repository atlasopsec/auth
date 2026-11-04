import { expect, test } from "@playwright/test";

import { PASSWORD, field, newEmail } from "./helpers";

// The pages run under the security standard's nonce-based Content Security
// Policy: Next.js's own scripts carry each response's nonce, and nothing
// the page needs is blocked.
test("pages run under the nonce-based Content Security Policy", async ({
  page,
}) => {
  const violations: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error" && /Content Security Policy/i.test(m.text())) {
      violations.push(m.text());
    }
  });

  const res = await page.goto("/sign-up");
  const policy = res?.headers()["content-security-policy"] ?? "";
  const nonce = policy.match(/'nonce-([^']+)'/)?.[1];
  expect(nonce, `a nonce in ${policy}`).toBeTruthy();
  expect(policy).not.toContain("unsafe-eval");
  expect(policy).toMatch(/script-src [^;]*'strict-dynamic'/);
  expect(policy).not.toMatch(/script-src [^;]*'unsafe-inline'/);

  // Every script from the server carries this response's nonce.
  const nonces = await page
    .locator("script")
    .evaluateAll((scripts) =>
      scripts.map((s) => (s as HTMLScriptElement).nonce),
    );
  expect(nonces.length).toBeGreaterThan(0);
  expect(new Set(nonces)).toEqual(new Set([nonce]));

  // The scripts ran: the form submits through its server action.
  await field(page, "Email").fill(newEmail());
  await field(page, "Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign up" }).click();
  await expect(
    page.getByRole("heading", { name: "Check your email" }),
  ).toBeVisible();

  // A new page gets a new nonce.
  const again = await page.goto("/login");
  expect(again?.headers()["content-security-policy"]).not.toContain(
    `'nonce-${nonce}'`,
  );
  expect(violations).toEqual([]);
});
