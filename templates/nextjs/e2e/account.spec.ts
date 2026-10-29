import { expect, test, type Page } from "@playwright/test";

import { API_URL } from "../playwright.config";
import {
  PASSWORD,
  base32Decode,
  newEmail,
  newIP,
  totp,
  verifiedUser,
  field,
} from "./helpers";

test.use({ extraHTTPHeaders: { "x-real-ip": newIP() } });

async function logIn(page: Page, email: string) {
  await page.goto("/login");
  await field(page, "Email").fill(email);
  await field(page, "Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Log in" }).click();
  await expect(page).not.toHaveURL(/\/login$/);
}

test("turn on 2FA from the account page, then log in with it", async ({
  page,
  request,
}) => {
  const email = newEmail();
  await verifiedUser(request, email);
  await logIn(page, email);
  await page.getByRole("link", { name: "Account settings" }).click();
  await page.getByRole("link", { name: "Manage" }).click();
  await expect(page).toHaveURL("/account/two-factor");

  await field(page, "Current password").fill(PASSWORD);
  await page
    .getByRole("button", { name: "Turn on two-factor authentication" })
    .click();
  await expect(
    page.getByRole("img", { name: "QR code for your authenticator app" }),
  ).toBeVisible();
  const key = (await page.getByText(/^Key: /).textContent())!.slice(5);
  const secret = base32Decode(key);

  await field(page, "Code from your authenticator app").fill(totp(secret));
  await page.getByRole("button", { name: "Confirm" }).click();
  await expect(
    page.getByText("Two-factor authentication is on."),
  ).toBeVisible();
  await expect(page.getByRole("listitem")).toHaveCount(10);

  await page.getByRole("link", { name: "Done" }).click();
  await expect(page.getByText(/^On\./)).toBeVisible();
  await page.goto("/dashboard");
  await page.getByRole("button", { name: "Log out" }).click();

  await logIn(page, email);
  await expect(page).toHaveURL(/\/login\/two-factor/);
  await field(page, /code/i).fill(totp(secret, 1));
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page).toHaveURL("/dashboard");
});

test("see where you're logged in, and log out another device", async ({
  page,
  request,
}) => {
  const email = newEmail();
  const other = await verifiedUser(request, email);
  await logIn(page, email);
  await page.goto("/account");

  const rows = page.getByRole("listitem");
  await expect(rows).toHaveCount(2);
  await expect(rows.filter({ hasText: "This device" })).toHaveCount(1);
  await rows
    .filter({ hasNotText: "This device" })
    .getByRole("button", { name: "Log out" })
    .click();
  await expect(rows).toHaveCount(1);

  const me = await request.get(`${API_URL}/v1/users/me`, {
    headers: { Authorization: `Bearer ${other}` },
  });
  expect(me.status()).toBe(401);
});

test("change the password from the account page", async ({ page, request }) => {
  const email = newEmail();
  const other = await verifiedUser(request, email);
  await logIn(page, email);
  await page.goto("/account");

  const passwordForm = page.locator("form", {
    has: page.getByRole("button", { name: "Change password" }),
  });
  await field(passwordForm, "Current password").fill(PASSWORD);
  await field(passwordForm, "New password").fill("another fake passphrase");
  await passwordForm.getByRole("button", { name: "Change password" }).click();
  await expect(page.getByRole("status")).toContainText("Password changed");

  // This session stays; the other one is logged out.
  await page.reload();
  await expect(page.getByRole("heading", { name: "Account" })).toBeVisible();
  const me = await request.get(`${API_URL}/v1/users/me`, {
    headers: { Authorization: `Bearer ${other}` },
  });
  expect(me.status()).toBe(401);
});
