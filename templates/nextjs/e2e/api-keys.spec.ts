import { expect, test } from "@playwright/test";

import { PASSWORD, field, newEmail, newIP, verifiedUser } from "./helpers";

test.use({ extraHTTPHeaders: { "x-real-ip": newIP() } });

// The example API offers "reports:read" to keys, but a new user has no app
// role, so the Go API refuses the key: the page shows why, next to the
// permissions, and no key. A key being made is covered by the unit tests.
test("the API keys page lists keys and shows the Go API's refusal", async ({
  page,
  request,
}) => {
  const email = newEmail();
  await verifiedUser(request, email);
  await page.goto("/login");
  await field(page, "Email").fill(email);
  await field(page, "Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Log in" }).click();
  await expect(page).not.toHaveURL(/\/login$/);

  await page.goto("/account");
  await page.getByRole("link", { name: "API keys" }).click();
  await expect(page).toHaveURL("/account/api-keys");
  await expect(page.getByText("No keys yet.")).toBeVisible();

  await field(page, "Name").fill("Nightly sync");
  await page.getByRole("checkbox", { name: "Read reports" }).check();
  await page.getByLabel("Expires after").selectOption("30");
  await field(page, "Current password").fill(PASSWORD);
  await page.getByRole("button", { name: "Create key" }).click();

  await expect(page.getByText(/keys may carry/)).toBeVisible();
  await expect(page.getByText(/won't be shown again/)).toHaveCount(0);
  await expect(field(page, "Name")).toHaveValue("Nightly sync");
});

test("a logged-out visitor is sent to log in", async ({ page }) => {
  await page.goto("/account/api-keys");
  await expect(page).toHaveURL(/\/login\?next=%2Faccount%2Fapi-keys$/);
});
