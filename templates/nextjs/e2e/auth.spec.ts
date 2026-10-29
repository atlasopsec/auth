import { expect, test } from "@playwright/test";

import {
  PASSWORD,
  enableTwoFactor,
  linkTo,
  newEmail,
  newIP,
  totp,
  verifiedUser,
  field,
} from "./helpers";
import { API_URL } from "../playwright.config";

test.use({ extraHTTPHeaders: { "x-real-ip": newIP() } });

async function logIn(page: import("@playwright/test").Page, email: string) {
  await field(page, "Email").fill(email);
  await field(page, "Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Log in" }).click();
}

test("logged-out visitors are sent to log in, and never see protected pages", async ({
  page,
  context,
  request,
}) => {
  await page.goto("/dashboard");
  await expect(page).toHaveURL("/login?next=%2Fdashboard");
  await expect(page.getByRole("heading", { name: "Log in" })).toBeVisible();

  // A made-up cookie gets past proxy.ts, but not requireSession.
  await context.addCookies([
    {
      name: "__Host-session",
      value: "made-up",
      domain: "localhost",
      path: "/",
      httpOnly: true,
      secure: true,
      sameSite: "Lax",
    },
  ]);
  await page.goto("/dashboard");
  await expect(page).toHaveURL("/login?next=%2Fdashboard");

  // Nothing from the page itself is sent before the redirect.
  const html = await request.get("/dashboard", {
    headers: { cookie: "__Host-session=made-up" },
    maxRedirects: 0,
  });
  expect(await html.text()).not.toContain("Logged in as");
});

test("sign up, verify the email, and log in", async ({ page }) => {
  const email = newEmail();
  await page.goto("/sign-up");
  await field(page, "Email").fill(email);
  await field(page, "Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign up" }).click();
  await expect(
    page.getByRole("heading", { name: "Check your email" }),
  ).toBeVisible();

  const token = await linkTo(email, "verify-email");
  await page.goto(`/verify-email#token=${token}`);
  await expect(page).toHaveURL("/verify-email");
  await field(page, "Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Confirm and log in" }).click();
  await expect(page).toHaveURL("/dashboard");
  await expect(page.getByText(`Logged in as ${email}.`)).toBeVisible();

  const cookie = (await page.context().cookies()).find(
    (c) => c.name === "__Host-session",
  );
  expect(cookie).toMatchObject({
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: "/",
  });
  // Until the session's latest expiry: 90 days.
  const days = (cookie!.expires * 1000 - Date.now()) / 86_400_000;
  expect(days).toBeGreaterThan(89);
  expect(days).toBeLessThanOrEqual(90);
});

test("wrong passwords are refused", async ({ page, request }) => {
  const email = newEmail();
  await verifiedUser(request, email);
  await page.goto("/login");
  await field(page, "Email").fill(email);
  await field(page, "Password").fill("not the password");
  await page.getByRole("button", { name: "Log in" }).click();
  await expect(page.getByRole("main").getByRole("alert")).toHaveText(
    "The email or password is incorrect.",
  );
  await expect(field(page, "Email")).toHaveValue(email);
});

test("log in with 2FA", async ({ page, request }) => {
  const email = newEmail();
  const secret = await enableTwoFactor(
    request,
    await verifiedUser(request, email),
  );

  await page.goto("/login?next=%2Fdashboard");
  await logIn(page, email);
  await expect(page).toHaveURL("/login/two-factor?next=%2Fdashboard");
  expect(page.url()).not.toContain("token");

  await field(page, /code/i).fill("000000");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(
    page.getByText("That code isn't right.", { exact: false }),
  ).toBeVisible();

  await field(page, /code/i).fill(totp(secret, 1));
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page).toHaveURL("/dashboard");
  await expect(page.getByText(`Logged in as ${email}.`)).toBeVisible();
  const names = (await page.context().cookies()).map((c) => c.name);
  expect(names).not.toContain("__Host-two-factor");
});

test("log out ends the session, so the old cookie stops working", async ({
  page,
  request,
  context,
}) => {
  const email = newEmail();
  await verifiedUser(request, email);
  await page.goto("/login");
  await logIn(page, email);
  await expect(page).toHaveURL("/dashboard");
  const cookie = (await context.cookies()).find(
    (c) => c.name === "__Host-session",
  )!;

  await page.getByRole("button", { name: "Log out" }).click();
  await expect(page).toHaveURL("/login");
  expect((await context.cookies()).map((c) => c.name)).not.toContain(
    "__Host-session",
  );

  // Even someone who copied the cookie can't use it now.
  const me = await request.get(`${API_URL}/v1/users/me`, {
    headers: { Authorization: `Bearer ${cookie.value}` },
  });
  expect(me.status()).toBe(401);
  await context.addCookies([cookie]);
  await page.goto("/dashboard");
  await expect(page).toHaveURL("/login?next=%2Fdashboard");
});

test("reset a forgotten password from the emailed link", async ({
  page,
  request,
}) => {
  const email = newEmail();
  await verifiedUser(request, email);

  await page.goto("/login");
  await page.getByRole("link", { name: "Forgot your password?" }).click();
  await field(page, "Email").fill(email);
  await page.getByRole("button", { name: "Send reset link" }).click();
  await expect(page.getByRole("status")).toContainText("we've sent it a link");

  const token = await linkTo(email, "reset-password");
  await page.goto(`/reset-password#token=${token}`);
  await expect(page).toHaveURL("/reset-password");
  await field(page, "New password").fill("a brand new fake passphrase");
  await page.getByRole("button", { name: "Set new password" }).click();
  await expect(page).toHaveURL("/login?notice=password-reset");
  await expect(page.getByRole("status")).toContainText(
    "Log in with your new password",
  );

  await field(page, "Email").fill(email);
  await field(page, "Password").fill("a brand new fake passphrase");
  await page.getByRole("button", { name: "Log in" }).click();
  await expect(page).toHaveURL("/dashboard");
});

test("confirm an email change from the emailed link", async ({
  page,
  request,
}) => {
  const email = newEmail();
  const newAddress = newEmail();
  const token = await verifiedUser(request, email);
  const requested = await request.post(`${API_URL}/v1/email-changes`, {
    data: { email: newAddress, current_password: PASSWORD },
    headers: { Authorization: `Bearer ${token}`, "X-Forwarded-For": newIP() },
  });
  expect(requested.status()).toBe(202);

  const link = await linkTo(newAddress, "confirm-email-change");
  await page.goto(`/confirm-email-change#token=${link}`);
  await page.getByRole("button", { name: "Confirm new email" }).click();
  await expect(page).toHaveURL("/login?notice=email-changed");

  await logIn(page, newAddress);
  await expect(page.getByText(`Logged in as ${newAddress}.`)).toBeVisible();
});

test("accept an invitation while logged out", async ({ page, request }) => {
  const owner = await verifiedUser(request, newEmail());
  const invitee = newEmail();
  await verifiedUser(request, invitee);
  const auth = { Authorization: `Bearer ${owner}`, "X-Forwarded-For": newIP() };
  const org = await request.post(`${API_URL}/v1/organizations`, {
    data: { name: "Acme" },
    headers: auth,
  });
  expect(org.status()).toBe(201);
  const invited = await request.post(
    `${API_URL}/v1/organizations/${(await org.json()).id}/invitations`,
    { data: { email: invitee, role: "member" }, headers: auth },
  );
  expect(invited.status()).toBe(201);

  const token = await linkTo(invitee, "accept-invitation");
  await page.goto(`/accept-invitation#token=${token}`);
  await expect(page).toHaveURL("/accept-invitation");
  await page.getByRole("link", { name: "Log in" }).first().click();
  await logIn(page, invitee);

  // Back to the invitation, which was kept in a cookie meanwhile.
  await expect(page).toHaveURL("/accept-invitation");
  await page.getByRole("button", { name: "Join the organization" }).click();
  await expect(page.getByRole("status")).toHaveText("You've joined Acme.");
  const names = (await page.context().cookies()).map((c) => c.name);
  expect(names).not.toContain("__Host-invitation");
});
