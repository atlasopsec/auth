import { expect, test } from "@playwright/test";

import {
  PASSWORD,
  enableTwoFactor,
  linkTo,
  newEmail,
  newIP,
  totp,
  verifiedUser,
} from "./helpers";
import { API_URL } from "../playwright.config";

test.use({ extraHTTPHeaders: { "x-real-ip": newIP() } });

async function logIn(page: import("@playwright/test").Page, email: string) {
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(PASSWORD);
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

test("sign up, verify the email, and log in", async ({ page, request }) => {
  const email = newEmail();
  await page.goto("/sign-up");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign up" }).click();
  await expect(
    page.getByRole("heading", { name: "Check your email" }),
  ).toBeVisible();

  // The verification page comes in the next PR; until then, verify through
  // the Go API.
  const token = await linkTo(email, "verify-email");
  const verified = await request.post(
    `${API_URL}/v1/email-verifications/confirm`,
    {
      data: { token, password: PASSWORD, client: "web" },
    },
  );
  expect(verified.status()).toBe(201);

  await page.goto("/dashboard");
  await logIn(page, email);
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
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill("not the password");
  await page.getByRole("button", { name: "Log in" }).click();
  await expect(page.getByRole("main").getByRole("alert")).toHaveText(
    "The email or password is incorrect.",
  );
  await expect(page.getByLabel("Email")).toHaveValue(email);
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

  await page.getByLabel(/code/i).fill("000000");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(
    page.getByText("That code isn't right.", { exact: false }),
  ).toBeVisible();

  await page.getByLabel(/code/i).fill(totp(secret, 1));
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
