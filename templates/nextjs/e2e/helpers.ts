import { createHmac, randomInt, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";

import {
  expect,
  type APIRequestContext,
  type Locator,
  type Page,
} from "@playwright/test";

import { API_URL, MAIL_FILE } from "../playwright.config";

export const PASSWORD = "a fake test passphrase";

// newEmail returns an address no other test uses.
export function newEmail(): string {
  return `user-${randomUUID()}@example.com`;
}

// newIP returns a test address (TEST-NET-3) for the browser to come from,
// so tests don't share the Go API's per-IP rate limits. The template
// forwards it, since CLIENT_IP_HEADER defaults to x-real-ip.
export function newIP(): string {
  return `203.0.113.${randomInt(1, 255)}`;
}

// linkTo waits for an email to addr with a link to page, and returns its
// token.
export async function linkTo(addr: string, page: string): Promise<string> {
  const pattern = new RegExp(`/${page}#token=([A-Za-z0-9_-]+)`);
  let token = "";
  await expect(async () => {
    const mail = await readFile(MAIL_FILE, "utf8").catch(() => "");
    const emails = mail
      .split(/^To: /m)
      .filter((m) => m.startsWith(`${addr}\n`));
    const match = emails.at(-1)?.match(pattern);
    expect(match, `an email to ${addr} linking to /${page}`).toBeTruthy();
    token = match![1];
  }).toPass({ timeout: 10_000 });
  return token;
}

// verifiedUser signs up and verifies a user through the Go API, and returns
// a session token for them.
export async function verifiedUser(
  request: APIRequestContext,
  email: string,
): Promise<string> {
  const ip = { "X-Forwarded-For": newIP() };
  const signUp = await request.post(`${API_URL}/v1/users`, {
    data: { email, password: PASSWORD, client: "web" },
    headers: ip,
  });
  expect(signUp.status()).toBe(202);
  const token = await linkTo(email, "verify-email");
  const confirm = await request.post(
    `${API_URL}/v1/email-verifications/confirm`,
    {
      data: { token, password: PASSWORD, client: "web" },
      headers: ip,
    },
  );
  expect(confirm.status()).toBe(201);
  return (await confirm.json()).token;
}

// enableTwoFactor turns on 2FA through the Go API and returns the secret.
export async function enableTwoFactor(
  request: APIRequestContext,
  token: string,
): Promise<Buffer> {
  const auth = { Authorization: `Bearer ${token}` };
  const setup = await request.post(`${API_URL}/v1/users/me/two-factor`, {
    data: { current_password: PASSWORD },
    headers: auth,
  });
  expect(setup.status()).toBe(201);
  const secret = base32Decode((await setup.json()).secret);
  const confirm = await request.post(
    `${API_URL}/v1/users/me/two-factor/confirm`,
    {
      data: { code: totp(secret) },
      headers: auth,
    },
  );
  expect(confirm.status()).toBe(200);
  return secret;
}

// totp returns the RFC 6238 code for secret, steps periods of 30 seconds
// from now. The Go API accepts one step either side, so a code for the next
// step works without waiting, even right after another code was used.
export function totp(secret: Buffer, steps = 0): string {
  const counter = Math.floor(Date.now() / 30_000) + steps;
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac("sha1", secret).update(msg).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const n = (mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return n.toString().padStart(6, "0");
}

export function base32Decode(s: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of s.replace(/=+$/, "")) {
    bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

// field finds a visible form field by its label. Next.js keeps the page
// you came from in the DOM, hidden, so its fields would match too.
export function field(page: Page | Locator, label: string | RegExp): Locator {
  return page.getByLabel(label).filter({ visible: true });
}
