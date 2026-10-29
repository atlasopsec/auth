// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
// The session cookie. The __Host- prefix makes browsers require Secure,
// Path=/, and no Domain, so it only ever goes to this exact site.
export const SESSION_COOKIE = "__Host-session";

// Holds a 2FA challenge between the password and the code, so the token
// stays out of the address bar and the page.
export const TWO_FACTOR_COOKIE = "__Host-two-factor";

// Holds an invitation's token while the user logs in or signs up, so it
// survives the trip without going into a URL.
export const INVITATION_COOKIE = "__Host-invitation";

export type CookieOptions = {
  httpOnly: true;
  secure: true;
  sameSite: "lax";
  path: "/";
  maxAge: number;
};

// clearedCookie is the settings that delete a cookie. Browsers ignore a
// __Host- cookie, even one that deletes, unless it's Secure with Path=/.
export const clearedCookie: CookieOptions = {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  path: "/",
  maxAge: 0,
};

// cookieOptions are the settings for a cookie that lasts until expiresAt.
// Browsers treat localhost as secure, so Secure works in development too.
export function cookieOptions(
  expiresAt: string,
  now: Date = new Date(),
): CookieOptions {
  const seconds = Math.floor(
    (new Date(expiresAt).getTime() - now.getTime()) / 1000,
  );
  return {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: Math.max(seconds, 0),
  };
}
