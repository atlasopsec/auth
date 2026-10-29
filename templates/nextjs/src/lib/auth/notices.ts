// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
// Messages the login page shows after another page sends the user there.
// Only these fixed texts are shown, never text from the URL.
export const NOTICES = {
  "password-reset": "Your password was changed. Log in with your new password.",
  "email-changed": "Your email address was changed. Log in with the new one.",
} as const;

export type Notice = keyof typeof NOTICES;

export function noticeText(notice: unknown): string | null {
  return typeof notice === "string" && Object.hasOwn(NOTICES, notice)
    ? NOTICES[notice as Notice]
    : null;
}
