// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
// Messages the login page shows after another page sends the user there.
// Only these fixed texts are shown, never text from the URL.
export const NOTICES = {
  "password-reset": "Your password was changed. Log in with your new password.",
  "email-changed": "Your email address was changed. Log in with the new one.",
  "oauth-failed": "Signing in didn't work. Try again.",
  "oauth-expired": "Signing in took too long. Try again.",
  "oauth-email-not-verified":
    "Your email address isn't verified with that provider. Verify it there, then try again.",
  "oauth-linked": "The account was linked. You can now log in with it.",
  "oauth-account-in-use":
    "That account is already linked to another account here.",
  "oauth-already-linked":
    "An account with that provider is already linked. Unlink it first.",
} as const;

export type Notice = keyof typeof NOTICES;

export function noticeText(notice: unknown): string | null {
  return typeof notice === "string" && Object.hasOwn(NOTICES, notice)
    ? NOTICES[notice as Notice]
    : null;
}
