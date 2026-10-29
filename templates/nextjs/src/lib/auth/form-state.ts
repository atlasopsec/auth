// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { ApiError } from "@/lib/api/client";

// FormState is what a server action tells its form: a message for the whole
// form, and errors for single fields.
export type FormState = {
  message?: string;
  fieldErrors?: Record<string, string>;
  // What was typed, so a failed submit doesn't clear it. Never passwords.
  values?: Record<string, string>;
  // The action succeeded, for forms that stay on the page.
  done?: boolean;
  // A 2FA setup in progress: the secret, and its QR code as an image URL.
  setup?: { secret: string; qrCode: string };
  // New recovery codes, shown once.
  recoveryCodes?: string[];
};

export const SOMETHING_WENT_WRONG = "Something went wrong. Please try again.";

// stateFromError turns an error into what the form shows. The Go API's
// messages are written for users; anything else gets a generic message.
export function stateFromError(
  e: unknown,
  values?: Record<string, string>,
): FormState {
  if (!(e instanceof ApiError)) {
    console.error(e);
    return { message: SOMETHING_WENT_WRONG, values };
  }
  const fieldErrors: Record<string, string> = {};
  for (const d of e.details) {
    fieldErrors[d.field] ??= d.message;
  }
  if (Object.keys(fieldErrors).length > 0) {
    return { fieldErrors, values };
  }
  return { message: e.message, values };
}
