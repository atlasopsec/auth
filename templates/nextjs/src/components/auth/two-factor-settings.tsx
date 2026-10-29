"use client";

// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { useActionState } from "react";

import { Field, FormMessage } from "@/components/auth/field";
import { Button } from "@/components/ui/button";
import {
  confirmTwoFactorSetup,
  regenerateRecoveryCodes,
  startTwoFactorSetup,
  turnOffTwoFactor,
} from "@/lib/auth/account-actions";
import type { FormState } from "@/lib/auth/form-state";

function PasswordField({ error }: { error?: string }) {
  return (
    <Field
      name="current_password"
      label="Current password"
      type="password"
      autoComplete="current-password"
      required
      error={error}
    />
  );
}

function CodeField({ error }: { error?: string }) {
  return (
    <Field
      name="code"
      label="Code from your authenticator app"
      autoComplete="one-time-code"
      inputMode="numeric"
      required
      error={error}
    />
  );
}

// RecoveryCodes shows new recovery codes. They're shown only once.
export function RecoveryCodes({ codes }: { codes: string[] }) {
  return (
    <div className="grid gap-2">
      <p role="status">
        Save these recovery codes somewhere safe. Each one logs you in once if
        you lose your authenticator. They won&apos;t be shown again.
      </p>
      <ul className="grid grid-cols-2 gap-1 font-mono text-sm">
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ul>
    </div>
  );
}

// TurnOnTwoFactor sets up 2FA: the password, then the QR code and a code
// from the app, then the recovery codes.
export function TurnOnTwoFactor() {
  const [state, action, pending] = useActionState<FormState, FormData>(
    startTwoFactorSetup,
    {},
  );
  if (state.setup) {
    return <ConfirmTwoFactor setup={state.setup} />;
  }
  return (
    <form action={action} className="grid gap-4">
      <PasswordField error={state.fieldErrors?.current_password} />
      <FormMessage message={state.message} />
      <Button type="submit" disabled={pending}>
        Turn on two-factor authentication
      </Button>
    </form>
  );
}

function ConfirmTwoFactor({
  setup,
}: {
  setup: NonNullable<FormState["setup"]>;
}) {
  const [state, action, pending] = useActionState<FormState, FormData>(
    confirmTwoFactorSetup,
    {},
  );
  if (state.recoveryCodes) {
    return (
      <div className="grid gap-4">
        <p>Two-factor authentication is on.</p>
        <RecoveryCodes codes={state.recoveryCodes} />
        {/* A full page load, so every page sees 2FA is now on. */}
        <a href="/account" className="underline">
          Done
        </a>
      </div>
    );
  }
  return (
    <form action={action} className="grid gap-4">
      <p>
        Scan this with your authenticator app, or enter the key by hand, then
        enter the code it shows.
      </p>
      {/* eslint-disable-next-line @next/next/no-img-element -- a generated data: URL, which next/image doesn't optimize */}
      <img
        src={setup.qrCode}
        alt="QR code for your authenticator app"
        width={200}
        height={200}
      />
      <p className="font-mono text-sm break-all">Key: {setup.secret}</p>
      <CodeField error={state.fieldErrors?.code} />
      <FormMessage message={state.message} />
      <Button type="submit" disabled={pending}>
        Confirm
      </Button>
    </form>
  );
}

export function TurnOffTwoFactor() {
  const [state, action, pending] = useActionState<FormState, FormData>(
    turnOffTwoFactor,
    {},
  );
  if (state.done) {
    return <p role="status">{state.message}</p>;
  }
  return (
    <form action={action} className="grid gap-4">
      <PasswordField error={state.fieldErrors?.current_password} />
      <CodeField error={state.fieldErrors?.code} />
      <FormMessage message={state.message} />
      <Button type="submit" variant="outline" disabled={pending}>
        Turn off two-factor authentication
      </Button>
    </form>
  );
}

export function RegenerateRecoveryCodes() {
  const [state, action, pending] = useActionState<FormState, FormData>(
    regenerateRecoveryCodes,
    {},
  );
  if (state.recoveryCodes) {
    return <RecoveryCodes codes={state.recoveryCodes} />;
  }
  return (
    <form action={action} className="grid gap-4">
      <PasswordField error={state.fieldErrors?.current_password} />
      <CodeField error={state.fieldErrors?.code} />
      <FormMessage message={state.message} />
      <Button type="submit" variant="outline" disabled={pending}>
        Get new recovery codes
      </Button>
    </form>
  );
}
