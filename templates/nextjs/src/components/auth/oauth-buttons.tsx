"use client";

// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { useActionState } from "react";

import { Field, FormMessage } from "@/components/auth/field";
import { Button } from "@/components/ui/button";
import type { FormState } from "@/lib/auth/form-state";
import {
  startOAuthLink,
  startOAuthLogin,
  unlinkOAuth,
} from "@/lib/auth/oauth-actions";

export type ProviderOption = { id: string; name: string };

// OAuthButtons are the "Continue with Google" buttons on the login page.
export function OAuthButtons({
  providers,
  next,
}: {
  providers: ProviderOption[];
  next?: string;
}) {
  const [state, action, pending] = useActionState<FormState, FormData>(
    startOAuthLogin,
    {},
  );
  if (providers.length === 0) {
    return null;
  }
  return (
    <form action={action} className="grid gap-2">
      {next && <input type="hidden" name="next" value={next} />}
      {providers.map((p) => (
        <Button
          key={p.id}
          type="submit"
          name="provider"
          value={p.id}
          variant="outline"
          disabled={pending}
        >
          Continue with {p.name}
        </Button>
      ))}
      <FormMessage message={state.message} />
    </form>
  );
}

// LinkProviderForm links another provider from the account page.
export function LinkProviderForm({
  providers,
}: {
  providers: ProviderOption[];
}) {
  const [state, action, pending] = useActionState<FormState, FormData>(
    startOAuthLink,
    {},
  );
  if (providers.length === 0) {
    return null;
  }
  return (
    <form action={action} className="grid gap-4">
      <Field
        name="current_password"
        label="Current password (if your account has one)"
        type="password"
        autoComplete="current-password"
        error={state.fieldErrors?.current_password}
      />
      <div className="flex flex-wrap gap-2">
        {providers.map((p) => (
          <Button
            key={p.id}
            type="submit"
            name="provider"
            value={p.id}
            variant="outline"
            disabled={pending}
          >
            Link {p.name}
          </Button>
        ))}
      </div>
      <FormMessage message={state.message} />
    </form>
  );
}

export function UnlinkProviderForm({ id, name }: { id: string; name: string }) {
  const [state, action, pending] = useActionState<FormState, FormData>(
    unlinkOAuth,
    {},
  );
  return (
    <form action={action} className="grid gap-2">
      <input type="hidden" name="id" value={id} />
      <Field
        name="current_password"
        label="Current password (if your account has one)"
        type="password"
        autoComplete="current-password"
        error={state.fieldErrors?.current_password}
      />
      <Button type="submit" variant="outline" disabled={pending}>
        Unlink {name}
      </Button>
      <FormMessage message={state.message} />
    </form>
  );
}
