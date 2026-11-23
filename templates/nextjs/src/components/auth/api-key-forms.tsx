"use client";

// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.6.0.
import { useActionState, useId } from "react";

import { Field, FormMessage } from "@/components/auth/field";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { createApiKey, revokeApiKey } from "@/lib/auth/account-actions";
import {
  API_KEY_LIFETIMES,
  API_KEY_PERMISSIONS,
  DEFAULT_API_KEY_LIFETIME,
} from "@/lib/auth/api-keys";
import type { FormState } from "@/lib/auth/form-state";

// NewApiKey shows a new key. It's shown only once.
export function NewApiKey({ apiKey }: { apiKey: string }) {
  return (
    <div className="grid gap-2">
      <p role="status">
        Copy this key now and keep it somewhere safe, such as the other
        system&apos;s secret settings. It won&apos;t be shown again.
      </p>
      <p className="rounded-md border border-neutral-300 p-3 font-mono text-sm break-all dark:border-neutral-700">
        {apiKey}
      </p>
      <p className="text-sm text-neutral-500">
        Anything holding it can act as you, with the permissions you chose,
        until it expires or you revoke it.
      </p>
      {/* A full page load, so the key leaves the page and the list updates. */}
      <a href="/account/api-keys" className="underline">
        Done
      </a>
    </div>
  );
}

// CreateApiKeyForm makes an API key. twoFactor says whether to ask for a
// code: the Go API needs one when the user has 2FA on.
export function CreateApiKeyForm({ twoFactor }: { twoFactor: boolean }) {
  const [state, action, pending] = useActionState<FormState, FormData>(
    createApiKey,
    {},
  );
  const lifetimeId = useId();
  const permissionsError = useId();
  if (state.apiKey) {
    return <NewApiKey apiKey={state.apiKey} />;
  }
  const errors = state.fieldErrors ?? {};
  return (
    <form action={action} className="grid gap-4">
      <Field
        name="name"
        label="Name"
        placeholder="What will use it"
        maxLength={100}
        required
        defaultValue={state.values?.name}
        error={errors.name}
      />
      <fieldset
        className="grid gap-2"
        aria-describedby={errors.permissions ? permissionsError : undefined}
      >
        <legend className="text-sm font-medium">Permissions</legend>
        {API_KEY_PERMISSIONS.map((p) => (
          <label key={p.value} className="flex items-center gap-2 text-sm">
            <input type="checkbox" name="permissions" value={p.value} />
            {p.label}
          </label>
        ))}
        {errors.permissions && (
          <p id={permissionsError} className="text-sm text-red-600">
            {errors.permissions}
          </p>
        )}
      </fieldset>
      <div className="grid gap-2">
        <Label htmlFor={lifetimeId}>Expires after</Label>
        <select
          id={lifetimeId}
          name="lifetime"
          defaultValue={DEFAULT_API_KEY_LIFETIME}
          className="h-9 w-full rounded-md border border-neutral-300 bg-transparent px-3 text-sm dark:border-neutral-700"
        >
          {API_KEY_LIFETIMES.map((days) => (
            <option key={days} value={days}>
              {days} days
            </option>
          ))}
        </select>
        {errors.expires_at && (
          <p className="text-sm text-red-600">{errors.expires_at}</p>
        )}
      </div>
      <Field
        name="current_password"
        label="Current password"
        type="password"
        autoComplete="current-password"
        required
        error={errors.current_password}
      />
      {twoFactor && (
        <Field
          name="code"
          label="Code from your authenticator app"
          autoComplete="one-time-code"
          inputMode="numeric"
          required
          error={errors.code}
        />
      )}
      <FormMessage message={state.message} />
      <Button type="submit" disabled={pending}>
        Create key
      </Button>
    </form>
  );
}

export function RevokeApiKeyButton({ id }: { id: string }) {
  const [state, action, pending] = useActionState<FormState, FormData>(
    revokeApiKey,
    {},
  );
  return (
    <form action={action}>
      <input type="hidden" name="id" value={id} />
      <Button type="submit" variant="outline" disabled={pending}>
        Revoke
      </Button>
      <FormMessage message={state.message} />
    </form>
  );
}
