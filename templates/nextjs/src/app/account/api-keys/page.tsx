// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.6.0.
import {
  CreateApiKeyForm,
  RevokeApiKeyButton,
} from "@/components/auth/api-key-forms";
import { callApi } from "@/lib/api/client";
import { apiKeyListSchema, type ApiKeyInfo } from "@/lib/api/schemas";
import { getSessionToken, requireSession } from "@/lib/auth/session";

// The API keys page, for projects that turn keys on (the Go API's
// Config.APIKeyPermissions; set the same permissions in
// src/lib/auth/api-keys.ts). Without keys, don't copy it: the Go API has no
// key endpoints, and this page would fail.
export default async function ApiKeysPage() {
  const session = await requireSession("/account/api-keys");
  const { data: keys } = await callApi("/v1/api-keys", apiKeyListSchema, {
    token: await getSessionToken(),
  });
  return (
    <>
      <h1 className="text-2xl font-semibold">API keys</h1>
      <p>
        A key lets another system call this app&apos;s API as you, with only the
        permissions you give it. It never lets anyone log in.
      </p>

      <section className="grid gap-4">
        <h2 className="text-lg font-semibold">Your keys</h2>
        {keys.length === 0 ? (
          <p>No keys yet.</p>
        ) : (
          <ul className="grid gap-4">
            {keys.map((k) => (
              <ApiKeyRow key={k.id} apiKey={k} />
            ))}
          </ul>
        )}
      </section>

      <section className="grid gap-4">
        <h2 className="text-lg font-semibold">New key</h2>
        <CreateApiKeyForm twoFactor={session.two_factor_enabled} />
      </section>
    </>
  );
}

function ApiKeyRow({ apiKey: k }: { apiKey: ApiKeyInfo }) {
  return (
    <li className="flex items-start justify-between gap-4 text-sm">
      <div className="min-w-0">
        <p className="truncate font-medium">
          {k.name} <span className="font-mono text-neutral-500">{k.hint}…</span>
        </p>
        <p className="text-neutral-500">{k.permissions.join(", ")}</p>
        <p className="text-neutral-500">
          Expires {new Date(k.expires_at).toUTCString()} ·{" "}
          {k.last_used_at
            ? `last used ${new Date(k.last_used_at).toUTCString()}${k.last_used_ip ? ` from ${k.last_used_ip}` : ""}`
            : "never used"}
        </p>
      </div>
      <RevokeApiKeyButton id={k.id} />
    </li>
  );
}
