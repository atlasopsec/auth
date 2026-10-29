// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import Link from "next/link";

import {
  ChangeEmailForm,
  ChangePasswordForm,
  EndSessionButton,
  LogOutEverywhereButton,
} from "@/components/auth/account-forms";
import {
  LinkProviderForm,
  UnlinkProviderForm,
} from "@/components/auth/oauth-buttons";
import { callApi } from "@/lib/api/client";
import {
  oauthAccountsSchema,
  sessionListSchema,
  type SessionInfo,
} from "@/lib/api/schemas";
import { noticeText } from "@/lib/auth/notices";
import { PROVIDER_NAMES, enabledProviders } from "@/lib/auth/oauth";
import { getSessionToken, requireSession } from "@/lib/auth/session";

export default async function AccountPage({
  searchParams,
}: PageProps<"/account">) {
  const session = await requireSession("/account");
  const token = await getSessionToken();
  const [{ data: sessions }, { data: linked }] = await Promise.all([
    callApi("/v1/sessions", sessionListSchema, { token }),
    callApi("/v1/users/me/oauth-accounts", oauthAccountsSchema, { token }),
  ]);
  const notice = noticeText((await searchParams).notice);
  const unlinked = enabledProviders()
    .filter((p) => !linked.some((a) => a.provider === p))
    .map((id) => ({ id, name: PROVIDER_NAMES[id] }));
  return (
    <>
      <h1 className="text-2xl font-semibold">Account</h1>
      {notice && <p role="status">{notice}</p>}

      <section className="grid gap-4">
        <h2 className="text-lg font-semibold">Email</h2>
        <p>{session.email}</p>
        <ChangeEmailForm />
      </section>

      <section className="grid gap-4">
        <h2 className="text-lg font-semibold">Password</h2>
        <ChangePasswordForm />
      </section>

      <section className="grid gap-4">
        <h2 className="text-lg font-semibold">Two-factor authentication</h2>
        <p>
          {session.two_factor_enabled ? "On." : "Off."}{" "}
          <Link href="/account/two-factor" className="underline">
            Manage
          </Link>
        </p>
      </section>

      {(linked.length > 0 || unlinked.length > 0) && (
        <section className="grid gap-4">
          <h2 className="text-lg font-semibold">Sign-in providers</h2>
          <ul className="grid gap-4">
            {linked.map((a) => {
              const name =
                PROVIDER_NAMES[a.provider as keyof typeof PROVIDER_NAMES] ??
                a.provider;
              return (
                <li key={a.id} className="grid gap-2 text-sm">
                  <p>
                    {name}
                    {a.email && ` (${a.email})`}
                  </p>
                  <UnlinkProviderForm id={a.id} name={name} />
                </li>
              );
            })}
          </ul>
          <LinkProviderForm providers={unlinked} />
        </section>
      )}

      <section className="grid gap-4">
        <h2 className="text-lg font-semibold">Where you&apos;re logged in</h2>
        <ul className="grid gap-4">
          {sessions.map((s) => (
            <SessionRow key={s.id} session={s} />
          ))}
        </ul>
        <LogOutEverywhereButton />
      </section>
    </>
  );
}

function SessionRow({ session: s }: { session: SessionInfo }) {
  return (
    <li className="flex items-start justify-between gap-4 text-sm">
      <div className="min-w-0">
        <p className="truncate font-medium" title={s.user_agent ?? undefined}>
          {s.user_agent ?? "Unknown device"}
        </p>
        <p className="text-neutral-500">
          {s.ip ?? "Unknown address"} · last used{" "}
          {new Date(s.last_used_at).toUTCString()}
        </p>
      </div>
      {s.is_current ? (
        <span className="shrink-0">This device</span>
      ) : (
        <EndSessionButton id={s.id} />
      )}
    </li>
  );
}
