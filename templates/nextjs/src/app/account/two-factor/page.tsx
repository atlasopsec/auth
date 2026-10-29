// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { LogOutButton } from "@/components/auth/log-out-button";
import {
  RegenerateRecoveryCodes,
  TurnOffTwoFactor,
  TurnOnTwoFactor,
} from "@/components/auth/two-factor-settings";
import { TWO_FACTOR_SETUP_PATH, requireSession } from "@/lib/auth/session";

export default async function TwoFactorSettingsPage() {
  // Users who must set up 2FA are sent here, so this page lets them in.
  const session = await requireSession(TWO_FACTOR_SETUP_PATH, {
    duringTwoFactorSetup: true,
  });
  if (!session.two_factor_enabled) {
    return (
      <>
        <h1 className="text-2xl font-semibold">Two-factor authentication</h1>
        {session.two_factor_required && (
          <p role="status">
            Your account needs two-factor authentication. Set it up to continue.
          </p>
        )}
        <p>
          Logging in will also ask for a code from an authenticator app on your
          phone, so a stolen password isn&apos;t enough.
        </p>
        <TurnOnTwoFactor />
        {/* They can't reach any other page until they're done. */}
        {session.two_factor_required && <LogOutButton />}
      </>
    );
  }
  return (
    <>
      <h1 className="text-2xl font-semibold">Two-factor authentication</h1>
      <p>On. Logging in asks for a code from your authenticator app.</p>
      <section className="grid gap-4">
        <h2 className="text-lg font-semibold">Recovery codes</h2>
        <RegenerateRecoveryCodes />
      </section>
      <section className="grid gap-4">
        <h2 className="text-lg font-semibold">Turn it off</h2>
        <TurnOffTwoFactor />
      </section>
    </>
  );
}
