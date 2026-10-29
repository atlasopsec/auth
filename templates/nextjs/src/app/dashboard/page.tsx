// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { LogOutButton } from "@/components/auth/log-out-button";
import { requireSession } from "@/lib/auth/session";

// A stand-in for a project's own protected pages: each one starts with
// requireSession, which redirects logged-out visitors to the login page.
export default async function DashboardPage() {
  const session = await requireSession("/dashboard");
  return (
    <main className="mx-auto grid w-full max-w-sm gap-6 px-4 py-16">
      <h1 className="text-2xl font-semibold">Dashboard</h1>
      <p>Logged in as {session.email}.</p>
      <LogOutButton />
    </main>
  );
}
