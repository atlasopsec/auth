// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    // Checks the settings at startup. Next.js would otherwise log the
    // error and keep serving, failing every request.
    const { env } = await import("@/lib/env");
    try {
      env();
    } catch (e) {
      console.error("Invalid environment variables:", e);
      process.exit(1);
    }
  }
}
