// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.3.0.
import "server-only";

import { z } from "zod";

const envSchema = z
  .object({
    // The Go API's private address, e.g. http://api.railway.internal:8080.
    API_URL: z.url(),
    // The header the hosting edge puts the browser's IP in. Railway's edge
    // sets X-Real-IP. "none" forwards no IP: use it when nothing in front of
    // the web app overwrites the header, since the browser could then send
    // any IP it likes. null means none.
    CLIENT_IP_HEADER: z
      .string()
      .regex(/^[A-Za-z0-9-]+$/)
      .default("x-real-ip")
      .transform((h) => h.toLowerCase())
      .transform((h) => (h === "none" ? null : h)),
    // The sign-in providers turned on in the Go API's Config.OAuth, e.g.
    // "google,github". Their buttons appear on the login and account pages.
    OAUTH_PROVIDERS: z
      .string()
      .default("")
      .transform((s) =>
        s
          .split(",")
          .map((p) => p.trim())
          .filter(Boolean),
      )
      .pipe(z.array(z.enum(["google", "github"]))),
    // The mobile app's deep link for finishing a sign-in, e.g.
    // exampleapp://oauth. Without it, /oauth/callback/mobile answers 404.
    MOBILE_OAUTH_REDIRECT_URL: z.url().optional(),
    // "true" refuses a MOBILE_OAUTH_REDIRECT_URL that isn't https. Any app
    // can register a custom scheme, so another app on the device could
    // catch the redirect; an https link is tied to the app by the domain.
    MOBILE_OAUTH_REQUIRE_HTTPS: z
      .enum(["true", "false"])
      .default("false")
      .transform((v) => v === "true"),
  })
  .refine(
    (e) =>
      !e.MOBILE_OAUTH_REQUIRE_HTTPS ||
      e.MOBILE_OAUTH_REDIRECT_URL === undefined ||
      new URL(e.MOBILE_OAUTH_REDIRECT_URL).protocol === "https:",
    {
      path: ["MOBILE_OAUTH_REDIRECT_URL"],
      message: "must be an https link when MOBILE_OAUTH_REQUIRE_HTTPS is true",
    },
  );

export type Env = z.infer<typeof envSchema>;

let parsed: Env | undefined;

// env returns the settings, checked on first use. instrumentation.ts calls
// it when the server starts, so a missing variable stops the deploy instead
// of failing requests. It isn't read at build time, so a Docker build
// doesn't need the runtime settings.
export function env(): Env {
  parsed ??= envSchema.parse(process.env);
  return parsed;
}
