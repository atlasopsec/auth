import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  resolve: {
    tsconfigPaths: true,
    alias: {
      // "server-only" throws outside Next.js's server bundles.
      "server-only": new URL("./src/test/empty.ts", import.meta.url).pathname,
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["./src/test/setup.ts"],
    env: {
      API_URL: "http://api.test",
      OAUTH_PROVIDERS: "google",
      MOBILE_OAUTH_REDIRECT_URL: "exampleapp://oauth",
    },
  },
});
