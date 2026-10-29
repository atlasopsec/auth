import { defineConfig, devices } from "@playwright/test";

// The end-to-end tests run the template against the real auth module:
// examples/api, on the Postgres in E2E_DATABASE_URL. The Go API prints
// emails to MAIL_FILE, where the tests read the links.
export const API_URL = "http://127.0.0.1:18080";
export const WEB_URL = "http://localhost:3100";
export const MAIL_FILE = ".e2e/mail.txt";

const databaseURL = process.env.E2E_DATABASE_URL;
if (!databaseURL) {
  throw new Error("E2E_DATABASE_URL must point at an empty Postgres database");
}

export default defineConfig({
  testDir: "e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: WEB_URL,
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: {
        ...devices["Desktop Chrome"],
        launchOptions: process.env.PLAYWRIGHT_CHROMIUM_PATH
          ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_PATH }
          : {},
      },
    },
  ],
  webServer: [
    {
      command: "rm -rf .e2e && mkdir .e2e && go run ../../examples/api",
      url: `${API_URL}/healthz`,
      timeout: 120_000,
      reuseExistingServer: false,
      env: {
        DATABASE_URL: databaseURL,
        // An obviously fake key: 32 bytes of 0x01.
        ENCRYPTION_KEY: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        PORT: "18080",
        APP_URL: WEB_URL,
        MAIL_FILE,
        DISABLE_BREACH_CHECK: "true",
      },
    },
    {
      command: "pnpm build && pnpm start --port 3100",
      url: WEB_URL,
      timeout: 240_000,
      reuseExistingServer: false,
      env: { API_URL },
    },
  ],
});
