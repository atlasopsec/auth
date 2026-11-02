import "@testing-library/jest-dom/vitest";

import { cleanup } from "@testing-library/react";
import { afterAll, afterEach, beforeAll, beforeEach, vi } from "vitest";

import { apiServer } from "@/test/api";
import { resetFakeRequest } from "@/test/next";

vi.mock("next/headers", () => import("@/test/next"));
vi.mock("next/navigation", () => import("@/test/next"));
vi.mock("next/cache", () => ({ refresh: vi.fn() }));
vi.mock("next/server", async (importOriginal) => ({
  ...(await importOriginal<typeof import("next/server")>()),
  connection: (await import("@/test/next")).connection,
}));

beforeAll(() => apiServer.listen({ onUnhandledFrame: "error" }));
beforeEach(() => resetFakeRequest());
afterEach(() => {
  apiServer.resetHandlers();
  vi.clearAllMocks();
  cleanup();
});
afterAll(() => apiServer.close());
