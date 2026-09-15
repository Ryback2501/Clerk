import { defineConfig } from "@playwright/test";
import path from "node:path";

/**
 * Where the signed-in administrator's cookies are kept for the other tests.
 * Anchored to this file so the suite works from any working directory.
 */
export const adminState = path.join(__dirname, ".auth", "admin.json");

// Clerk is expected to be already running, with its mock sign-in provider and
// role service. CI starts them with `e2e/stack.sh up` before invoking these
// tests, and the same command works locally.
const baseURL = process.env.BASE_URL ?? "http://localhost:8080";

export default defineConfig({
  testDir: "./tests",
  // These tests share one provider instance and register applications in it,
  // so they must not interleave.
  workers: 1,
  fullyParallel: false,
  // A flake here would mask a real failure; fail rather than retry.
  retries: 0,
  timeout: 30_000,
  reporter: process.env.CI ? "list" : "html",
  use: {
    baseURL,
    trace: "retain-on-failure",
  },
  projects: [
    { name: "setup", testMatch: /auth\.setup\.ts/ },
    {
      name: "e2e",
      testMatch: /\.spec\.ts/,
      dependencies: ["setup"],
      use: { storageState: adminState },
    },
  ],
});
