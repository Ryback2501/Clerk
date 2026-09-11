import { defineConfig } from "@playwright/test";

// Clerk is expected to be already running. CI starts the container before
// invoking these tests; locally, `docker compose up -d` is enough.
const baseURL = process.env.CLERK_BASE_URL ?? "http://localhost:8080";

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
});
