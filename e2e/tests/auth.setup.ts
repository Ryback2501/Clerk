import { test as setup, expect } from "@playwright/test";
import { adminState } from "../playwright.config";

/**
 * Signs in to the admin interface once, through the real sign-in path: the
 * upstream provider (a mock in the e2e stack) and the role check (a Bouncer
 * stub). Every other test starts from the session this leaves behind.
 */
setup("sign in as an administrator", async ({ page }) => {
  await page.goto("/admin");
  await expect(page).toHaveURL(/\/admin\/signin$/);

  await page.getByRole("link", { name: /google/i }).click();

  await expect(page).toHaveURL(/\/admin$/);
  await expect(page.getByRole("button", { name: "Sign out" })).toBeVisible();

  await page.context().storageState({ path: adminState });
});
