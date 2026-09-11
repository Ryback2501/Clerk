import { Page, expect } from "@playwright/test";
import { randomUUID } from "node:crypto";

/**
 * A name no other run will have used.
 *
 * These tests register applications in a shared, persistent provider — the same
 * container may already hold rows from an earlier run — so a fixed name would
 * match several and make assertions about "the" application meaningless.
 */
export function uniqueName(prefix: string): string {
  return `${prefix} ${randomUUID().slice(0, 8)}`;
}

/**
 * Registers an application through the admin UI and returns its credentials.
 *
 * The client secret is shown exactly once, so it is read from the page that
 * immediately follows creation — reloading first would consume the reveal and
 * leave nothing to capture.
 */
export async function registerApplication(
  page: Page,
  name: string,
  redirectUri: string,
): Promise<{ clientId: string; clientSecret: string; id: string }> {
  await page.goto("/admin/applications/new");
  await page.getByLabel("Application name").fill(name);
  await page.getByLabel("Redirect URIs").fill(redirectUri);
  await page.getByRole("button", { name: "Register application" }).click();

  await expect(page.getByText("Copy it now")).toBeVisible();

  const clientId = (await page.locator("dd code.value").first().innerText()).trim();
  const clientSecret = (await page.locator("article code.value").first().innerText()).trim();

  const id = new URL(page.url()).pathname.split("/").pop()!;
  return { clientId, clientSecret, id };
}

/** Adds a test user to an application. */
export async function addUser(page: Page, applicationId: string, username: string) {
  await page.goto(`/admin/applications/${applicationId}`);
  await page.getByLabel("Add a test user").fill(username);
  await page.getByRole("button", { name: "Add user" }).click();
  await expect(page.getByRole("cell", { name: username, exact: true })).toBeVisible();
}

/**
 * The validation error shown on a page.
 *
 * Scoped to <main>: the "administration is unauthenticated" banner in the
 * header is also role="alert", so an unscoped lookup matches two elements.
 */
export function pageAlert(page: Page) {
  return page.locator('main [role="alert"]');
}
