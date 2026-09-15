import { Locator, Page, expect } from "@playwright/test";
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

/** The list of applications, once it has finished loading. */
export async function applicationList(page: Page): Promise<Locator> {
  if (new URL(page.url()).pathname !== "/admin") {
    await page.goto("/admin");
  }
  const list = page.locator("#applications");
  await expect(list).not.toHaveAttribute("aria-busy", "true");
  return list;
}

/** One application's foldable card. */
export function applicationCard(page: Page, id: string): Locator {
  return page.locator(`#applications details[data-app="${id}"]`);
}

/** Unfolds an application, if it is not already, and waits for its panel. */
export async function openApplication(page: Page, id: string): Promise<Locator> {
  await applicationList(page);
  const card = applicationCard(page, id);
  if (!(await card.evaluate((details: HTMLDetailsElement) => details.open))) {
    await card.locator("summary").click();
  }
  await expect(card.locator(".panel")).toBeVisible();
  return card;
}

/**
 * Registers an application through the admin UI, adds a redirect URI to it,
 * and returns its credentials.
 *
 * The client secret is shown exactly once, in the unfolded card that follows
 * creation, so it is read there before anything else can replace it.
 */
export async function registerApplication(
  page: Page,
  name: string,
  redirectUri: string,
): Promise<{ clientId: string; clientSecret: string; id: string }> {
  await page.goto("/admin");
  await applicationList(page);

  await page.getByRole("button", { name: "Register application" }).click();
  const dialog = page.getByRole("dialog", { name: "Register an application" });
  await dialog.getByLabel("Application name").fill(name);

  const created = page.waitForResponse(
    (r) => new URL(r.url()).pathname === "/admin/applications" && r.request().method() === "POST",
  );
  await dialog.getByRole("button", { name: "Create" }).click();
  const response = await created;
  expect(response.status()).toBe(201);
  const id = response.headers()["x-clerk-application"];

  const card = applicationCard(page, id);
  await expect(card).toHaveJSProperty("open", true);
  await expect(card.getByText("Copy it now")).toBeVisible();

  const clientId = (await card.locator(".credentials code.value").first().innerText()).trim();
  const clientSecret = (await card.locator("code.secret").innerText()).trim();

  await addRedirectUri(page, id, redirectUri);
  return { clientId, clientSecret, id };
}

/** Adds a redirect URI to an application. */
export async function addRedirectUri(page: Page, id: string, uri: string) {
  const card = await openApplication(page, id);
  await card.getByLabel("Add a redirect URI").fill(uri);
  await card.getByRole("button", { name: "Add redirect URI" }).click();
  await expect(card.getByRole("cell", { name: uri, exact: true })).toBeVisible();
}

/** Adds a test user to an application. */
export async function addUser(page: Page, id: string, username: string) {
  const card = await openApplication(page, id);
  await card.getByLabel("Add a test user").fill(username);
  await card.getByRole("button", { name: "Add user" }).click();
  await expect(card.getByRole("cell", { name: username, exact: true })).toBeVisible();
}

/**
 * The validation error inside one application's panel, so an alert anywhere
 * else can never be mistaken for it.
 */
export function panelAlert(card: Locator): Locator {
  return card.locator('.panel [role="alert"]');
}
