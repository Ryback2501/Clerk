import { test, expect } from "@playwright/test";
import { registerApplication, addUser, pageAlert, uniqueName } from "./helpers";

test.describe("administration", () => {
  test("registers an application and shows its secret exactly once", async ({ page }) => {
    const { clientId, clientSecret, id } = await registerApplication(
      page,
      uniqueName("E2E Application"),
      "https://e2e.example.com/callback",
    );

    expect(clientId).toMatch(/^[A-Za-z0-9_-]{20,}$/);
    expect(clientSecret).toMatch(/^[A-Za-z0-9_-]{40,}$/);
    expect(clientSecret).not.toEqual(clientId);

    // Reloading must not show it again: only a hash is stored.
    await page.reload();
    await expect(page.getByText("Copy it now")).toBeHidden();
    await expect(page.getByText(clientSecret)).toBeHidden();

    // The client id is not a secret and stays visible.
    await expect(page.locator("dd code.value").first()).toHaveText(clientId);
    expect(id).toMatch(/^\d+$/);
  });

  test("rejects an invalid redirect URI without losing the form", async ({ page }) => {
    await page.goto("/admin/applications/new");
    await page.getByLabel("Application name").fill("Bad URI Application");
    await page.getByLabel("Redirect URIs").fill("not-a-url");
    await page.getByRole("button", { name: "Register application" }).click();

    await expect(pageAlert(page)).toContainText("redirect uri");
    // What was typed must survive, rather than having to be retyped.
    await expect(page.getByLabel("Application name")).toHaveValue("Bad URI Application");
    await expect(page.getByLabel("Redirect URIs")).toHaveValue("not-a-url");
  });

  test("regenerating the secret invalidates the previous one", async ({ page }) => {
    const { clientSecret, id } = await registerApplication(
      page,
      uniqueName("Rotating Application"),
      "https://rotate.example.com/callback",
    );

    await page.goto(`/admin/applications/${id}`);
    await page.getByRole("button", { name: "Regenerate client secret" }).click();

    await expect(page.getByText("Copy it now")).toBeVisible();
    const rotated = (await page.locator("article code.value").first().innerText()).trim();
    expect(rotated).not.toEqual(clientSecret);
  });

  test("the same user name is allowed in two applications", async ({ page }) => {
    const first = await registerApplication(page, uniqueName("Users A"), "https://a.example.com/cb");
    const second = await registerApplication(page, uniqueName("Users B"), "https://b.example.com/cb");

    await addUser(page, first.id, "david");
    await addUser(page, second.id, "david");

    // Two identities with the same name must have different subjects.
    await page.goto(`/admin/applications/${first.id}`);
    const subA = await page.locator("tbody code.value").first().innerText();
    await page.goto(`/admin/applications/${second.id}`);
    const subB = await page.locator("tbody code.value").first().innerText();

    expect(subA).not.toEqual(subB);
  });

  test("a duplicate user name within one application is refused", async ({ page }) => {
    const app = await registerApplication(page, uniqueName("Duplicate Users"), "https://dup.example.com/cb");
    await addUser(page, app.id, "david");

    await page.getByLabel("Add a test user").fill("david");
    await page.getByRole("button", { name: "Add user" }).click();
    await expect(pageAlert(page)).toContainText("already exists");
  });

  test("deleting an application warns about its users first", async ({ page }) => {
    const name = uniqueName("Doomed Application");
    const app = await registerApplication(page, name, "https://doomed.example.com/cb");
    await addUser(page, app.id, "david");
    await addUser(page, app.id, "alice");

    await page.goto(`/admin/applications/${app.id}`);
    await page.getByRole("button", { name: "Delete application" }).click();

    await expect(page.getByText("permanently delete")).toBeVisible();
    await expect(page.getByText("cannot be undone")).toBeVisible();
    // The count of what will be destroyed must be stated, not implied.
    await expect(page.locator("article")).toContainText("2");

    await page.getByRole("button", { name: "Delete application" }).click();
    await expect(page).toHaveURL(/\/admin$/);
    await expect(page.getByRole("link", { name, exact: true })).toHaveCount(0);
  });
});
