import { test, expect, Page, Request } from "@playwright/test";
import {
  addRedirectUri,
  addUser,
  applicationCard,
  applicationList,
  openApplication,
  panelAlert,
  registerApplication,
  uniqueName,
} from "./helpers";

/** Records the GET requests the page makes for one application's panel. */
function panelRequests(page: Page, id: string): Request[] {
  const seen: Request[] = [];
  page.on("request", (request) => {
    if (request.method() === "GET" && new URL(request.url()).pathname === `/admin/applications/${id}`) {
      seen.push(request);
    }
  });
  return seen;
}

/** A promise and the function that resolves it, to hold a response back. */
function gate(): { opened: Promise<void>; open: () => void } {
  let open!: () => void;
  const opened = new Promise<void>((resolve) => (open = resolve));
  return { opened, open };
}

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
    expect(id).toMatch(/^\d+$/);

    // The admin never leaves the one page.
    expect(new URL(page.url()).pathname).toBe("/admin");

    // Setting the application up (registerApplication added a redirect URI)
    // must not wipe the secret before it has been copied.
    const created = applicationCard(page, id);
    await expect(created.locator("code.secret")).toHaveText(clientSecret);
    await addUser(page, id, "david");
    await expect(created.locator("code.secret")).toHaveText(clientSecret);

    // Reloading must not show it again: only a hash is stored.
    await page.reload();
    const card = await openApplication(page, id);
    await expect(card.getByText("Copy it now")).toBeHidden();
    await expect(page.getByText(clientSecret)).toBeHidden();

    // The client id is not a secret and stays visible.
    await expect(card.locator(".credentials code.value").first()).toHaveText(clientId);
  });

  test("an application cannot be registered without a name", async ({ page }) => {
    await applicationList(page);
    let posted = 0;
    page.on("request", (r) => {
      if (r.method() === "POST" && new URL(r.url()).pathname === "/admin/applications") posted++;
    });

    await page.getByRole("button", { name: "Register application" }).click();
    const dialog = page.getByRole("dialog", { name: "Register an application" });
    const name = dialog.getByLabel("Application name");

    for (const blank of ["", "   "]) {
      await name.fill(blank);
      await dialog.getByRole("button", { name: "Create" }).click();
      await expect(dialog).toBeVisible();
      expect(await name.evaluate((input: HTMLInputElement) => input.validity.valid)).toBe(false);
    }
    expect(posted).toBe(0);

    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toBeHidden();
  });

  test("rejects an invalid redirect URI without losing what was typed", async ({ page }) => {
    const app = await registerApplication(page, uniqueName("Bad URI"), "https://good.example.com/cb");
    const card = await openApplication(page, app.id);

    await card.getByLabel("Add a redirect URI").fill("not-a-url");
    await card.getByRole("button", { name: "Add redirect URI" }).click();

    await expect(panelAlert(card)).toContainText("redirect uri");
    await expect(card.getByLabel("Add a redirect URI")).toHaveValue("not-a-url");
  });

  test("regenerating the secret replaces the previous one", async ({ page }) => {
    const { clientSecret, id } = await registerApplication(
      page,
      uniqueName("Rotating Application"),
      "https://rotate.example.com/callback",
    );

    const card = await openApplication(page, id);
    await card.getByRole("button", { name: "Regenerate client secret" }).click();

    await expect(card.getByText("Copy it now")).toBeVisible();
    await expect(card.locator("code.secret")).not.toHaveText(clientSecret);
  });

  test("the same user name is allowed in two applications", async ({ page }) => {
    const first = await registerApplication(page, uniqueName("Users A"), "https://a.example.com/cb");
    const second = await registerApplication(page, uniqueName("Users B"), "https://b.example.com/cb");

    await addUser(page, first.id, "david");
    await addUser(page, second.id, "david");

    // Two identities with the same name must have different subjects.
    const subA = await (await openApplication(page, first.id)).locator("tbody code.value").last().innerText();
    const subB = await (await openApplication(page, second.id)).locator("tbody code.value").last().innerText();
    expect(subA).not.toEqual(subB);
  });

  test("a duplicate user name within one application is refused", async ({ page }) => {
    const app = await registerApplication(page, uniqueName("Duplicate Users"), "https://dup.example.com/cb");
    await addUser(page, app.id, "david");

    const card = await openApplication(page, app.id);
    await card.getByLabel("Add a test user").fill("david");
    await card.getByRole("button", { name: "Add user" }).click();
    await expect(panelAlert(card)).toContainText("already exists");
    await expect(card.getByLabel("Add a test user")).toHaveValue("david");
  });

  test("deleting an application confirms in a centred dialog first", async ({ page }) => {
    const name = uniqueName("Doomed Application");
    const app = await registerApplication(page, name, "https://doomed.example.com/cb");
    await addUser(page, app.id, "david");
    await addUser(page, app.id, "alice");

    const card = await openApplication(page, app.id);
    await expect(card.locator("summary")).toContainText("2 test users");
    await card.getByRole("button", { name: "Delete application" }).click();

    const dialog = page.getByRole("dialog", { name: "Delete application?" });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText("permanently delete")).toBeVisible();
    await expect(dialog.getByText("cannot be undone")).toBeVisible();
    // The count of what will be destroyed must be stated, not implied.
    await expect(dialog).toContainText("all 2 of its test users");

    const box = (await dialog.boundingBox())!;
    const viewport = page.viewportSize()!;
    expect(Math.abs(box.x + box.width / 2 - viewport.width / 2)).toBeLessThan(2);
    expect(Math.abs(box.y + box.height / 2 - viewport.height / 2)).toBeLessThan(2);

    await dialog.getByRole("button", { name: "Delete application" }).click();
    await expect(dialog).toBeHidden();
    await expect(applicationCard(page, app.id)).toHaveCount(0);
    expect(new URL(page.url()).pathname).toBe("/admin");
  });

  test("an application's data is requested once, when it is first unfolded", async ({ page }) => {
    const app = await registerApplication(page, uniqueName("Fetched Once"), "https://once.example.com/cb");

    // The application just created arrived with its panel: no request at all,
    // however often it is folded and unfolded.
    const afterCreate = panelRequests(page, app.id);
    const card = applicationCard(page, app.id);
    for (let i = 0; i < 2; i++) {
      await card.locator("summary").click();
      await card.locator("summary").click();
    }
    await expect(card.locator(".panel")).toBeVisible();
    expect(afterCreate).toHaveLength(0);

    // After a reload, the first unfold fetches it and later ones do not.
    await page.reload();
    const afterReload = panelRequests(page, app.id);
    await applicationList(page);
    expect(afterReload).toHaveLength(0);

    await openApplication(page, app.id);
    for (let i = 0; i < 2; i++) {
      await card.locator("summary").click();
      await expect(card).toHaveJSProperty("open", false);
      await card.locator("summary").click();
      await expect(card.locator(".panel")).toBeVisible();
    }
    expect(afterReload).toHaveLength(1);

    // Changes in the panel are posted, not followed by another fetch.
    await addRedirectUri(page, app.id, "https://twice.example.com/cb");
    expect(afterReload).toHaveLength(1);
  });

  test("the list is disabled while it loads", async ({ page }) => {
    await registerApplication(page, uniqueName("Slow List"), "https://slow.example.com/cb");

    const held = gate();
    await page.route(
      (url) => url.pathname === "/admin/applications",
      async (route) => {
        if (route.request().method() === "GET") await held.opened;
        await route.continue();
      },
    );

    await page.reload();
    const list = page.locator("#applications");
    await expect(list).toHaveAttribute("aria-busy", "true");
    await expect(list).toHaveJSProperty("inert", true);
    await expect(page.getByRole("button", { name: "Register application" })).toBeEnabled();

    held.open();
    await expect(list).not.toHaveAttribute("aria-busy", "true");
    await expect(list).toHaveJSProperty("inert", false);
  });

  test("a loading panel is disabled, but its application can still be folded", async ({ page }) => {
    const app = await registerApplication(page, uniqueName("Slow Panel"), "https://slow.example.com/cb");
    await page.reload();
    await applicationList(page);

    const requests = panelRequests(page, app.id);
    const held = gate();
    await page.route(
      (url) => url.pathname === `/admin/applications/${app.id}`,
      async (route) => {
        if (route.request().method() === "GET") await held.opened;
        await route.continue();
      },
    );

    const card = applicationCard(page, app.id);
    const host = card.locator(".panel-host");
    await card.locator("summary").click();
    await expect(host).toHaveAttribute("aria-busy", "true");
    await expect(host).toHaveJSProperty("inert", true);

    // The summary stays usable mid-load, and unfolding again does not ask twice.
    await card.locator("summary").click();
    await expect(card).toHaveJSProperty("open", false);
    await card.locator("summary").click();
    await expect(card).toHaveJSProperty("open", true);
    await expect(host).toHaveAttribute("aria-busy", "true");

    held.open();
    await expect(card.locator(".panel")).toBeVisible();
    await expect(host).not.toHaveAttribute("aria-busy", "true");
    expect(requests).toHaveLength(1);
  });
});
