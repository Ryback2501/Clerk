import { test, expect, Page, Request } from "@playwright/test";
import {
  addRedirectUri,
  addUser,
  applicationCard,
  applicationList,
  cardSummary,
  fieldMessage,
  hoverRow,
  openApplication,
  registerApplication,
  secretDialog,
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

    // Once its dialog is closed the secret is nowhere in the page.
    await expect(page.locator("code.secret")).toHaveCount(0);
    await expect(page.getByText(clientSecret)).toBeHidden();
    await addUser(page, id, "david");
    await expect(page.locator("code.secret")).toHaveCount(0);

    // Reloading must not show it again: only a hash is stored.
    await page.reload();
    const card = await openApplication(page, id);
    await expect(secretDialog(page)).toHaveCount(0);
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
    const create = dialog.getByRole("button", { name: "Create" });

    for (const blank of ["", "   "]) {
      await name.fill(blank);
      await expect(create).toBeDisabled();
      expect(await name.evaluate((input: HTMLInputElement) => input.validity.valid)).toBe(false);
    }
    await name.fill(uniqueName("Named"));
    await expect(create).toBeEnabled();
    await expect(dialog).toBeVisible();
    expect(posted).toBe(0);

    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toBeHidden();
  });

  test("rejects an invalid redirect URI without losing what was typed", async ({ page }) => {
    const app = await registerApplication(page, uniqueName("Bad URI"), "https://good.example.com/cb");
    const card = await openApplication(page, app.id);

    await card.getByLabel("Add a redirect URI").fill("not-a-url");
    await card.getByRole("button", { name: "Add redirect URI" }).click();

    // The reason appears under the field, where the hint was.
    await expect(fieldMessage(card, "uri")).toContainText("redirect uri");
    await expect(card.getByLabel("Add a redirect URI")).toHaveValue("not-a-url");
  });

  test("regenerating the secret asks first, then shows the new one once", async ({ page }) => {
    const { clientSecret, id } = await registerApplication(
      page,
      uniqueName("Rotating Application"),
      "https://rotate.example.com/callback",
    );

    const card = await openApplication(page, id);
    await card.getByRole("button", { name: "Regenerate client secret" }).click();

    const confirm = page.getByRole("dialog", { name: "Regenerate the client secret?" });
    await expect(confirm).toBeVisible();
    await confirm.getByRole("button", { name: "Cancel" }).click();
    await expect(confirm).toBeHidden();
    await expect(secretDialog(page)).toHaveCount(0);

    await card.getByRole("button", { name: "Regenerate client secret" }).click();
    await confirm.getByRole("button", { name: "OK", exact: true }).click();

    const secret = secretDialog(page);
    await expect(secret).toBeVisible();
    await expect(secret.locator("code.secret")).not.toHaveText(clientSecret);
    await secret.getByRole("button", { name: "OK", exact: true }).click();
    await expect(page.locator("code.secret")).toHaveCount(0);
  });

  test("the secret dialog explains itself and copies to the clipboard", async ({ page, context }) => {
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    await applicationList(page);

    await page.getByRole("button", { name: "Register application" }).click();
    const dialog = page.getByRole("dialog", { name: "Register an application" });
    await dialog.getByLabel("Application name").fill(uniqueName("Copyable"));
    await dialog.getByRole("button", { name: "Create" }).click();

    const secret = secretDialog(page);
    await expect(secret).toBeVisible();
    await expect(secret).toContainText("will not be able to see or retrieve this secret again");
    await expect(secret.getByText("Copied")).toBeHidden();

    const shown = (await secret.locator("code.secret").innerText()).trim();
    await secret.locator("[data-copy]").click();
    await expect(secret.getByText("Copied")).toBeVisible();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(shown);

    await secret.getByRole("button", { name: "OK", exact: true }).click();
    await expect(secret).toHaveCount(0);
    await expect(page.getByText(shown)).toBeHidden();
  });

  test("an application name cannot be used twice", async ({ page }) => {
    const name = uniqueName("Unique Name");
    await registerApplication(page, name, "https://unique.example.com/cb");

    await page.getByRole("button", { name: "Register application" }).click();
    const dialog = page.getByRole("dialog", { name: "Register an application" });
    const create = dialog.getByRole("button", { name: "Create" });
    const before = (await dialog.boundingBox())!;

    // The check runs while it is typed, in a slot that is always in the layout.
    await dialog.getByLabel("Application name").fill(name.toUpperCase());
    await expect(dialog.getByText("That name is already in use")).toBeVisible();
    await expect(create).toBeDisabled();
    expect((await dialog.boundingBox())!.height).toBe(before.height);

    await dialog.getByLabel("Application name").fill(`${name} II`);
    await expect(dialog.getByText("That name is already in use")).toBeHidden();
    await expect(create).toBeEnabled();

    await dialog.getByRole("button", { name: "Cancel" }).click();
  });

  test("an application can be renamed through the same dialog", async ({ page }) => {
    const before = uniqueName("Before Rename");
    const after = uniqueName("After Rename");
    const app = await registerApplication(page, before, "https://rename.example.com/cb");

    const card = await openApplication(page, app.id);
    await card.getByRole("button", { name: "Rename" }).click();

    const dialog = page.getByRole("dialog", { name: "Rename application" });
    const save = dialog.getByRole("button", { name: "Save" });
    await expect(dialog.getByLabel("Application name")).toHaveValue(before);
    // The name it already has is not a change worth saving.
    await expect(save).toBeDisabled();

    // A cancelled attempt is forgotten rather than reopened.
    await dialog.getByLabel("Application name").fill("Scratch");
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await card.getByRole("button", { name: "Rename" }).click();
    await expect(dialog.getByLabel("Application name")).toHaveValue(before);
    await expect(save).toBeDisabled();

    await dialog.getByLabel("Application name").fill(after);
    await expect(save).toBeEnabled();
    await save.click();

    await expect(dialog).toBeHidden();
    await expect(cardSummary(card)).toContainText(after);
    await expect(card.locator(".name-value")).toHaveText(after);
    // Renaming changes a label, and nothing else.
    await expect(applicationCard(page, app.id).locator(".credentials code.value").first())
      .toHaveText(app.clientId);
    await expect(page.locator(`#applications .app-name`, { hasText: before })).toHaveCount(0);
  });

  test("the folded row shows the name and the user count, and nothing else", async ({ page }) => {
    const app = await registerApplication(page, uniqueName("Tidy Row"), "https://tidy.example.com/cb");
    await addUser(page, app.id, "david");
    await page.reload();

    const summary = cardSummary(applicationCard(page, app.id));
    await expect(summary).toContainText("1 test user");
    await expect(summary).not.toContainText(app.clientId);
    await expect(summary).not.toContainText("202");
  });

  test("the danger zone starts folded", async ({ page }) => {
    const app = await registerApplication(page, uniqueName("Careful"), "https://careful.example.com/cb");
    await page.reload();
    const card = await openApplication(page, app.id);

    const danger = card.locator("details.danger-zone");
    await expect(danger).toHaveJSProperty("open", false);
    await expect(card.getByRole("button", { name: "Delete application" })).toBeHidden();

    await danger.locator("summary").click();
    await expect(card.getByRole("button", { name: "Delete application" })).toBeVisible();
  });

  test("the add forms keep the focus, so entries can be typed one after another", async ({ page }) => {
    const app = await registerApplication(page, uniqueName("Fast Entry"), "https://fast.example.com/cb");
    const card = await openApplication(page, app.id);

    // Enter submits, and the box is ready for the next name.
    await card.getByLabel("Add a test user").fill("david");
    await card.getByLabel("Add a test user").press("Enter");
    await expect(card.getByRole("cell", { name: "david", exact: true })).toBeVisible();
    await expect(card.getByLabel("Add a test user")).toBeFocused();
    await expect(card.getByLabel("Add a test user")).toHaveValue("");

    await page.keyboard.type("alice");
    await page.keyboard.press("Enter");
    await expect(card.getByRole("cell", { name: "alice", exact: true })).toBeVisible();
    await expect(card.getByLabel("Add a test user")).toBeFocused();

    // The same for redirect URIs, whether submitted by button or by Enter.
    await card.getByLabel("Add a redirect URI").fill("https://second.example.com/cb");
    await card.getByRole("button", { name: "Add redirect URI" }).click();
    await expect(card.getByRole("cell", { name: "https://second.example.com/cb", exact: true })).toBeVisible();
    await expect(card.getByLabel("Add a redirect URI")).toBeFocused();
    await expect(card.getByLabel("Add a redirect URI")).toHaveValue("");
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

  test("a duplicate is refused as it is typed, in both add forms", async ({ page }) => {
    const app = await registerApplication(page, uniqueName("Duplicates"), "https://dup.example.com/cb");
    await addUser(page, app.id, "david");
    const card = await openApplication(page, app.id);

    const userBox = card.getByLabel("Add a test user");
    const addUserButton = card.getByRole("button", { name: "Add user" });
    await userBox.fill("david");
    await expect(card.getByText("A user with that name already exists")).toBeVisible();
    await expect(addUserButton).toBeDisabled();
    await userBox.fill("alice");
    await expect(card.getByText("A user with that name already exists")).toBeHidden();
    await expect(addUserButton).toBeEnabled();

    const uriBox = card.getByLabel("Add a redirect URI");
    const addUriButton = card.getByRole("button", { name: "Add redirect URI" });
    const hint = card.getByText("Matched exactly at authorization time");
    await expect(hint).toBeVisible();

    await uriBox.fill("https://dup.example.com/cb");
    await expect(card.getByText("That redirect URI is already registered")).toBeVisible();
    // The message takes the hint's place rather than pushing the page around.
    await expect(hint).toBeHidden();
    await expect(addUriButton).toBeDisabled();

    await uriBox.fill("https://other.example.com/cb");
    await expect(card.getByText("That redirect URI is already registered")).toBeHidden();
    await expect(hint).toBeVisible();
    await expect(addUriButton).toBeEnabled();
  });

  test("removing a user or a redirect URI asks first", async ({ page }) => {
    const app = await registerApplication(page, uniqueName("Confirmed Removal"), "https://keep.example.com/cb");
    await addUser(page, app.id, "david");
    const card = await openApplication(page, app.id);

    // Cancelling leaves everything as it was.
    await (await hoverRow(card, /david/)).getByRole("button", { name: "Delete" }).click();
    const userDialog = page.getByRole("dialog", { name: "Delete this test user?" });
    await expect(userDialog).toContainText("david");
    await userDialog.getByRole("button", { name: "Cancel" }).click();
    await expect(card.getByRole("cell", { name: "david", exact: true })).toBeVisible();

    await (await hoverRow(card, /keep.example.com/)).getByRole("button", { name: "Remove" }).click();
    const uriDialog = page.getByRole("dialog", { name: "Remove this redirect URI?" });
    await expect(uriDialog).toContainText("https://keep.example.com/cb");
    await uriDialog.getByRole("button", { name: "Cancel" }).click();
    await expect(card.getByRole("cell", { name: "https://keep.example.com/cb", exact: true })).toBeVisible();

    // Confirming goes through.
    await (await hoverRow(card, /david/)).getByRole("button", { name: "Delete" }).click();
    await userDialog.getByRole("button", { name: "Delete", exact: true }).click();
    await expect(card.getByRole("cell", { name: "david", exact: true })).toBeHidden();

    await (await hoverRow(card, /keep.example.com/)).getByRole("button", { name: "Remove" }).click();
    await uriDialog.getByRole("button", { name: "Remove", exact: true }).click();
    await expect(card.getByRole("cell", { name: "https://keep.example.com/cb", exact: true })).toBeHidden();
  });

  test("row actions belong to their own application when several are unfolded", async ({ page }) => {
    const first = await registerApplication(page, uniqueName("Both Open A"), "https://first.example.com/cb");
    const second = await registerApplication(page, uniqueName("Both Open B"), "https://second.example.com/cb");

    const firstCard = await openApplication(page, first.id);
    const secondCard = await openApplication(page, second.id);
    await expect(firstCard).toHaveJSProperty("open", true);

    // Both panels hold a first redirect-URI row; the button must reach its own.
    await (await hoverRow(secondCard, /second.example.com/)).getByRole("button", { name: "Remove" }).click();
    const dialog = page.getByRole("dialog", { name: "Remove this redirect URI?" });
    await expect(dialog).toContainText("https://second.example.com/cb");
    await dialog.getByRole("button", { name: "Remove", exact: true }).click();

    await expect(secondCard.getByRole("cell", { name: "https://second.example.com/cb", exact: true })).toBeHidden();
    await expect(firstCard.getByRole("cell", { name: "https://first.example.com/cb", exact: true })).toBeVisible();
  });

  test("a user can be renamed without changing its subject", async ({ page }) => {
    const app = await registerApplication(page, uniqueName("Renamed User"), "https://ru.example.com/cb");
    await addUser(page, app.id, "david");
    await addUser(page, app.id, "alice");
    const card = await openApplication(page, app.id);

    const sub = await card.getByRole("row", { name: /david/ }).locator("code.value").innerText();
    await (await hoverRow(card, /david/)).getByRole("button", { name: "Rename" }).click();

    const dialog = page.getByRole("dialog", { name: "Rename test user" });
    const save = dialog.getByRole("button", { name: "Save" });
    const box = dialog.getByLabel("User name");
    await expect(box).toHaveValue("david");
    await expect(save).toBeDisabled();

    // The dialog refuses a duplicate exactly as the add form does.
    await box.fill("alice");
    await expect(dialog.getByText("A user with that name already exists")).toBeVisible();
    await expect(save).toBeDisabled();

    await box.fill("David Jones");
    await expect(dialog.getByText("A user with that name already exists")).toBeHidden();
    await expect(save).toBeEnabled();
    await save.click();

    await expect(dialog).toBeHidden();
    await expect(card.getByRole("cell", { name: "David Jones", exact: true })).toBeVisible();
    // The sub is what a client stores; renaming must not disturb it.
    await expect(card.getByRole("row", { name: /David Jones/ }).locator("code.value")).toHaveText(sub);
  });

  test("a redirect URI can be corrected in place", async ({ page }) => {
    const app = await registerApplication(page, uniqueName("Edited URI"), "https://typo.example.com/cb");
    await addRedirectUri(page, app.id, "https://other.example.com/cb");
    const card = await openApplication(page, app.id);

    await (await hoverRow(card, /typo.example.com/)).getByRole("button", { name: "Edit" }).click();
    const dialog = page.getByRole("dialog", { name: "Edit redirect URI" });
    const save = dialog.getByRole("button", { name: "Save" });
    const box = dialog.getByLabel("Redirect URI");
    await expect(box).toHaveValue("https://typo.example.com/cb");
    await expect(save).toBeDisabled();

    await box.fill("https://other.example.com/cb");
    await expect(dialog.getByText("That redirect URI is already registered")).toBeVisible();
    await expect(save).toBeDisabled();

    await box.fill("https://fixed.example.com/cb");
    await expect(save).toBeEnabled();
    await save.click();

    await expect(dialog).toBeHidden();
    await expect(card.getByRole("cell", { name: "https://fixed.example.com/cb", exact: true })).toBeVisible();
    await expect(card.getByRole("cell", { name: "https://typo.example.com/cb", exact: true })).toBeHidden();
    await expect(card.getByRole("cell", { name: "https://other.example.com/cb", exact: true })).toBeVisible();
  });

  test("row buttons appear only on the row being pointed at", async ({ page }) => {
    const app = await registerApplication(page, uniqueName("Hover Rows"), "https://hover.example.com/cb");
    await addUser(page, app.id, "david");
    const card = await openApplication(page, app.id);

    const row = card.getByRole("row", { name: /david/ });
    const rename = row.getByRole("button", { name: "Rename" });
    const shown = () => rename.evaluate((el) => getComputedStyle(el).opacity);

    expect(await shown()).toBe("0");
    await row.hover();
    await expect.poll(shown).toBe("1");

    // They stay reachable without a pointer: focusing one brings it back.
    await page.mouse.move(0, 0);
    await expect.poll(shown).toBe("0");
    await rename.focus();
    await expect.poll(shown).toBe("1");
  });

  test("the danger zone's arrow turns as it opens", async ({ page }) => {
    const app = await registerApplication(page, uniqueName("Arrow"), "https://arrow.example.com/cb");
    const card = await openApplication(page, app.id);

    const danger = card.locator("details.danger-zone");
    const arrow = danger.locator("summary .app-chevron");
    const rotation = () => arrow.evaluate((el) => getComputedStyle(el).transform);

    const folded = await rotation();
    await danger.locator("summary").click();
    await expect(danger).toHaveJSProperty("open", true);
    await expect.poll(rotation).not.toBe(folded);
  });

  test("deleting an application confirms in a centred dialog first", async ({ page }) => {
    const name = uniqueName("Doomed Application");
    const app = await registerApplication(page, name, "https://doomed.example.com/cb");
    await addUser(page, app.id, "david");
    await addUser(page, app.id, "alice");

    const card = await openApplication(page, app.id);
    await expect(cardSummary(card)).toContainText("2 test users");
    await card.locator("details.danger-zone summary").click();
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
      await cardSummary(card).click();
      await cardSummary(card).click();
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
      await cardSummary(card).click();
      await expect(card).toHaveJSProperty("open", false);
      await cardSummary(card).click();
      await expect(card.locator(".panel")).toBeVisible();
    }
    expect(afterReload).toHaveLength(1);

    // Changes in the panel are posted, not followed by another fetch.
    await addRedirectUri(page, app.id, "https://twice.example.com/cb");
    expect(afterReload).toHaveLength(1);
  });

  test("a long page scrolls, and nothing ends up hidden under the fixed top bar", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 480 });
    const app = await registerApplication(page, uniqueName("Scrolling"), "https://scroll.example.com/cb");
    await page.reload();
    await openApplication(page, app.id);

    const scroll = () => page.evaluate(() => ({
      y: window.scrollY,
      max: document.scrollingElement!.scrollHeight - window.innerHeight,
    }));
    expect((await scroll()).max).toBeGreaterThan(0);

    await page.mouse.move(640, 300);
    await page.mouse.wheel(0, 400);
    await expect.poll(async () => (await scroll()).y).toBeGreaterThan(0);

    // The last control on the page can be reached, and the bar stays put.
    const register = page.getByRole("button", { name: "Register application" });
    await register.scrollIntoViewIfNeeded();
    await expect(register).toBeInViewport();
    await expect(page.locator(".topbar")).toBeInViewport();

    // Bringing an application into view — as the page does after creating one —
    // stops below the bar, not underneath it.
    await page.keyboard.press("End");
    const summary = cardSummary(applicationCard(page, app.id));
    await summary.evaluate((el) => el.scrollIntoView({ block: "start" }));
    const bar = (await page.locator(".topbar").boundingBox())!;
    const box = (await summary.boundingBox())!;
    expect(box.y).toBeGreaterThanOrEqual(bar.y + bar.height);
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
    await cardSummary(card).click();
    await expect(host).toHaveAttribute("aria-busy", "true");
    await expect(host).toHaveJSProperty("inert", true);

    // The summary stays usable mid-load, and unfolding again does not ask twice.
    await cardSummary(card).click();
    await expect(card).toHaveJSProperty("open", false);
    await cardSummary(card).click();
    await expect(card).toHaveJSProperty("open", true);
    await expect(host).toHaveAttribute("aria-busy", "true");

    held.open();
    await expect(card.locator(".panel")).toBeVisible();
    await expect(host).not.toHaveAttribute("aria-busy", "true");
    expect(requests).toHaveLength(1);
  });
});
