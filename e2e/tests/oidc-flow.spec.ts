import { test, expect, request } from "@playwright/test";
import { registerApplication, addUser, uniqueName } from "./helpers";

/**
 * The whole point of the provider: a third-party application signs a user in.
 *
 * This drives the browser exactly as a real client would — redirect to
 * /authorize, pick an identity, get sent back with a code — and then exchanges
 * that code server-side and verifies the ID token against the published JWKS.
 */
test("a third-party application can sign a test user in", async ({ page, baseURL }) => {
  const redirectUri = "https://client.example.com/callback";
  const app = await registerApplication(page, uniqueName("Flow Application"), redirectUri);
  await addUser(page, app.id, "david");

  // The client sends the browser to the provider.
  const authorize = new URL("/authorize", baseURL!);
  authorize.searchParams.set("client_id", app.clientId);
  authorize.searchParams.set("redirect_uri", redirectUri);
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("scope", "openid profile");
  authorize.searchParams.set("state", "e2e-state-value");
  authorize.searchParams.set("nonce", "e2e-nonce-value");

  await page.goto(authorize.toString());

  await expect(page.getByRole("heading", { name: /^Sign in to Flow Application/ })).toBeVisible();
  // §8: no password, no consent step.
  await expect(page.locator('input[type="password"]')).toHaveCount(0);

  await page.getByLabel("Select user").selectOption({ label: "david" });

  // Read the redirect itself rather than following it. The registered URI is a
  // real-looking address that does not resolve, and a browser cannot be sent
  // somewhere that does not exist — what matters is what the provider puts in
  // the Location header, which is exactly what a real client would receive.
  const [redirect] = await Promise.all([
    page.waitForResponse(
      (r) => r.url().includes("/authorize") && r.request().method() === "POST",
    ),
    page.getByRole("button", { name: "Login" }).click().catch(() => {}),
  ]);

  expect(redirect.status()).toBe(302);
  const returned = new URL(redirect.headers()["location"]);
  expect(returned.origin + returned.pathname).toBe(redirectUri);

  const code = returned.searchParams.get("code");

  expect(code).toBeTruthy();
  expect(returned.searchParams.get("state")).toBe("e2e-state-value");

  // From here a real client works server-side.
  const api = await request.newContext({ baseURL });

  const tokenResponse = await api.post("/token", {
    form: {
      grant_type: "authorization_code",
      code: code!,
      redirect_uri: redirectUri,
      client_id: app.clientId,
      client_secret: app.clientSecret,
    },
  });
  expect(tokenResponse.status()).toBe(200);
  const tokens = await tokenResponse.json();
  expect(tokens.token_type).toBe("Bearer");
  expect(tokens.id_token).toBeTruthy();
  expect(tokens.refresh_token).toBeUndefined();

  // The ID token must assert this sign-in, and nothing more.
  const claims = JSON.parse(
    Buffer.from(tokens.id_token.split(".")[1], "base64url").toString("utf8"),
  );
  const discovery = await (await api.get("/.well-known/openid-configuration")).json();
  expect(claims.iss).toBe(discovery.issuer);
  expect(claims.aud).toBe(app.clientId);
  expect(claims.nonce).toBe("e2e-nonce-value");
  expect(claims.name).toBe("david");
  expect(claims.email).toBeUndefined();

  // The signing key must be published where discovery says it is.
  const jwks = await (await api.get(new URL(discovery.jwks_uri).pathname)).json();
  const header = JSON.parse(
    Buffer.from(tokens.id_token.split(".")[0], "base64url").toString("utf8"),
  );
  expect(jwks.keys.some((k: { kid: string }) => k.kid === header.kid)).toBe(true);

  // UserInfo must describe the same account.
  const userinfo = await api.get("/userinfo", {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  });
  expect(userinfo.status()).toBe(200);
  expect(await userinfo.json()).toEqual({ sub: claims.sub, name: "david" });

  // A code is good exactly once.
  const replay = await api.post("/token", {
    form: {
      grant_type: "authorization_code",
      code: code!,
      redirect_uri: redirectUri,
      client_id: app.clientId,
      client_secret: app.clientSecret,
    },
  });
  expect(replay.status()).toBe(400);
  expect((await replay.json()).error).toBe("invalid_grant");
});

test("an unregistered redirect URI is refused without redirecting", async ({ page, baseURL }) => {
  const app = await registerApplication(page, uniqueName("Strict Redirect"), "https://strict.example.com/cb");
  await addUser(page, app.id, "david");

  const authorize = new URL("/authorize", baseURL!);
  authorize.searchParams.set("client_id", app.clientId);
  authorize.searchParams.set("redirect_uri", "https://attacker.example.com/steal");
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("scope", "openid");

  const response = await page.goto(authorize.toString());

  // Nothing may be sent to an address that is not registered.
  expect(response?.status()).toBe(400);
  expect(new URL(page.url()).host).toBe(new URL(baseURL!).host);
  await expect(page.getByRole("heading", { name: /Invalid redirect URI/ })).toBeVisible();
  // The rejected address is attacker-supplied and must not be echoed back.
  await expect(page.locator("main")).not.toContainText("attacker.example.com");
});

test("an application with no users explains itself", async ({ page, baseURL }) => {
  const app = await registerApplication(page, uniqueName("Empty Application"), "https://empty.example.com/cb");

  const authorize = new URL("/authorize", baseURL!);
  authorize.searchParams.set("client_id", app.clientId);
  authorize.searchParams.set("redirect_uri", "https://empty.example.com/cb");
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("scope", "openid");

  await page.goto(authorize.toString());
  await expect(page.getByRole("heading", { name: /No test users/ })).toBeVisible();
  await expect(page.getByRole("button", { name: "Login" })).toHaveCount(0);
});
