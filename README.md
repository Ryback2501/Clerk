# Clerk
An Identity Provider (IdP) for testing and development environments to generate and manage users for testing purposes and an easy and fast login system.

## Running it

Clerk is configured entirely through environment variables (see [Configuration](#configuration)).
Administration always requires signing in, so besides `ISSUER` it needs Bouncer and at
least one sign-in provider — see [Administration access](#administration-access).
Keep them in a dedicated env file, e.g. `clerk.env` (no quotes around values):

```dotenv
ISSUER=http://localhost:8080
BOUNCER_URL=http://host.docker.internal:3000
BOUNCER_API_KEY=bncr_...
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
```

### With Docker

```bash
docker run -d --name clerk \
  --env-file clerk.env \
  --add-host=host.docker.internal:host-gateway \
  -v clerk-data:/data \
  -v clerk-keys:/keys \
  -p 8080:8080 \
  ryback2501/clerk:latest
```

Inside the container `localhost` is the container itself, so a Bouncer running on your
machine is reached as `host.docker.internal` (which `--add-host` makes resolvable on
Linux); a Bouncer in another container is reached by its name on a shared Docker network.
The image has a built-in healthcheck, so `docker ps` reports the container as healthy
once it is serving.

### From source

```bash
set -a; source clerk.env; set +a
export BOUNCER_URL=http://localhost:3000   # no container in between
export DB_PATH=./data/clerk.db KEYS_PATH=./keys/signing.pem
mkdir -p data keys
go run ./cmd/clerk
```

The default database and key paths are container paths, hence the overrides.

### Trying it without credentials

`e2e/stack.sh` runs Clerk from source next to a mock sign-in provider and a Bouncer stub
that make you an administrator — the same stack the end-to-end tests use:

```bash
e2e/stack.sh up     # then open http://localhost:8080/admin and sign in with "google"
e2e/stack.sh down
```

It uses host networking, so the browser and Clerk see the mock provider at the same
address, and ports 8080–8082 must be free. It works as-is on Linux; Docker Desktop on
macOS or Windows needs host networking enabled in its settings.

In every case, open <http://localhost:8080/admin> to register an application, then
connect your application as described in [Using Clerk as an identity provider](#using-clerk-as-an-identity-provider).

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `ISSUER` | *(required)* | Public base URL of the provider. Published as `issuer` and as the `iss` claim, so it must match what clients are configured with exactly. |
| `LISTEN_ADDR` | `:8080` | Address to listen on. |
| `DB_PATH` | `/data/clerk.db` | SQLite database path. |
| `KEYS_PATH` | `/keys/signing.pem` | RS256 signing key path. Generated on first run and never regenerated. |
| `CODE_TTL` | `1m` | Authorization code lifetime. |
| `ACCESS_TOKEN_TTL` | `1h` | Access token lifetime. |
| `ID_TOKEN_TTL` | `1h` | ID token lifetime. |

### Administration access

Administrators sign in with an external OAuth provider, and whether they may
administer this provider is then decided by [Bouncer](https://github.com/Ryback2501/Bouncer).
Clerk refuses to start unless this is configured: there is no unauthenticated mode.

| Variable | Meaning |
|---|---|
| `BOUNCER_URL` | Where Bouncer is reachable, e.g. `http://bouncer:3000`. |
| `BOUNCER_API_KEY` | The `bncr_…` key Bouncer issued for Clerk's application. |
| `BOUNCER_REQUIRED_ROLE` | Role `customId` an administrator must hold. Default `admin`; empty accepts any active role. |
| `GOOGLE_CLIENT_ID` / `_SECRET` | Google OAuth credentials. |
| `GITHUB_CLIENT_ID` / `_SECRET` | GitHub OAuth credentials. |
| `MICROSOFT_CLIENT_ID` / `_SECRET` | Microsoft OAuth credentials. |
| `LINKEDIN_CLIENT_ID` / `_SECRET` | LinkedIn OAuth credentials. |
| `<PROVIDER>_ISSUER` | Overrides that provider's OIDC issuer. Microsoft **single-tenant** applications need `MICROSOFT_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0`; the default is the multi-tenant endpoint and a single-tenant app's tokens would not validate against it. |

At least one provider is required. Register this callback with each one, exactly:

```text
<ISSUER>/admin/auth/<provider>/callback
```

Clerk logs each callback URL at startup so it can be copied verbatim.

#### Setting up Bouncer

1. In Bouncer, register an application for Clerk and create the `admin` role.
2. Issue an API key for it and set it as `BOUNCER_API_KEY`.
3. Assign yourself that role, using the same provider you will sign in to Clerk with.

The subject Clerk sends is the identifier Bouncer recorded for you, which is **not**
the same claim for every provider — Microsoft in particular is matched on `oid`, since
its `sub` is issued per-client and would never match. Clerk handles this per provider;
it matters only if you are debugging a `user_not_found` response.

**A Bouncer outage closes administration and nothing else.** The OIDC endpoints keep
issuing tokens normally, which is verified by a test that runs the full flow with the
role service unreachable.

### Volumes

Both must persist, or every client breaks on restart:

- `/data` — the SQLite database.
- `/keys` — the RS256 signing key. A new key would invalidate every token ever issued.

The container runs as uid 65532 and does not terminate TLS; put a reverse proxy in front
of it and forward the full path.

## Using Clerk as an identity provider

A third-party application talks to Clerk exactly as it would to Google or Microsoft:
standard OpenID Connect, Authorization Code flow, RS256-signed ID tokens. Only the
sign-in screen differs — the user picks a test identity instead of entering a password.
The full HTTP interface is described in [`docs/openapi.yaml`](docs/openapi.yaml).

### 1. Register the application

In the admin interface (`<ISSUER>/admin`):

Everything happens on that one page: each application is a card that unfolds to show its
credentials, redirect URIs, test users and a danger zone.

1. **Register application** (below the list) and give it a name. Names are unique, and the
   dialog says so while you type. The new application appears unfolded, ready to set up.
2. The **client secret** appears in a dialog, once. Click it to copy it, then close the
   dialog — Clerk keeps only a hash and cannot show it again. If it is lost, **Regenerate
   client secret** issues a new one, invalidating the old one, and shows it the same way.
   The **client ID** is not secret and stays under Credentials.
3. **Add a redirect URI**. Each must be an absolute `http` or `https` URL with a host and
   no `#fragment`, and is matched **exactly** at sign-in — a different port, path or
   trailing slash is refused.
4. **Add test users**. These are the identities offered on the sign-in screen. An
   application with no users cannot sign anyone in.

**Rename**, at the top of an unfolded application, changes only its label: the client ID,
secret, redirect URIs and users stay as they are.

### 2. Configure the client

Most OIDC libraries need only these settings:

| Setting | Value |
|---|---|
| Issuer / authority | `<ISSUER>`, e.g. `http://localhost:8080` |
| Discovery URL | `<ISSUER>/.well-known/openid-configuration` |
| Client ID / secret | From registration |
| Client authentication | `client_secret_basic` (HTTP Basic) or `client_secret_post` (form fields) |
| Response type / flow | `code` (Authorization Code) |
| Scopes | `openid profile` |
| PKCE | Optional; `S256` only. Recommended. |
| Redirect URI | One of the registered URIs, exactly |

The endpoints, all relative to the issuer, are advertised by discovery:

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/openid-configuration` | Provider metadata |
| `GET /jwks` | Public key for verifying ID tokens |
| `GET /authorize` | Where the browser is sent to sign in |
| `POST /token` | Exchanges the code for tokens (server-to-server) |
| `GET` / `POST /userinfo` | Claims for an access token |

### 3. The flow

1. **Send the browser to `/authorize`** (one URL, wrapped here for readability):

   ```text
   http://localhost:8080/authorize?response_type=code
     &client_id=<client-id>
     &redirect_uri=https://app.example.com/callback
     &scope=openid%20profile
     &state=<random>
     &nonce=<random>
     &code_challenge=<base64url(sha256(verifier))>
     &code_challenge_method=S256
   ```

   `scope` must include `openid`; other scopes such as `email` are ignored rather than
   rejected. If `client_id` or `redirect_uri` is wrong, Clerk shows an error page and
   does **not** redirect; the same goes for an application with no test users, which
   gets a page saying so. Other problems with the request are sent back to the redirect
   URI as `?error=...&error_description=...&state=...`.

2. **The user picks a test identity and presses Login.** Clerk redirects to:

   ```text
   https://app.example.com/callback?code=<code>&state=<state>
   ```

   Check that `state` matches what you sent. The code is single-use and expires after
   one minute by default.

3. **Exchange the code** from your server:

   ```bash
   curl -u '<client-id>:<client-secret>' http://localhost:8080/token \
     -d grant_type=authorization_code \
     -d code='<code>' \
     -d redirect_uri='https://app.example.com/callback' \
     -d code_verifier='<verifier>'
   ```

   `redirect_uri` must be the same one used in step 1, and `code_verifier` is required
   exactly when a `code_challenge` was sent. The response:

   ```json
   {
     "access_token": "...",
     "token_type": "Bearer",
     "expires_in": 3600,
     "id_token": "eyJ...",
     "scope": "openid profile"
   }
   ```

4. **Verify the ID token** before trusting it: check the RS256 signature with the key
   from `/jwks` whose `kid` matches the token header, then check that `iss` equals the
   issuer, `aud` equals your client ID, `exp` is in the future, and `nonce` equals the
   one you sent.

5. **Optionally call `/userinfo`:**

   ```bash
   curl -H 'Authorization: Bearer <access-token>' http://localhost:8080/userinfo
   ```

   ```json
   { "sub": "…", "name": "david" }
   ```

### Claims and tokens

| Claim | In ID token | In `/userinfo` | Value |
|---|---|---|---|
| `iss` | always | — | The issuer |
| `sub` | always | always | The test user's subject |
| `aud` | always | — | Your client ID |
| `iat`, `exp` | always | — | Issued-at and expiry, in seconds since the epoch |
| `nonce` | if sent to `/authorize` | — | The nonce you sent |
| `name` | with `profile` | with `profile` | The test user's username |

- **`sub`** is random, stable for the user's lifetime, and never derived from the
  username. The same username in two applications is two different users with two
  different subjects, so key accounts on `sub`, not `name`.
- **The access token** is an opaque string, not a JWT. Its only use is `/userinfo`.
- **Lifetimes** default to one minute for codes and one hour for access and ID tokens;
  see `CODE_TTL`, `ACCESS_TOKEN_TTL` and `ID_TOKEN_TTL` under [Configuration](#configuration).
- **No refresh tokens.** When the tokens expire, send the user through `/authorize`
  again; they only have to pick an identity.

### Errors worth knowing

| Symptom | Cause |
|---|---|
| "Invalid redirect URI" page, no redirect | The `redirect_uri` is not registered exactly as sent |
| "No test users" page | The application has no users yet |
| `invalid_grant` from `/token` | The code expired, was already used, was issued to another client, or `redirect_uri`/`code_verifier` does not match |
| `invalid_client` (401) from `/token` | Wrong client ID or secret |
| `invalid_token` (401) from `/userinfo` | The access token is unknown or expired |

A code presented a second time is treated as intercepted: the exchange is refused and
the access token issued from its first use is revoked. The ID token from that first use
cannot be revoked and stays valid until it expires.

### Not supported

Implicit and hybrid flows, refresh tokens, the `email` scope and claims, logout and
token revocation endpoints, and dynamic client registration. Clients must be registered
through the admin interface.

## Status

The OpenID Connect provider is complete: discovery, JWKS, the Authorization Code flow
with PKCE, RS256 ID tokens, and UserInfo. Administration is authenticated with external
OAuth and authorized by Bouncer.

Not implemented, deliberately: refresh tokens, an admin REST API, and anything else in
the out-of-scope list this project was specified with.
