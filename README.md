# Clerk

Clerk is a small sign-in service (an OpenID Connect **identity provider**) for
development and testing.

Your application connects to Clerk in the same way it connects to Google or Microsoft.
The difference is the sign-in page: there are no passwords. The user picks a test user
from a list and presses **Login**. With Clerk, you can test your application's sign-in
without creating real accounts.

**Clerk is not for real users.** Anyone who can open the sign-in page can sign in as any
test user.

How it works:

- **The sign-in protocol is real.** Clerk uses the standard Authorization Code flow,
  signed ID tokens (RS256), discovery and JWKS. Your application's normal OpenID Connect
  library works with it.
- **The users are fake.** You create test users in Clerk's admin page. They have no
  passwords.
- **The admin page is protected.** Administrators sign in with Google, GitHub,
  Microsoft or LinkedIn. Then [Bouncer](https://github.com/Ryback2501/Bouncer) checks
  that they have the right role.

## Run Clerk

To try Clerk quickly, without accounts or keys, see
[Try Clerk without credentials](#try-clerk-without-credentials).

To run Clerk for real, follow these steps in order:

1. [Set up an admin sign-in provider](#set-up-an-admin-sign-in-provider) (Google,
   GitHub, Microsoft or LinkedIn).
2. [Set up Clerk in Bouncer](#set-up-clerk-in-bouncer).
3. Write the settings in a `.env` file. See [Configuration](#configuration).
4. Start Clerk with [Docker](#docker) or [from source](#from-source).
5. Open `<ISSUER>/admin` (for example <http://localhost:8080/admin>) and sign in.
6. Register your application and connect it to Clerk. See
   [Use Clerk as an identity provider](#use-clerk-as-an-identity-provider).

Clerk checks every setting when it starts. If something is wrong or missing, it stops
and lists all the problems together. It also contacts each admin sign-in provider when
it starts. If it cannot reach one, it stops.

### Try Clerk without credentials

The script `e2e/stack.sh` starts Clerk together with a fake sign-in provider and a fake
Bouncer. The fake Bouncer makes you an administrator. You do not need any accounts or
keys.

You need Docker and `curl`. Ports 8080, 8081 and 8082 must be free.

1. From the project folder, start everything:

   ```bash
   e2e/stack.sh up
   ```

2. Wait until the script says `clerk is ready`.
3. Open <http://localhost:8080/admin>.
4. Click **Continue with Google**. You are signed in immediately.
5. When you finish, stop and remove everything, including the data:

   ```bash
   e2e/stack.sh down
   ```

To see the logs, run `e2e/stack.sh logs`.

The containers use host networking. This works as it is on Linux. With Docker Desktop
on macOS or Windows, turn on host networking in the Docker Desktop settings first.

### Set up an admin sign-in provider

Administrators sign in to Clerk with an external account. You need at least one
provider.

1. At the provider (Google, GitHub, Microsoft or LinkedIn), create an OAuth application
   for Clerk.
2. Add this **redirect URL** (also called *callback URL*) to that application. It must
   match exactly:

   ```text
   <ISSUER>/admin/auth/<provider>/callback
   ```

   For example: `https://clerk.example.com/admin/auth/google/callback`.
   `<provider>` is `google`, `github`, `microsoft` or `linkedin`.
3. Copy the **client ID** and the **client secret** into your settings (table below).
4. When Clerk starts, it writes each callback URL to its log. You can copy it from
   there.

You can enable more than one provider. Each provider you enable needs both its ID and
its secret.

| Setting | Required | What it is |
|---|---|---|
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | At least one provider | Google OAuth application |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | At least one provider | GitHub OAuth application |
| `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET` | At least one provider | Microsoft (Entra ID) application |
| `LINKEDIN_CLIENT_ID`, `LINKEDIN_CLIENT_SECRET` | At least one provider | LinkedIn application |
| `GOOGLE_ISSUER`, `MICROSOFT_ISSUER`, `LINKEDIN_ISSUER` | No | Replaces the provider's default issuer address. You only need it for a **single-tenant** Microsoft application: `MICROSOFT_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0`. GitHub has no issuer. |

### Set up Clerk in Bouncer

After an administrator signs in, Clerk asks Bouncer if that person has the required
role. Bouncer does not send the browser back to Clerk, so **Clerk does not need a
redirect URI in Bouncer**.

1. In Bouncer, create an application for Clerk.
2. In that application, create a role with the customId `admin`.
3. Create an API key for the application. It starts with `bncr_`.
4. Give yourself the `admin` role. Use the **same provider** (for example, Google)
   that you will use to sign in to Clerk.
5. Put Bouncer's address and the API key in your settings (table below).

| Setting | Required | Default | What it is |
|---|---|---|---|
| `BOUNCER_URL` | Yes | — | The address where Clerk can reach Bouncer, for example `http://bouncer:3000` |
| `BOUNCER_API_KEY` | Yes | — | The `bncr_…` API key from step 3 |
| `BOUNCER_REQUIRED_ROLE` | No | `admin` | The customId of the role an administrator must have. It is case-sensitive. If you leave it empty, Clerk uses `admin`. |

Good to know:

- **If Bouncer is down, only the admin page stops working.** It shows an error (503)
  that explains the cause. Sign-in for your applications keeps working.
- **Bouncer and Clerk must use the same user ID.** Clerk sends the ID that Bouncer saved
  for you. It is not the same field for every provider. For example, Microsoft uses
  `oid`. Clerk handles this for you. It only matters if Bouncer answers
  `user_not_found`.

### Configuration

Clerk reads all its settings from **environment variables**. There are no
configuration files inside Clerk. You can give Clerk the settings in several ways.

**A `.env` file (recommended).** Copy the example file and fill in the values:

```bash
cp .env.example .env
```

In this file, write one `KEY=value` per line, with no quotes and no spaces around `=`.
Lines that start with `#` are comments. Never commit your `.env` file: it contains
secrets. Git already ignores it.

**Docker, using the `.env` file:**

```bash
docker run --env-file .env ... ryback2501/clerk:latest
```

**Docker, with each setting in the command:**

```bash
docker run -e ISSUER=http://localhost:8080 -e BOUNCER_URL=... ... ryback2501/clerk:latest
```

You can use both. A `-e` value replaces the same key from `--env-file`.

**Docker Compose:**

```yaml
services:
  clerk:
    image: ryback2501/clerk:latest
    env_file: .env            # all settings from the file
    environment:              # or here, one by one (this wins over env_file)
      ISSUER: http://localhost:8080
    ports:
      - "8080:8080"
    volumes:
      - clerk-data:/data
      - clerk-keys:/keys

volumes:
  clerk-data:
  clerk-keys:
```

**From source (without Docker):** load the file into your shell before you start
Clerk:

```bash
set -a; source .env; set +a
```

All settings:

| Setting | Required | Default | What it is |
|---|---|---|---|
| `ISSUER` | Yes | — | The public address of Clerk, for example `https://clerk.example.com`. Applications must use exactly this value. It must start with `http://` or `https://`, and it cannot have `?query` or `#fragment`. A slash at the end is removed. |
| `BOUNCER_URL` | Yes | — | See [Set up Clerk in Bouncer](#set-up-clerk-in-bouncer) |
| `BOUNCER_API_KEY` | Yes | — | See [Set up Clerk in Bouncer](#set-up-clerk-in-bouncer) |
| `BOUNCER_REQUIRED_ROLE` | No | `admin` | See [Set up Clerk in Bouncer](#set-up-clerk-in-bouncer) |
| `<PROVIDER>_CLIENT_ID`, `<PROVIDER>_CLIENT_SECRET` | At least one provider | — | See [Set up an admin sign-in provider](#set-up-an-admin-sign-in-provider) |
| `<PROVIDER>_ISSUER` | No | The provider's own | See [Set up an admin sign-in provider](#set-up-an-admin-sign-in-provider) |
| `LISTEN_ADDR` | No | `:8080` | The address and port Clerk listens on |
| `DB_PATH` | No | `/data/clerk.db` | Where Clerk saves its database (SQLite) |
| `KEYS_PATH` | No | `/keys/signing.pem` | Where Clerk saves its signing key. Clerk creates the key the first time it starts and never replaces it. |
| `CODE_TTL` | No | `1m` | How long a sign-in code is valid |
| `ACCESS_TOKEN_TTL` | No | `1h` | How long an access token is valid |
| `ID_TOKEN_TTL` | No | `1h` | How long an ID token is valid |

Write durations with a number and a unit, for example `30s`, `5m` or `1h`. The minimum is
`1s`.

### Docker

The image is `ryback2501/clerk` on Docker Hub. It has a version tag (for example
`:0.1.0`) and `:latest`.

1. Create your `.env` file (see [Configuration](#configuration)).
2. Start Clerk:

   ```bash
   docker run -d --name clerk \
     --env-file .env \
     --add-host=host.docker.internal:host-gateway \
     -v clerk-data:/data \
     -v clerk-keys:/keys \
     -p 8080:8080 \
     ryback2501/clerk:latest
   ```

3. Wait until `docker ps` shows the container as `healthy`. The image checks its own
   `/health` address.
4. Open <http://localhost:8080/admin>.

**Reaching Bouncer from the container.** Inside a container, `localhost` means the
container itself, not your computer.

- If Bouncer runs on your computer, use `BOUNCER_URL=http://host.docker.internal:3000`.
  The `--add-host` option makes this name work on Linux.
- If Bouncer runs in another container, put both containers on the same Docker network
  and use the container name, for example `http://bouncer:3000`.

**HTTPS.** Clerk does not handle HTTPS itself. In production, put a reverse proxy (for
example nginx, Caddy or Traefik) in front of it. The proxy must forward the full path.
Set `ISSUER` to the public `https://` address.

#### Volumes

Clerk saves two things. Both must survive a restart, so both folders need a volume:

| Folder | What it contains | If you lose it |
|---|---|---|
| `/data` | The database: applications, redirect URIs and test users | You must register everything again |
| `/keys` | The signing key | Every token Clerk has issued stops being valid |

The container runs as user ID `65532`. Named volumes (like `clerk-data` above) work
without changes. If you use a folder from your computer instead (a bind mount), user
`65532` must be able to write to it.

### From source

You need Go 1.27.

1. Create your `.env` file (see [Configuration](#configuration)).
2. Load it and start Clerk:

   ```bash
   set -a; source .env; set +a
   export BOUNCER_URL=http://localhost:3000
   export DB_PATH=./data/clerk.db KEYS_PATH=./keys/signing.pem
   mkdir -p data keys
   go run ./cmd/clerk
   ```

3. Open <http://localhost:8080/admin>.

Why the extra lines: without Docker, Bouncer is at `localhost`, not at
`host.docker.internal`. The default database and key paths are for the container, so
you point them to local folders.

## Use Clerk as an identity provider

Your application connects to Clerk with standard OpenID Connect (Authorization Code flow,
RS256-signed ID tokens), in the same way it connects to Google or Microsoft. Only the
sign-in page is different. The complete HTTP description is in
[`docs/openapi.yaml`](docs/openapi.yaml).

### 1. Register the application

Everything happens on one page: `<ISSUER>/admin`. Each application is a card. Click it
to open it and see its credentials, redirect URIs, test users and the danger zone.

1. Click **Register application** (below the list) and write a name. Names must be
   unique. The dialog tells you while you type if the name is already used.
2. Clerk shows the **client secret** in a dialog, **only once**. Click it to copy it,
   then close the dialog. Clerk keeps only a hash, so it cannot show the secret again.
   If you lose it, click **Regenerate client secret**. This creates a new secret and the
   old one stops working. The **client ID** is not secret. You can always see it under
   Credentials.
3. **Add a redirect URI.** This is the address in your application where Clerk sends the
   user after sign-in. It must start with `http://` or `https://`, have a host, and have
   no `#fragment`. Clerk compares it **exactly**: a different port, path or slash at the
   end is refused.
4. **Add test users.** These are the names shown on the sign-in page. An application
   without users cannot sign anyone in.

Later changes:

- **Rename** (at the top of an open application) changes only the name. The client ID,
  secret, redirect URIs and users stay the same.
- To edit or remove a redirect URI or a test user, point at its row. The buttons appear
  there. Clerk asks before it removes anything.
- **Renaming a test user keeps its `sub`** (its user ID), so your application still
  recognizes the user. If you delete a user and create it again with the same name, it
  gets a new `sub`, and your application sees a new user.
- **Delete application** (in the danger zone) removes the application and all its test
  users.

### 2. Configure the client

Most OpenID Connect libraries only need these settings:

| Setting | Value |
|---|---|
| Issuer / authority | `<ISSUER>`, for example `http://localhost:8080` |
| Discovery URL | `<ISSUER>/.well-known/openid-configuration` |
| Client ID and secret | From step 1 |
| Client authentication | `client_secret_basic` (HTTP Basic) or `client_secret_post` (form fields) |
| Response type / flow | `code` (Authorization Code) |
| Scopes | `openid profile` |
| PKCE | Optional, `S256` only. Recommended. |
| Redirect URI | One of the registered redirect URIs, exactly |

The library finds the endpoints through discovery. All of them are relative to the issuer:

| Endpoint | What it does |
|---|---|
| `GET /.well-known/openid-configuration` | Describes the provider (discovery) |
| `GET /jwks` | The public key to check ID token signatures |
| `GET /authorize` | The sign-in page. The browser goes here. |
| `POST /token` | Changes the code into tokens. Your server calls it. |
| `GET` or `POST /userinfo` | Returns the user's claims for an access token |
| `GET /health` | Returns `{"status":"ok"}` when Clerk is running |

### 3. The sign-in flow

Your OpenID Connect library usually does all these steps for you. They are here so you
can understand and debug the flow.

1. **Send the browser to `/authorize`.** This is one URL. It is split into lines here so
   it is easier to read:

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

   If `client_id` or `redirect_uri` is wrong, Clerk shows an error page and does **not**
   redirect. It also shows a page if the application has no test users. For other
   problems, Clerk redirects to the redirect URI with
   `?error=...&error_description=...&state=...`.

2. **The user picks a test user and presses Login.** Clerk redirects to:

   ```text
   https://app.example.com/callback?code=<code>&state=<state>
   ```

   Check that `state` is the same value you sent. You can use the code only once. It
   expires after one minute by default (`CODE_TTL`).

3. **Change the code into tokens.** Do this from your server:

   ```bash
   curl -u '<client-id>:<client-secret>' http://localhost:8080/token \
     -d grant_type=authorization_code \
     -d code='<code>' \
     -d redirect_uri='https://app.example.com/callback' \
     -d code_verifier='<verifier>'
   ```

   `redirect_uri` must be the same as in step 1. Send `code_verifier` only if you sent a
   `code_challenge` in step 1 (then it is required). The answer:

   ```json
   {
     "access_token": "...",
     "token_type": "Bearer",
     "expires_in": 3600,
     "id_token": "eyJ...",
     "scope": "openid profile"
   }
   ```

4. **Check the ID token before you trust it.**
   - The signature is valid (RS256), using the key from `/jwks` with the same `kid` as
     the token header.
   - `iss` is the issuer.
   - `aud` is your client ID.
   - `exp` is in the future.
   - `nonce` is the value you sent.

5. **Optional: call `/userinfo`.**

   ```bash
   curl -H 'Authorization: Bearer <access-token>' http://localhost:8080/userinfo
   ```

   ```json
   { "sub": "…", "name": "david" }
   ```

### Claims and tokens

| Claim | In the ID token | In `/userinfo` | Value |
|---|---|---|---|
| `iss` | Always | — | The issuer |
| `sub` | Always | Always | The test user's ID |
| `aud` | Always | — | Your client ID |
| `iat`, `exp` | Always | — | When the token was created and when it expires (seconds since 1970) |
| `nonce` | If you sent one to `/authorize` | — | The nonce you sent |
| `name` | With the `profile` scope | With the `profile` scope | The test user's name |

- **`sub`** is random. It never changes for the life of the user, and it does not come
  from the name. The same name in two applications is two different users with two
  different `sub` values. Identify users by `sub`, not by `name`.
- **The access token** is a random string, not a JWT. You can only use it with
  `/userinfo`.
- **Lifetimes:** codes are valid for one minute, access and ID tokens for one hour. You
  can change this with `CODE_TTL`, `ACCESS_TOKEN_TTL` and `ID_TOKEN_TTL` (see
  [Configuration](#configuration)).
- **There are no refresh tokens.** When the tokens expire, send the user to `/authorize`
  again. The user only has to pick a name.

### Common errors

| What you see | Why |
|---|---|
| "Invalid redirect URI" page, no redirect | The `redirect_uri` is not registered exactly as you sent it |
| "No test users" page | The application has no test users yet |
| `invalid_grant` from `/token` | The code expired, was already used, or belongs to another client. Or `redirect_uri` or `code_verifier` does not match. |
| `invalid_client` (401) from `/token` | Wrong client ID or client secret |
| `invalid_token` (401) from `/userinfo` | The access token is unknown or expired |

If someone uses the same code twice, Clerk assumes it was stolen. It refuses the second
exchange and cancels the access token from the first one. The ID token from the first
exchange cannot be cancelled. It stays valid until it expires.

### Not supported

- Implicit and hybrid flows
- Refresh tokens
- The `email` scope and email claims
- Logout and token revocation endpoints
- Dynamic client registration. You register applications only in the admin page.

## Status

Clerk is complete for its purpose:

- **Sign-in service:** discovery, JWKS, the Authorization Code flow with PKCE, RS256 ID
  tokens and UserInfo.
- **Admin page:** register, rename and delete applications; create and regenerate client
  secrets; add, edit and remove redirect URIs and test users.
- **Admin access:** sign-in with Google, GitHub, Microsoft or LinkedIn, and a role check
  in Bouncer.

These are not implemented, on purpose: refresh tokens, logout, token revocation, the
`email` scope, dynamic client registration and an admin REST API. There is also no rate
limiting, so do not expose Clerk to the public internet without protection in front of
it.
