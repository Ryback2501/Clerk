# Clerk

Clerk is a small sign-in service (an OpenID Connect **identity provider**) for
development and testing.

Your application connects to Clerk in the same way it connects to Google or Microsoft.
The difference is the sign-in page: there are no passwords. The user picks a test user
from a list and presses **Login**. With Clerk, you can test your application's sign-in
without creating real accounts.

**Clerk is not for real users.** Anyone who can open the sign-in page can sign in as any
test user.

**Clerk uses Bouncer.** Clerk's admin page must be protected, but Clerk does not
keep passwords or accounts for its administrators. Administrators sign in with an
account they already have (Google, Microsoft, GitHub or LinkedIn). Then Clerk asks
[Bouncer](https://github.com/Ryback2501/Bouncer), a separate access-control service,
whether that account has the admin role. This way, Clerk never stores or checks
administrator credentials. You add, change and remove administrators in one place:
Bouncer.

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

1. [Set up an admin sign-in provider](#1-set-up-an-admin-sign-in-provider) (Google,
   GitHub, Microsoft or LinkedIn).
2. [Set up Clerk in Bouncer](#2-set-up-clerk-in-bouncer).
3. Write the settings in a `.env` file. See [Configuration](#3-configuration).
4. [Start Clerk](#4-start-clerk) with Docker or from source.
5. [Sign in to the admin page](#5-sign-in-to-the-admin-page).
6. Register your application and connect it to Clerk. See
   [Use Clerk as an identity provider](#6-use-clerk-as-an-identity-provider).

Clerk checks every setting when it starts. If something is wrong or missing, it stops
and lists all the problems together. It also contacts each admin sign-in provider when
it starts. If it cannot reach one, it stops.

## Try Clerk without credentials

The script `e2e/stack.sh` starts Clerk together with a fake sign-in provider and a fake
Bouncer. The fake Bouncer makes you an administrator. You do not need any accounts or
keys.

The script is part of Clerk's source code. It is not in the Docker image. It builds Clerk
from the source code, so you need a copy of the project first.

You need Git (or a downloaded copy of the project), Docker and `curl`. Ports 8080, 8081
and 8082 must be free.

**Note:** the containers use host networking. This works as it is on Linux. With Docker
Desktop on macOS or Windows, turn on host networking in the Docker Desktop settings
**before** you start. Without it, the steps below fail.

1. Get the source code. Clone the project:

   ```bash
   git clone https://github.com/Ryback2501/Clerk.git
   cd Clerk
   ```

   Or download it as a ZIP file from GitHub (**Code → Download ZIP**), unzip it, and open
   a terminal in that folder.

2. Start everything:

   ```bash
   e2e/stack.sh up
   ```

3. Wait until the script says `clerk is ready`.
4. Open <http://localhost:8080/admin>.
5. Click **Continue with Google**. You are signed in immediately.
6. When you finish, stop and remove everything, including the data:

   ```bash
   e2e/stack.sh down
   ```

To see the logs, run `e2e/stack.sh logs`.

## 1. Set up an admin sign-in provider

Administrators sign in to Clerk with an external account: Google, Microsoft, GitHub or
LinkedIn. You need **at least one** provider. Choose the ones you want and skip the
others.

For each provider, you create an OAuth application at the provider. This gives you a
**client ID** and a **client secret**. You put both in your `.env` file (see
[Configuration](#3-configuration)).

Each provider also needs Clerk's **callback URL** (also called *redirect URL*). This is
the address the provider sends you back to after you sign in. It must match exactly:

```text
<ISSUER>/admin/auth/<provider>/callback
```

`<provider>` is `google`, `microsoft`, `github` or `linkedin`. The examples below use
`http://localhost:8080` as the `ISSUER`. For a real server, use its address instead.
When Clerk starts, it writes each callback URL to its log. You can copy it from there.

**Tip:** if you already set up Google, Microsoft or LinkedIn for Bouncer, you can use the
same OAuth application for Clerk. Add Clerk's callback URL to it and use the same client
ID and secret. GitHub is different: a GitHub OAuth app has only one callback URL, so
create a separate one for Clerk.

### Google

1. Open the [Google Cloud Console → APIs & Services → Credentials](https://console.cloud.google.com/apis/credentials).
   Choose a project or create one.
2. If Google asks, set up the **OAuth consent screen** first. Choose **External**, and
   write an app name, a support email and a contact email. The scopes Clerk needs
   (`openid`, `email`, `profile`) are added automatically.
3. Click **Create credentials → OAuth client ID**. Application type: **Web application**.
4. Under **Authorized redirect URIs**, add
   `http://localhost:8080/admin/auth/google/callback`.
5. Save. Copy the **Client ID** and the **Client secret**.

```dotenv
GOOGLE_CLIENT_ID=<client-id>
GOOGLE_CLIENT_SECRET=<client-secret>
```

### Microsoft

1. Sign in to the [Azure Portal](https://portal.azure.com/). Go to
   **Microsoft Entra ID → App registrations → New registration**.
2. Write a name. Under **Supported account types**, choose
   **Accounts in any organizational directory and personal Microsoft accounts**. This is
   what Clerk expects by default. For a single-tenant application, see step 6 below.
3. Under **Redirect URI**, choose the platform **Web** and write
   `http://localhost:8080/admin/auth/microsoft/callback`. Click **Register**.
4. On the application's **Overview** page, copy the **Application (client) ID**.
5. Go to **Certificates & secrets → Client secrets → New client secret**. Copy the
   secret **Value** right away. Microsoft shows it only once.
6. Only for a **single-tenant** application (only accounts from your organization): copy
   the **Directory (tenant) ID** from the **Overview** page and set `MICROSOFT_ISSUER`
   (see below). Without it, sign-in fails.

The default API permissions are enough.

```dotenv
MICROSOFT_CLIENT_ID=<application-client-id>
MICROSOFT_CLIENT_SECRET=<secret-value>
# Only for a single-tenant application:
MICROSOFT_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
```

### GitHub

1. Open [Settings → Developer settings → OAuth Apps → New OAuth App](https://github.com/settings/developers).
2. Fill in the form:
   - **Application name:** `Clerk` (or any name).
   - **Homepage URL:** `http://localhost:8080`.
   - **Authorization callback URL:** `http://localhost:8080/admin/auth/github/callback`.
3. Click **Register application**.
4. Copy the **Client ID**. Click **Generate a new client secret** and copy it right away.
   GitHub shows it only once.

Clerk only asks GitHub for your public profile (`read:user`). You do not need to set up
anything else.

```dotenv
GITHUB_CLIENT_ID=<client-id>
GITHUB_CLIENT_SECRET=<client-secret>
```

### LinkedIn

1. Open the [LinkedIn Developer portal → My apps → Create app](https://www.linkedin.com/developers/apps).
   The app must belong to a LinkedIn Page. A personal page is fine for testing.
2. Write the app name, choose the page and upload a logo. Submit.
3. In the **Auth** tab, under **OAuth 2.0 settings → Authorized redirect URLs for your
   app**, add `http://localhost:8080/admin/auth/linkedin/callback`.
4. In the **Products** tab, request **Sign In with LinkedIn using OpenID Connect**.
   LinkedIn approves it automatically.
5. Back in the **Auth** tab, copy the **Client ID** and the **Client Secret**.

```dotenv
LINKEDIN_CLIENT_ID=<client-id>
LINKEDIN_CLIENT_SECRET=<client-secret>
```

### Provider settings

Each provider you use needs both its ID and its secret. If you set only one of them,
Clerk does not start.

| Setting | Required | What it is |
|---|---|---|
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | At least one provider | Google OAuth application |
| `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET` | At least one provider | Microsoft (Entra ID) application |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | At least one provider | GitHub OAuth app |
| `LINKEDIN_CLIENT_ID`, `LINKEDIN_CLIENT_SECRET` | At least one provider | LinkedIn application |
| `GOOGLE_ISSUER`, `MICROSOFT_ISSUER`, `LINKEDIN_ISSUER` | No | Replaces the provider's default issuer address. You only need it for a **single-tenant** Microsoft application. GitHub has no issuer. |

For a real server:

- **Every provider requires HTTPS** for callback URLs that are not `localhost`. Add the
  `https://…` callback URL of your server to each provider.
- **You can keep the `localhost` callback URLs.** With both, the same OAuth application
  works for your server and for testing on your computer.
- **Google:** while the consent screen is in *Testing* mode, only the test users you
  added there can sign in. Publish it to allow other accounts.

## 2. Set up Clerk in Bouncer

After an administrator signs in, Clerk asks Bouncer if that person has the required
role. Bouncer does not send the browser back to Clerk, so **Clerk does not need a
redirect URI in Bouncer**.

You need to be an administrator in Bouncer. The names of buttons and pages below are the
ones in Bouncer's admin page.

**Create the application and the role:**

1. Go to **Applications** and click **New Application**. Name: `Clerk`. ID: `clerk`.
   Leave **Allowed redirect URIs** empty.
2. On the `Clerk` row, click **Roles**, then **New Role**. Name: `Admin`. ID: `admin`.
   The ID must be the same as `BOUNCER_REQUIRED_ROLE` (default `admin`).

**Create the API key:**

3. On the `Clerk` row, click **API Keys**, then **Generate Key**.
4. Copy the key right away. It starts with `bncr_`. Bouncer shows it only once.
5. Write it in your `.env` file as `BOUNCER_API_KEY`. In the same file, write Bouncer's
   address as `BOUNCER_URL` (see [Configuration](#3-configuration)).

**Give yourself the role with an invitation:**

6. Go to **Invitations** and click **Create Invitation**.
   - **Application:** `Clerk`.
   - **Role:** `Admin`.
   - **Invitee email:** optional. If you write an email, only an account with that email
     can accept the invitation.
   - **Redirect URI:** leave it empty.
7. Copy the invitation link.
8. Open the link in a private (incognito) browser window.
9. Choose the provider **you will use to sign in to Clerk**, and sign in with the
   account you will use. Bouncer shows **Access granted**.

**Another way, without an invitation:** if Bouncer already knows the exact account you
will use for Clerk (for example, you sign in to Bouncer with the same Google account), go
to **Users**, open your user, click **Assign Role**, and choose Application `Clerk` and
Role `Admin`.

| Setting | Required | Default | What it is |
|---|---|---|---|
| `BOUNCER_URL` | Yes | — | The address where Clerk can reach Bouncer, for example `http://bouncer:3000` |
| `BOUNCER_API_KEY` | Yes | — | The `bncr_…` API key from step 4 above |
| `BOUNCER_REQUIRED_ROLE` | No | `admin` | The ID of the role an administrator must have. It is case-sensitive. If you leave it empty, Clerk uses `admin`. |

Good to know:

- **Sign in to Clerk with the account that has the role.** Bouncer gives the role to one
  account at one provider, for example your Google account. Sign in to Clerk with that
  same provider and that same account. With a different provider or a different
  account, Clerk shows **Not authorized**. To use another account, give it the role too
  (repeat steps 6–9 above).
- **If Bouncer is down, only the admin page stops working.** It shows
  **Administration unavailable** (error 503). Sign-in for your applications keeps
  working.

## 3. Configuration

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
| `BOUNCER_URL` | Yes | — | See [Set up Clerk in Bouncer](#2-set-up-clerk-in-bouncer) |
| `BOUNCER_API_KEY` | Yes | — | See [Set up Clerk in Bouncer](#2-set-up-clerk-in-bouncer) |
| `BOUNCER_REQUIRED_ROLE` | No | `admin` | See [Set up Clerk in Bouncer](#2-set-up-clerk-in-bouncer) |
| `<PROVIDER>_CLIENT_ID`, `<PROVIDER>_CLIENT_SECRET` | At least one provider | — | See [Set up an admin sign-in provider](#1-set-up-an-admin-sign-in-provider) |
| `<PROVIDER>_ISSUER` | No | The provider's own | See [Set up an admin sign-in provider](#1-set-up-an-admin-sign-in-provider) |
| `LISTEN_ADDR` | No | `:8080` | The address and port Clerk listens on |
| `DB_PATH` | No | `/data/clerk.db` | Where Clerk saves its database (SQLite) |
| `KEYS_PATH` | No | `/keys/signing.pem` | Where Clerk saves its signing key. Clerk creates the key the first time it starts and never replaces it. |
| `CODE_TTL` | No | `1m` | How long a sign-in code is valid |
| `ACCESS_TOKEN_TTL` | No | `1h` | How long an access token is valid |
| `ID_TOKEN_TTL` | No | `1h` | How long an ID token is valid |

Write durations with a number and a unit, for example `30s`, `5m` or `1h`. The minimum is
`1s`.

## 4. Start Clerk

You can start Clerk in two ways:

- [Docker](#docker): the easiest way. You only need Docker.
- [From source](#from-source): you need Go and a copy of the source code.

### Docker

The image is `ryback2501/clerk` on Docker Hub. It has a version tag (for example
`:0.1.0`) and `:latest`.

1. Create your `.env` file (see [Configuration](#3-configuration)).
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
4. Continue with [5. Sign in to the admin page](#5-sign-in-to-the-admin-page).

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

You need Go 1.27 and a copy of the source code (see step 1 of
[Try Clerk without credentials](#try-clerk-without-credentials)).

1. Create your `.env` file (see [Configuration](#3-configuration)).
2. Load it and start Clerk:

   ```bash
   set -a; source .env; set +a
   export BOUNCER_URL=http://localhost:3000
   export DB_PATH=./data/clerk.db KEYS_PATH=./keys/signing.pem
   mkdir -p data keys
   go run ./cmd/clerk
   ```

3. Continue with [5. Sign in to the admin page](#5-sign-in-to-the-admin-page).

Why the extra lines: without Docker, Bouncer is at `localhost`, not at
`host.docker.internal`. The default database and key paths are for the container, so
you point them to local folders.

## 5. Sign in to the admin page

Open `<ISSUER>/admin` in your browser, for example <http://localhost:8080/admin>. Click
the button of your provider (for example **Continue with Google**) and sign in with the
account that has the role in Bouncer. You then see Clerk's admin page, with the list of
your applications. It is empty the first time. If Clerk shows **Not authorized**, your
account does not have the role: see [Set up Clerk in Bouncer](#2-set-up-clerk-in-bouncer).
If it shows **Administration unavailable**, Clerk cannot reach Bouncer, or Bouncer does
not accept the API key: check `BOUNCER_URL` and `BOUNCER_API_KEY`.

## 6. Use Clerk as an identity provider

Your application connects to Clerk with standard OpenID Connect (Authorization Code flow,
RS256-signed ID tokens), in the same way it connects to Google or Microsoft. Only the
sign-in page is different. The complete HTTP description is in
[`docs/openapi.yaml`](docs/openapi.yaml).

### 6.1 Register the application

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

### 6.2 Configure the client

Most OpenID Connect libraries only need these settings:

| Setting | Value |
|---|---|
| Issuer / authority | `<ISSUER>`, for example `http://localhost:8080` |
| Discovery URL | `<ISSUER>/.well-known/openid-configuration` |
| Client ID and secret | From [6.1 Register the application](#61-register-the-application) |
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

### 6.3 The sign-in flow

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

   `redirect_uri` must be the same as in step 1 above. Send `code_verifier` only if you sent a
   `code_challenge` in step 1 above (then it is required). The answer:

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
  [Configuration](#3-configuration)).
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
