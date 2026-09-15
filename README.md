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

In every case, open <http://localhost:8080/admin> to register an application, and point
your OIDC client at `http://localhost:8080/.well-known/openid-configuration`.

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

## Status

The OpenID Connect provider is complete: discovery, JWKS, the Authorization Code flow
with PKCE, RS256 ID tokens, and UserInfo. Administration is authenticated with external
OAuth and authorized by Bouncer.

Not implemented, deliberately: refresh tokens, an admin REST API, and anything else in
the out-of-scope list this project was specified with.
