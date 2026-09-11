# Clerk
An Identity Provider (IdP) for testing and development environments to generate and manage users for testing purposes and an easy and fast login system.

## Running it

```bash
docker run -d --name clerk \
  -e CLERK_ISSUER=http://localhost:8080 \
  -e CLERK_ADMIN_INSECURE=true \
  -v clerk-data:/data \
  -v clerk-keys:/keys \
  -p 8080:8080 \
  ryback2501/clerk:latest
```

Then open <http://localhost:8080/admin> to register an application, and point your
OIDC client at `http://localhost:8080/.well-known/openid-configuration`.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `CLERK_ISSUER` | *(required)* | Public base URL of the provider. Published as `issuer` and as the `iss` claim, so it must match what clients are configured with exactly. |
| `CLERK_LISTEN_ADDR` | `:8080` | Address to listen on. |
| `CLERK_DB_PATH` | `/data/clerk.db` | SQLite database path. |
| `CLERK_KEYS_PATH` | `/keys/signing.pem` | RS256 signing key path. Generated on first run and never regenerated. |
| `CLERK_CODE_TTL` | `1m` | Authorization code lifetime. |
| `CLERK_ACCESS_TOKEN_TTL` | `1h` | Access token lifetime. |
| `CLERK_ID_TOKEN_TTL` | `1h` | ID token lifetime. |
| `CLERK_ADMIN_INSECURE` | `false` | Run with administration **completely unauthenticated**. Only for local work; never expose the port. |

### Administration access

Administrators sign in with an external OAuth provider, and whether they may
administer this provider is then decided by [Bouncer](https://github.com/Ryback2501/Bouncer).
Clerk refuses to start unless either this is configured or `CLERK_ADMIN_INSECURE=true`
is set — otherwise an image would quietly serve an open admin interface.

| Variable | Meaning |
|---|---|
| `CLERK_BOUNCER_URL` | Where Bouncer is reachable, e.g. `http://bouncer:3000`. |
| `CLERK_BOUNCER_API_KEY` | The `bncr_…` key Bouncer issued for Clerk's application. |
| `CLERK_BOUNCER_REQUIRED_ROLE` | Role `customId` an administrator must hold. Default `admin`; empty accepts any active role. |
| `CLERK_GOOGLE_CLIENT_ID` / `_SECRET` | Google OAuth credentials. |
| `CLERK_GITHUB_CLIENT_ID` / `_SECRET` | GitHub OAuth credentials. |
| `CLERK_MICROSOFT_CLIENT_ID` / `_SECRET` | Microsoft OAuth credentials. |
| `CLERK_LINKEDIN_CLIENT_ID` / `_SECRET` | LinkedIn OAuth credentials. |

At least one provider is required. Register this callback with each one, exactly:

```text
<CLERK_ISSUER>/admin/auth/<provider>/callback
```

Clerk logs each callback URL at startup so it can be copied verbatim.

#### Setting up Bouncer

1. In Bouncer, register an application for Clerk and create the `admin` role.
2. Issue an API key for it and set it as `CLERK_BOUNCER_API_KEY`.
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
