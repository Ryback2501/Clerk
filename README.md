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
| `CLERK_ADMIN_INSECURE` | `false` | **Required for now.** Administration has no authentication yet, so Clerk refuses to start without this. Do not expose the port to an untrusted network. |

### Volumes

Both must persist, or every client breaks on restart:

- `/data` — the SQLite database.
- `/keys` — the RS256 signing key. A new key would invalidate every token ever issued.

The container runs as uid 65532 and does not terminate TLS; put a reverse proxy in front
of it and forward the full path.

## Status

Under construction. Registering applications works; test users, the authorization code
flow, and administrator sign-in are still being built.
