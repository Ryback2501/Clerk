-- Signed-in administrators.
--
-- Sessions are server-side rather than a signed cookie so that signing out,
-- or an administrator losing their role, takes effect immediately instead of
-- when a token happens to expire.
CREATE TABLE admin_sessions (
    id         TEXT    PRIMARY KEY,
    subject    TEXT    NOT NULL,
    provider   TEXT    NOT NULL,
    name       TEXT    NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_admin_sessions_expiry ON admin_sessions(expires_at);

-- An in-flight OAuth sign-in: the state parameter and the PKCE verifier Clerk
-- generated for it, held only until the provider redirects back.
CREATE TABLE admin_logins (
    state         TEXT    PRIMARY KEY,
    provider      TEXT    NOT NULL,
    code_verifier TEXT    NOT NULL,
    nonce         TEXT    NOT NULL,
    return_to     TEXT    NOT NULL,
    expires_at    INTEGER NOT NULL,
    created_at    INTEGER NOT NULL
);

CREATE INDEX idx_admin_logins_expiry ON admin_logins(expires_at);
