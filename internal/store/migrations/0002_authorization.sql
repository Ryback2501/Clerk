-- A validated authorization request, parked while the user picks an identity.
--
-- The login form carries only this opaque id. Keeping the validated parameters
-- server-side means the client, redirect URI, scope and PKCE challenge cannot
-- be swapped between rendering the page and submitting it.
CREATE TABLE auth_requests (
    id                    TEXT    PRIMARY KEY,
    application_id        INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    redirect_uri          TEXT    NOT NULL,
    -- Opaque to this provider: state is the client's CSRF value and is only
    -- ever echoed back untouched.
    state                 TEXT,
    nonce                 TEXT,
    scope                 TEXT    NOT NULL,
    code_challenge        TEXT,
    code_challenge_method TEXT,
    -- Unix seconds. Integers rather than formatted timestamps so expiry is a
    -- plain numeric comparison with no parsing or timezone ambiguity.
    expires_at            INTEGER NOT NULL,
    created_at            INTEGER NOT NULL
);

CREATE INDEX idx_auth_requests_expiry ON auth_requests(expires_at);

-- An issued authorization code.
--
-- Only a hash of the code is stored, so a database dump cannot be replayed.
-- The row is retained after use: recognising a replayed code is what lets the
-- token endpoint detect it, which a plain delete would make impossible.
CREATE TABLE auth_codes (
    code_hash             TEXT    PRIMARY KEY,
    application_id        INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    user_id               INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Bound to the exact redirect URI the code was issued for; the token
    -- endpoint requires the same value back.
    redirect_uri          TEXT    NOT NULL,
    nonce                 TEXT,
    scope                 TEXT    NOT NULL,
    code_challenge        TEXT,
    code_challenge_method TEXT,
    expires_at            INTEGER NOT NULL,
    created_at            INTEGER NOT NULL,
    consumed_at           INTEGER
);

CREATE INDEX idx_auth_codes_expiry ON auth_codes(expires_at);
