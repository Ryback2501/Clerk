-- Issued access tokens.
--
-- Like authorization codes, only a hash is stored: these are bearer
-- credentials, so a database dump must not yield usable ones. They are
-- high-entropy random values rather than JWTs, because the only resource
-- server is this provider's own UserInfo endpoint — a self-contained token
-- format would add signing and parsing for no benefit here.
CREATE TABLE access_tokens (
    token_hash     TEXT    PRIMARY KEY,
    application_id INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope          TEXT    NOT NULL,
    expires_at     INTEGER NOT NULL,
    created_at     INTEGER NOT NULL
);

CREATE INDEX idx_access_tokens_expiry ON access_tokens(expires_at);
