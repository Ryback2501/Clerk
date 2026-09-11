-- Applications are the OIDC clients registered with this provider.
CREATE TABLE applications (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    name               TEXT    NOT NULL,
    client_id          TEXT    NOT NULL UNIQUE,
    -- Only a hash is ever stored; the secret itself is shown once at creation.
    client_secret_hash TEXT    NOT NULL,
    created_at         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Redirect URIs are matched exactly during authorization, never by prefix.
CREATE TABLE redirect_uris (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    uri            TEXT    NOT NULL,
    UNIQUE (application_id, uri)
);

CREATE INDEX idx_redirect_uris_application ON redirect_uris(application_id);

-- Test users belong to exactly one application. Deleting the application
-- deletes them (enforced by the cascade above, not only in the UI).
CREATE TABLE users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    -- The user-visible name, unique only within its application.
    username       TEXT    NOT NULL,
    -- The OIDC subject identifier: opaque, globally unique, stable for life,
    -- and deliberately unrelated to both the username and the primary key.
    sub            TEXT    NOT NULL UNIQUE,
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (application_id, username)
);

CREATE INDEX idx_users_application ON users(application_id);
