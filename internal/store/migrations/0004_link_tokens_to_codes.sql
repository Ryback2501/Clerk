-- Record which authorization code each access token came from.
--
-- RFC 6749 §4.1.2 says a server that detects a replayed code SHOULD revoke the
-- tokens already issued from it. Without this link there is no way to find
-- them: on a replay the legitimate client is refused, but whoever redeemed the
-- code first keeps a working bearer token for its full lifetime.
ALTER TABLE access_tokens ADD COLUMN auth_code_hash TEXT;

CREATE INDEX idx_access_tokens_auth_code ON access_tokens(auth_code_hash);
