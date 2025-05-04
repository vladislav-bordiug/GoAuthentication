CREATE TABLE IF NOT EXISTS tokens (
    id SERIAL PRIMARY KEY,
    guid INTEGER NOT NULL,
    refresh_hash TEXT,
    status TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tokens_guid ON tokens(guid);

ALTER TABLE tokens
  ADD CONSTRAINT status_check
  CHECK (status IN ('unused', 'used', 'blocked'));