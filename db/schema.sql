-- TrustVault schema. Run as the `migrator` role (owner of the tables).
-- Safe to run once on an empty database.

CREATE TABLE users (
  id            SERIAL PRIMARY KEY,
  email         TEXT UNIQUE NOT NULL CHECK (email = lower(email)),
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('admin','owner','viewer')),
  active        BOOLEAN NOT NULL DEFAULT TRUE,
  failed_logins INT NOT NULL DEFAULT 0,
  locked_until  TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Server-side sessions. Only the SHA-256 of the cookie token is stored.
CREATE TABLE sessions (
  id         TEXT PRIMARY KEY,
  user_id    INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf       TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_user_idx ON sessions(user_id);

CREATE TABLE documents (
  id         UUID PRIMARY KEY,
  owner_id   INT NOT NULL REFERENCES users(id),
  name       TEXT NOT NULL,
  category   TEXT NOT NULL DEFAULT '',
  s3_key     TEXT NOT NULL,
  sha256     TEXT NOT NULL,
  size       BIGINT NOT NULL,
  mime       TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);
CREATE INDEX documents_owner_idx ON documents(owner_id);

CREATE TABLE grants (
  id          SERIAL PRIMARY KEY,
  document_id UUID NOT NULL REFERENCES documents(id),
  user_id     INT NOT NULL REFERENCES users(id),
  permission  TEXT NOT NULL CHECK (permission IN ('read','edit')),
  granted_by  INT NOT NULL REFERENCES users(id),
  granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at  TIMESTAMPTZ,
  revoked_by  INT REFERENCES users(id)
);
-- At most one ACTIVE grant per (document, user).
CREATE UNIQUE INDEX one_active_grant ON grants(document_id, user_id) WHERE revoked_at IS NULL;
CREATE INDEX grants_user_idx ON grants(user_id) WHERE revoked_at IS NULL;

-- Append-only, hash-chained audit trail. `ts` is the exact string that was hashed.
CREATE TABLE audit_log (
  id             BIGSERIAL PRIMARY KEY,
  ts             TEXT NOT NULL,
  actor_id       INT,
  actor_email    TEXT,
  action         TEXT NOT NULL,
  document_id    UUID,
  target_user_id INT,
  outcome        TEXT NOT NULL CHECK (outcome IN ('allowed','denied')),
  ip             TEXT,
  detail         TEXT NOT NULL,   -- canonical JSON text (hashed as-is)
  prev_hash      TEXT NOT NULL,
  hash           TEXT NOT NULL
);
CREATE INDEX audit_doc_idx ON audit_log(document_id);
CREATE INDEX audit_actor_idx ON audit_log(actor_id);

CREATE FUNCTION audit_no_mutate() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'audit_log is append-only'; END $$ LANGUAGE plpgsql;
CREATE TRIGGER audit_no_update BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_no_mutate();
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION audit_no_mutate();

-- Records of chain heads written to the Object Lock bucket.
CREATE TABLE anchors (
  id         SERIAL PRIMARY KEY,
  audit_id   BIGINT NOT NULL,
  s3_key     TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER anchors_no_update BEFORE UPDATE OR DELETE ON anchors
  FOR EACH ROW EXECUTE FUNCTION audit_no_mutate();

-- Least privilege for the application login (explicit, not inherited defaults).
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON users, sessions, documents, grants TO app_user;
GRANT SELECT, INSERT ON audit_log, anchors TO app_user;   -- no UPDATE, DELETE, TRUNCATE
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;
