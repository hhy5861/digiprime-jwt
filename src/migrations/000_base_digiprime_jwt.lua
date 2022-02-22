return {
  postgres = {
    up = [[
      CREATE TABLE IF NOT EXISTS "digiprime-jwt" (
        "id"              UUID                         PRIMARY KEY,
        "created_at"      TIMESTAMP WITH TIME ZONE     DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'),
        "consumer_id"     UUID                         REFERENCES "consumers" ("id") ON DELETE CASCADE,
        "key"             TEXT                         UNIQUE,
        "secret"          TEXT,
        "algorithm"       TEXT,
        "rsa_public_key"  TEXT,
        "tags"            TEXT
      );

      DO $$
      BEGIN
        CREATE INDEX IF NOT EXISTS "digiprime-jwt_consumer_id_idx" ON "digiprime-jwt" ("consumer_id");
      EXCEPTION WHEN UNDEFINED_COLUMN THEN
        -- Do nothing, accept existing state
      END$$;

      DO $$
      BEGIN
        CREATE INDEX IF NOT EXISTS "digiprime-jwt_secret_idx" ON "digiprime-jwt" ("secret");
      EXCEPTION WHEN UNDEFINED_COLUMN THEN
        -- Do nothing, accept existing state
      END$$;

      DO $$
      BEGIN
        CREATE INDEX IF NOT EXISTS jwtsecrets_tags_idex_tags_idx ON digiprime-jwt USING GIN(tags);
      EXCEPTION WHEN UNDEFINED_COLUMN THEN
        -- Do nothing, accept existing state
      END$$;
    ]],
  },

  cassandra = {
    up = [[
      CREATE TABLE IF NOT EXISTS digiprime-jwt(
        id             uuid PRIMARY KEY,
        created_at     timestamp,
        consumer_id    uuid,
        algorithm      text,
        rsa_public_key text,
        key            text,
        secret         text,
        tags           text
      );
      CREATE INDEX IF NOT EXISTS ON digiprime-jwt(key);
      CREATE INDEX IF NOT EXISTS ON digiprime-jwt(secret);
      CREATE INDEX IF NOT EXISTS ON digiprime-jwt(consumer_id);
    ]],
  },
}
