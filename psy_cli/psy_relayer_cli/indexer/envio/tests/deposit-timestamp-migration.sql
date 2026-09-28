-- Run ONLY against a disposable PostgreSQL database, never the live database.
\set ON_ERROR_STOP on
CREATE SCHEMA timestamp_migration_test;
SET search_path TO timestamp_migration_test;
CREATE TABLE "Deposit" (id TEXT PRIMARY KEY, block_number INTEGER NOT NULL);
CREATE TABLE "envio_history_Deposit" (id TEXT, block_number INTEGER, checkpoint_id INTEGER);
CREATE TABLE chain_metadata (id INTEGER, progress_block INTEGER);
INSERT INTO "Deposit" VALUES ('97-7', 42);
INSERT INTO "envio_history_Deposit" VALUES ('97-7', 42, 1);
INSERT INTO chain_metadata VALUES (97, 42);
\set envio_schema timestamp_migration_test
\ir ../migrations/001-deposit-block-timestamp.sql
-- Idempotence: safe to rerun following an interrupted rollout.
\ir ../migrations/001-deposit-block-timestamp.sql
DO $$
BEGIN
  IF (SELECT count(*) FROM "Deposit") <> 1
     OR NOT EXISTS (SELECT 1 FROM "Deposit" WHERE id = '97-7' AND block_number = 42 AND block_timestamp IS NULL)
     OR NOT EXISTS (SELECT 1 FROM "envio_history_Deposit" WHERE id = '97-7' AND checkpoint_id = 1 AND block_timestamp IS NULL)
     OR NOT EXISTS (SELECT 1 FROM chain_metadata WHERE id = 97 AND progress_block = 42)
  THEN RAISE EXCEPTION 'migration changed existing state'; END IF;
END $$;
INSERT INTO "Deposit" VALUES ('84532-8', 43, 1716601728);
INSERT INTO "envio_history_Deposit" VALUES ('84532-8', 43, 2, 1716601728);
-- Restore the pre-upgrade row using the new column list, as rollback would.
UPDATE "Deposit" d SET block_timestamp = h.block_timestamp
FROM "envio_history_Deposit" h WHERE d.id = h.id AND h.checkpoint_id = 1;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM "Deposit" WHERE id = '84532-8' AND block_timestamp = 1716601728)
     OR NOT EXISTS (SELECT 1 FROM "Deposit" WHERE id = '97-7' AND block_timestamp IS NULL)
  THEN RAISE EXCEPTION 'timestamp insert/legacy rollback failed'; END IF;
END $$;

-- History-disabled installations also upgrade without creating history.
CREATE SCHEMA timestamp_no_history_test;
SET search_path TO timestamp_no_history_test;
CREATE TABLE "Deposit" (id TEXT PRIMARY KEY);
\set envio_schema timestamp_no_history_test
\ir ../migrations/001-deposit-block-timestamp.sql
DO $$
BEGIN
  IF to_regclass('"envio_history_Deposit"') IS NOT NULL THEN
    RAISE EXCEPTION 'migration unexpectedly created history';
  END IF;
END $$;
