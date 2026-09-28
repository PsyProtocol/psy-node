-- Additive only. Run with psql -X -v ON_ERROR_STOP=1 -v envio_schema=public
-- against a backed-up Envio database, with its writer stopped. No reindex.
-- Confirm the actual schema before choosing envio_schema.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
SET LOCAL search_path TO :"envio_schema";

ALTER TABLE "Deposit" ADD COLUMN IF NOT EXISTS block_timestamp NUMERIC;

-- Envio rollback history must carry the same nullable field. A deployment with
-- history disabled may have no history table; do not create it speculatively.
DO $$
BEGIN
  IF to_regclass('"envio_history_Deposit"') IS NOT NULL THEN
    ALTER TABLE "envio_history_Deposit" ADD COLUMN IF NOT EXISTS block_timestamp NUMERIC;
  END IF;
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name IN ('Deposit', 'envio_history_Deposit')
      AND column_name = 'block_timestamp'
      AND (data_type <> 'numeric' OR is_nullable <> 'YES')
  ) THEN
    RAISE EXCEPTION 'block_timestamp must be nullable NUMERIC; refusing incompatible schema';
  END IF;
END $$;
COMMIT;
