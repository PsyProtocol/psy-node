-- Read-only before/after verification for psy-services migration 051.
BEGIN READ ONLY;
WITH authority AS (
  SELECT tx.owner_user_id AS user_id,
    min((SELECT string_agg(substr(encode(tx.content_hash, 'hex'), i * 2 + 1, 2), '' ORDER BY i DESC)
         FROM generate_series(0, 31) AS i)) AS public_key,
    array_agg(DISTINCT tx.included_checkpoint_id) AS checkpoints
  FROM tx_events tx
  WHERE tx.tx_type = 'register_user' AND tx.role_type = 'coordinator' AND tx.role_id = 0
    AND tx.included_checkpoint_id IS NOT NULL AND tx.included_at IS NOT NULL
    AND tx.owner_user_id IS NOT NULL AND tx.result->>'user_id' = tx.owner_user_id::text
    AND octet_length(tx.content_hash) = 32
  GROUP BY tx.owner_user_id HAVING count(DISTINCT tx.content_hash) = 1
)
SELECT count(*) AS eligible_users,
       count(*) FILTER (WHERE users.public_key IS DISTINCT FROM authority.public_key) AS mismatched_users
FROM user_info users JOIN authority USING (user_id)
WHERE users.metadata->>'genesis' IS DISTINCT FROM 'true'
  AND (users.registered_checkpoint_id IS NULL OR users.registered_checkpoint_id = ANY(authority.checkpoints));
SELECT max(version) AS latest_migration, bool_and(success) AS migrations_successful FROM _sqlx_migrations;
COMMIT;
