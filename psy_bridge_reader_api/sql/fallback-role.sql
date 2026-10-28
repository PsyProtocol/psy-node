-- Read-only role of the psy-services direct-PostgreSQL fallback on the Envio
-- database (design C13). It grants READER_TABLES and LEGACY_TABLES; the
-- Reader's own role (reader-role.sql) grants READER_TABLES only. Run by the
-- deployment installer as a superuser (or a role with CREATEROLE) connected
-- to the Envio database. The role itself (LOGIN, password, timeouts) is
-- created by the operator; this script only grants.
--
--   psql -v ON_ERROR_STOP=1 -v reader_role=services_fallback -v envio_schema=envio \
--        -f psy_bridge_reader_api/sql/fallback-role.sql
--
-- Re-apply after EVERY Envio schema re-initialisation (`envio start -r`, a
-- fresh init): Envio drops and re-creates its schema, which drops these
-- grants with it. The SELECT list must match READER_TABLES + LEGACY_TABLES in
-- src/sql.rs. No write grant is ever given.

GRANT USAGE ON SCHEMA :"envio_schema" TO :"reader_role";
GRANT SELECT ON
    :"envio_schema"."Deposit",
    :"envio_schema"."DepositLeaf",
    :"envio_schema"."DepositTreeMeta",
    :"envio_schema"."WithdrawalClaim",
    :"envio_schema"."FinalizedBatch",
    :"envio_schema"."envio_chains",
    :"envio_schema"."AccountDepositStats",
    :"envio_schema"."DepositTreeNode"
TO :"reader_role";
