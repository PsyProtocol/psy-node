-- Read-only role of psy-bridge-reader on the Envio PostgreSQL database. It
-- grants READER_TABLES only. The psy-services fallback role also needs
-- LEGACY_TABLES and is a separate script, added later; do not reuse this one
-- for it. Run by the deployment installer as a superuser (or a role with
-- CREATEROLE) connected to the Envio database. The role itself (LOGIN,
-- password, timeouts) is created by the operator; this script only grants.
--
--   psql -v ON_ERROR_STOP=1 -v reader_role=envio_reader -v envio_schema=envio \
--        -f psy_bridge_reader_api/sql/reader-role.sql
--
-- Re-apply after EVERY Envio schema re-initialisation (`envio start -r`, a
-- fresh init): Envio drops and re-creates its schema, which drops these
-- grants with it. The SELECT list must match READER_TABLES in src/sql.rs.
-- No write grant is ever given.

GRANT USAGE ON SCHEMA :"envio_schema" TO :"reader_role";
GRANT SELECT ON
    :"envio_schema"."Deposit",
    :"envio_schema"."DepositLeaf",
    :"envio_schema"."DepositTreeMeta",
    :"envio_schema"."WithdrawalClaim",
    :"envio_schema"."FinalizedBatch",
    :"envio_schema"."envio_chains"
TO :"reader_role";
