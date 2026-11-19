-- DBOS 3.6.0 hardened database bootstrap.  Run ONCE as a DBA/superuser, connected to the
-- maintenance database:
--   psql -v ON_ERROR_STOP=1 -v db=dbos_app -v migrator_pw="'...'" -v runtime_pw="'...'" \
--        -v pruner_pw="'...'" \
--        -f 01_roles_and_database.sql
-- Tested on PostgreSQL 16.15 with dbos==3.6.0 (see HARDENING.md, control 2).

-- Three roles:
--   dbos_migrator  owns the schema; used ONLY by `dbos migrate` at deploy time.
--   dbos_runtime   what the application and DBOSClient processes log in with: SELECT/INSERT/UPDATE.
--                  No DELETE: dbos 3.6.0 only issues DELETE from delete_workflow(s),
--                  rewind_workflow, delete_schedule and delete_queue (tested), and withholding it
--                  makes DBOS.reset_system_database(truncate=True) fail for this role.
--   dbos_pruner    used ONLY by the retention job (prune_workflows.py): SELECT + DELETE.
CREATE ROLE dbos_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :migrator_pw;
CREATE ROLE dbos_runtime  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :runtime_pw CONNECTION LIMIT 100;
CREATE ROLE dbos_pruner   LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :pruner_pw CONNECTION LIMIT 5;

-- A dedicated database owned by the DBA (not by either DBOS role), so neither role can DROP it.
CREATE DATABASE :"db";
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO dbos_migrator, dbos_runtime, dbos_pruner;
-- (TEMP is intentionally not granted: DBOS 3.6.0 creates no temporary tables.)

-- Optional but recommended: neither role needs the maintenance database.  `dbos migrate`
-- tries to connect to it to check that the target database exists, logs
-- "Could not connect to postgres database to verify existence of ... Continuing..." and proceeds.
-- REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;   -- only if nothing else relies on it

\connect :"db"

-- Nobody but the DBA may create objects in "public" (default since PG15; explicit for older).
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- Pre-create the DBOS system schema owned by the migrator, so the migrator needs no
-- CREATE privilege on the database itself.
CREATE SCHEMA dbos AUTHORIZATION dbos_migrator;

-- Everything the migrator creates later in schema dbos is automatically usable by the runtime
-- role with SELECT/INSERT/UPDATE only (never DDL, DELETE, TRUNCATE, REFERENCES or TRIGGER).
ALTER DEFAULT PRIVILEGES FOR ROLE dbos_migrator IN SCHEMA dbos
    GRANT SELECT, INSERT, UPDATE ON TABLES TO dbos_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE dbos_migrator IN SCHEMA dbos
    GRANT SELECT, DELETE ON TABLES TO dbos_pruner;
GRANT USAGE ON SCHEMA dbos TO dbos_runtime, dbos_pruner;

-- Pin the search_path of both roles (defence against search_path games in shared databases).
ALTER ROLE dbos_runtime  IN DATABASE :"db" SET search_path = pg_catalog;
ALTER ROLE dbos_pruner   IN DATABASE :"db" SET search_path = pg_catalog;
ALTER ROLE dbos_migrator IN DATABASE :"db" SET search_path = pg_catalog;
