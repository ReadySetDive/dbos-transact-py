-- Run as the DBA (or as dbos_migrator) AFTER every `dbos migrate`, connected to the DBOS database:
--   psql -v ON_ERROR_STOP=1 -d dbos_app -f 02_after_migrate.sql
-- Idempotent.  Re-asserts the minimal grants on whatever the migration created.
-- NEVER use `dbos migrate --app-role`: it grants ALL PRIVILEGES on tables, sequences and functions.

GRANT USAGE ON SCHEMA dbos TO dbos_runtime, dbos_pruner;

-- Runtime: no DELETE, TRUNCATE, REFERENCES, TRIGGER; no DDL.
REVOKE ALL ON ALL TABLES IN SCHEMA dbos FROM dbos_runtime;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA dbos TO dbos_runtime;
-- The migration bookkeeping table is read at every launch (run_migrations=False verifies the
-- schema version) but must never be written by the runtime role.
REVOKE INSERT, UPDATE ON dbos.dbos_migrations FROM dbos_runtime;
REVOKE CREATE ON SCHEMA dbos FROM dbos_runtime;

-- Retention job: read + delete only.
REVOKE ALL ON ALL TABLES IN SCHEMA dbos FROM dbos_pruner;
GRANT SELECT, DELETE ON ALL TABLES IN SCHEMA dbos TO dbos_pruner;
REVOKE DELETE ON dbos.dbos_migrations FROM dbos_pruner;

-- OPTIONAL, only if the application itself calls these APIs (each needs DELETE):
--   DBOS.delete_schedule            GRANT DELETE ON dbos.workflow_schedules TO dbos_runtime;
--   DBOS.delete_queue               GRANT DELETE ON dbos.queues TO dbos_runtime;
--   DBOS.delete_workflow(s)         GRANT DELETE ON dbos.workflow_status, dbos.workflow_input,
--                                     dbos.workflow_output, dbos.operation_outputs TO dbos_runtime;
--   DBOS.rewind_workflow            additionally DELETE ON dbos.workflow_events,
--                                     dbos.workflow_events_history, dbos.streams, dbos.notifications
-- Granting DELETE on all tables re-enables DBOS.reset_system_database(truncate=True) for the role.
