-- OPTIONAL database-side defence for R3 (pickle deserialization), dbos==3.6.0.
-- PRECONDITION: every process that uses this schema (application, DBOSClient users, CLI) is
-- configured with a NON-pickle serializer (e.g. json_serializer.StrictJSONSerializer or
-- DBOSPortableJSONSerializer).  With the default serializer the application cannot write at all
-- once this is installed.
--
-- Run as the schema owner (dbos_migrator) or DBA, connected to the DBOS database, AFTER
-- `dbos migrate`.  Idempotent.  Remove with 03_reject_pickle_remove.sql before a dbos upgrade
-- if a migration ever fails on these tables (none does in 3.6.0 -> 3.7.0a2; see HARDENING.md).
--
-- Why a trigger and not a CHECK constraint: a CHECK violation makes PostgreSQL attach
-- "DETAIL: Failing row contains (...)" -- the full row, i.e. workflow payloads -- to the error,
-- which dbos then logs.  The trigger raises a fixed message without row data.

CREATE OR REPLACE FUNCTION dbos.hardening_reject_pickle() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.serialization = 'py_pickle' THEN
        RAISE EXCEPTION 'dbos hardening: serialization py_pickle is not permitted in %.%',
            TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['workflow_status','operation_outputs','notifications',
                             'workflow_events','workflow_events_history','streams']
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS hardening_reject_pickle ON dbos.%I', t);
        EXECUTE format('CREATE TRIGGER hardening_reject_pickle BEFORE INSERT OR UPDATE OF serialization '
                       'ON dbos.%I FOR EACH ROW EXECUTE FUNCTION dbos.hardening_reject_pickle()', t);
    END LOOP;
END $$;

-- Existing pickle-tagged rows are NOT touched by the trigger.  List them; they must be drained
-- or deleted before the control means anything:
SELECT 'workflow_status' AS tbl, count(*) FROM dbos.workflow_status WHERE serialization = 'py_pickle'
UNION ALL SELECT 'operation_outputs', count(*) FROM dbos.operation_outputs WHERE serialization = 'py_pickle'
UNION ALL SELECT 'notifications', count(*) FROM dbos.notifications WHERE serialization = 'py_pickle'
UNION ALL SELECT 'workflow_events', count(*) FROM dbos.workflow_events WHERE serialization = 'py_pickle'
UNION ALL SELECT 'workflow_events_history', count(*) FROM dbos.workflow_events_history WHERE serialization = 'py_pickle'
UNION ALL SELECT 'streams', count(*) FROM dbos.streams WHERE serialization = 'py_pickle';
