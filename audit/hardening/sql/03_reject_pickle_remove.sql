-- Removes the optional pickle-rejection triggers (run as schema owner / DBA).
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['workflow_status','operation_outputs','notifications',
                             'workflow_events','workflow_events_history','streams']
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS hardening_reject_pickle ON dbos.%I', t);
    END LOOP;
END $$;
DROP FUNCTION IF EXISTS dbos.hardening_reject_pickle();
