-- Rows in any DBOS table that reference a workflow with no workflow_status row.
-- Every count must be 0 after pruning.
SELECT 'workflow_input' AS tbl, count(*) AS orphans FROM dbos.workflow_input t WHERE NOT EXISTS (SELECT 1 FROM dbos.workflow_status s WHERE s.workflow_uuid = t.workflow_uuid)
UNION ALL SELECT 'workflow_output', count(*) FROM dbos.workflow_output t WHERE NOT EXISTS (SELECT 1 FROM dbos.workflow_status s WHERE s.workflow_uuid = t.workflow_uuid)
UNION ALL SELECT 'operation_outputs', count(*) FROM dbos.operation_outputs t WHERE NOT EXISTS (SELECT 1 FROM dbos.workflow_status s WHERE s.workflow_uuid = t.workflow_uuid)
UNION ALL SELECT 'notifications', count(*) FROM dbos.notifications t WHERE NOT EXISTS (SELECT 1 FROM dbos.workflow_status s WHERE s.workflow_uuid = t.destination_uuid)
UNION ALL SELECT 'workflow_events', count(*) FROM dbos.workflow_events t WHERE NOT EXISTS (SELECT 1 FROM dbos.workflow_status s WHERE s.workflow_uuid = t.workflow_uuid)
UNION ALL SELECT 'workflow_events_history', count(*) FROM dbos.workflow_events_history t WHERE NOT EXISTS (SELECT 1 FROM dbos.workflow_status s WHERE s.workflow_uuid = t.workflow_uuid)
UNION ALL SELECT 'streams', count(*) FROM dbos.streams t WHERE NOT EXISTS (SELECT 1 FROM dbos.workflow_status s WHERE s.workflow_uuid = t.workflow_uuid)
UNION ALL SELECT 'external_objects', count(*) FROM dbos.external_objects t WHERE NOT EXISTS (SELECT 1 FROM dbos.workflow_status s WHERE s.workflow_uuid = t.workflow_uuid);
