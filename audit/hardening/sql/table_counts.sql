SELECT 'workflow_status' t, count(*) FROM dbos.workflow_status UNION ALL SELECT 'workflow_input', count(*) FROM dbos.workflow_input
UNION ALL SELECT 'workflow_output', count(*) FROM dbos.workflow_output UNION ALL SELECT 'operation_outputs', count(*) FROM dbos.operation_outputs
UNION ALL SELECT 'notifications', count(*) FROM dbos.notifications UNION ALL SELECT 'workflow_events', count(*) FROM dbos.workflow_events
UNION ALL SELECT 'workflow_events_history', count(*) FROM dbos.workflow_events_history UNION ALL SELECT 'streams', count(*) FROM dbos.streams;
