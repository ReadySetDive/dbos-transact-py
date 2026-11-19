-- Which decoders are selected by rows currently in the DBOS system schema?
-- NULL means "the serializer configured in the reading process" (pickle if none is configured).
SELECT 'workflow_status' AS tbl, coalesce(serialization,'<NULL>') AS serialization, count(*) FROM dbos.workflow_status GROUP BY 2
UNION ALL SELECT 'operation_outputs', coalesce(serialization,'<NULL>'), count(*) FROM dbos.operation_outputs GROUP BY 2
UNION ALL SELECT 'notifications', coalesce(serialization,'<NULL>'), count(*) FROM dbos.notifications GROUP BY 2
UNION ALL SELECT 'workflow_events', coalesce(serialization,'<NULL>'), count(*) FROM dbos.workflow_events GROUP BY 2
UNION ALL SELECT 'workflow_events_history', coalesce(serialization,'<NULL>'), count(*) FROM dbos.workflow_events_history GROUP BY 2
UNION ALL SELECT 'streams', coalesce(serialization,'<NULL>'), count(*) FROM dbos.streams GROUP BY 2
ORDER BY 1, 2;
