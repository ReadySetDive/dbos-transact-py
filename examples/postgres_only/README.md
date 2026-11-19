# Postgres-only patterns

Small, self-contained patterns for running DBOS Transact with Postgres as the
only backing service (no Conductor).

| File | What it shows |
|---|---|
| `setup_graph.py` | A setup dependency graph that runs once per environment, with each task routed to a worker role, and repeating jobs that start when their own prerequisites are done. |
| `watchdog.py` | Heartbeat table plus `DBOS.recover_workflows` so survivors take over jobs owned by a dead machine. |
| `job_lock.py` | A session advisory lock that keeps two copies of a step body from running at once after a job is handed off. |

Run the graph demo with one process per role:

    DBOS_URL=postgresql://user:pass@host:5432/db python setup_graph.py db
    DBOS_URL=postgresql://user:pass@host:5432/db python setup_graph.py search

Every process needs a unique, stable `executor_id` and a pinned
`application_version`; `setup_graph.py` sets both.
