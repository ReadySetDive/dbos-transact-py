# Security and stability audit: `dbos` (DBOS Transact for Python)

| | |
|---|---|
| Audit date | 2026-11-19 |
| Deploy candidate | `dbos==3.6.0` (tag `3.6.0`, commit `2cf279c`) |
| Tree audited | this fork at `afef3f7` (3.6.0 + 2 commits), identical to upstream `dbos-inc/dbos-transact-py` |
| Wheel sha256 | `bed76236c8225d9da34d3f5c641dbc55249e113da071757f0d99fde6d1af58ac` |
| Threat model | corporate intranet service on PostgreSQL, MIT package only (no `dbos-enterprise`, no Conductor) |
| Method | two rounds of independent reviewers: line-by-line reading, git and PyPI forensics, `strace`, crash and concurrency testing on PostgreSQL 16, fuzzing |

Line numbers refer to tag 3.6.0 unless stated. Each finding carries a confidence label:

- **executed**: reproduced by running code in a sandbox.
- **read**: confirmed by reading the source, not run.
- **inferred**: reasoned from the code; not verified.

The tested mitigations referenced throughout are in [`hardening/`](hardening/), with the full
guide in [`hardening/HARDENING.md`](hardening/HARDENING.md).

## Contents

1. [Verdict](#1-verdict)
2. [What was verified clean](#2-what-was-verified-clean)
3. [Security findings](#3-security-findings) (S1 to S9)
4. [Data exposure in logs and telemetry](#4-data-exposure-in-logs-and-telemetry) (L1 to L7)
5. [Operational and durability findings](#5-operational-and-durability-findings) (O1 to O17)
6. [Supply chain](#6-supply-chain) (C1 to C7)
7. [Licensing and vendor](#7-licensing-and-vendor) (V1 to V5)
8. [Not covered](#8-not-covered)
9. [Deployment checklist](#9-deployment-checklist)

---

## 1. Verdict

No malware, backdoor, hidden blob, obfuscation or phone-home was found in the MIT core, the
tests, any of the 27 published `dbos-enterprise` versions, the full git history (all refs,
including unmerged pull requests), the `dbos init` templates, or the pinned dependencies.

The MIT-only package is deployable on an intranet **if pinned and hardened**. Out of the box it
has defaults that duplicate or strand work in multi-process deployments, it treats write access
to its database as equivalent to code execution, and it leaks workflow data into logs in several
ordinary failure situations. The project is a fast-moving, effectively single-maintainer product
whose vendor is moving features into a proprietary package.

## 2. What was verified clean

| Check | Result | Confidence |
|---|---|---|
| Fork vs upstream | All commits and objects in this fork exist upstream; no hooks, stashes or extra refs | executed |
| PyPI vs git | All 571 `dbos` releases (1,142 files) match a git commit byte for byte; no `.pth`, `.so` or `.pyc` in any artifact | executed |
| Reproducible build | Tag 3.6.0 rebuilt to the same sha256 as PyPI, by two reviewers | executed |
| Provenance | 1,018 attested files verify against `dbos-inc/dbos-transact-py` / `publish.yml` | executed (offline trust root) |
| Commit signatures | All 672 commits on `main` carry a good GitHub web-flow signature | executed (key from a public keyserver) |
| Merge integrity | For all 671 non-root commits, the tree equals the merge of the public pull-request head | executed |
| History | No binary blob, secret, analytics code or moved tag in any ref (5,943 commits, 10,855 blobs) | executed |
| Source read | Every file under `dbos/` read line by line; all 67 maintainer commits and all external commits since 2026-08 read | read |
| Default network behaviour | `strace` over import, launch, workload and four 10-minute idle runs: connections only to the configured database; no DNS, no listening socket | executed |
| Telemetry | OpenTelemetry is not imported unless `enable_otlp` is set; ambient `OTEL_*` variables alone export nothing | executed |
| SQL injection | No value is ever inlined into SQL text; hostile identifiers round-trip or are rejected | executed |
| Durable execution | 150 `kill -9`s, 307 killed connections, Postgres restarts and a 48 s outage: 5,388 workflows all correct, no step re-run after its checkpoint | executed |
| Dependencies | Every pure-Python file of the 10 pinned dependencies is byte-identical to its upstream git tag | executed |

---

## 3. Security findings

### S1. Write access to the DBOS tables is code execution (pickle) [high, executed]

The default serializer is pickle. More importantly, the **row** chooses the decoder, so
configuring a JSON serializer does not stop a row tagged `py_pickle` from being unpickled:

```python
# dbos/_serialization.py:238
def deserialize_value(serialized_value, serialization, serializer):
    ...
    if serialization == DBOSPortableJSON.name():
        return DBOSPortableJSON.deserialize(serialized_value)
    if serialization == DBOSDefaultSerializer.name():          # "py_pickle"
        return DBOSDefaultSerializer.deserialize(serialized_value)   # pickle.loads
    ...
    return serializer.deserialize(serialized_value)            # your configured serializer
```

This is reached by workers, by `DBOSClient`, and by read-only calls such as
`list_workflows()` (which loads inputs and outputs by default), so an operator workstation that
lists workflows is exposed too. The same applies to `datasource_outputs` in the application
database if DBOS datasources are used; that table's serializer defaults to pickle independently
of `DBOSConfig.serializer`.

One path is closed by a custom serializer: `workflow_schedules.context` has no format column
and always uses the configured serializer.

Upstream's stated position is that pickle is safe "assuming you can trust your own database" and
will remain the default. There is no configuration switch to disable it.

**Mitigation (tested).** Three layers; the first two together are robust against a stolen
runtime credential:

```python
# 1. Write no pickle rows: configure a non-pickle serializer everywhere,
#    including every DBOSClient(serializer=...) and every datasource.
from json_serializer import StrictJSONSerializer   # hardening/json_serializer.py
config["serializer"] = StrictJSONSerializer()
```

```sql
-- 2. Reject pickle-tagged rows in the database (hardening/sql/03_reject_pickle.sql).
--    A trigger, not a CHECK constraint: a CHECK violation prints the whole row into the logs.
CREATE TRIGGER hardening_reject_pickle
  BEFORE INSERT OR UPDATE OF serialization ON dbos.workflow_status
  FOR EACH ROW EXECUTE FUNCTION dbos.hardening_reject_pickle();
-- ...and the same on operation_outputs, notifications, workflow_events,
--    workflow_events_history, streams.
```

```python
# 3. Restrict what the built-in decoder will load (fragile: patches a private attribute,
#    validated against 3.6.0 only).
import dbos_hardening
dbos_hardening.install_pickle_guard(allow_modules=("myapp.models",))
```

With a JSON serializer configured, the library wrote zero `py_pickle` rows over a full workload;
the only remaining pickle write is an explicit `WorkflowSerializationFormat.NATIVE`.

### S2. `@DBOS.required_roles` can be satisfied by writing a row [high, executed]

Identity and roles are restored verbatim from the status row:

```python
# dbos/_core.py:1364
recovered_user = status.get("authenticated_user")
recovered_roles_str = status.get("authenticated_roles")
recovered_roles = json.loads(recovered_roles_str) if recovered_roles_str else None
with DBOSContextSetAuth(recovered_user, recovered_roles):
    ...
```

A row inserted by plain SQL with `authenticated_roles = '["admin"]'` ran an admin-only workflow.
No pickle is involved. The SQL function `dbos.enqueue_workflow(...)` also accepts caller-supplied
user and roles. DBOS role checks are an application convenience, not a security boundary against
anyone who can write `workflow_status` or call `DBOSClient.enqueue`.

**Mitigation.** Control database write access (S4), and enforce authorization in your own
service layer before enqueueing, not only with `required_roles`.

### S3. Any role that can connect to the database can disturb and observe workflows [high, executed]

DBOS wakes waiting workflows with `LISTEN`/`NOTIFY` on three fixed, database-wide channel names
(`dbos_notifications_channel`, `dbos_workflow_events_channel`, `dbos_streams_channel`). Postgres
requires no privilege to `NOTIFY` or `LISTEN`, and `PUBLIC` has `CONNECT` on new databases.

- **Integrity.** A role with nothing but `CONNECT` sent a notification with a matching payload;
  a `recv(timeout_seconds=600)` returned `None` after 3 s and the workflow recorded that as a
  genuine timeout and finished `SUCCESS`. The wait loop leaves on any wake-up and treats "nothing
  there" as a timeout (`_sys_db.py:4250-4258`, `:4831-4839`).
- **Cross-schema.** Two applications in different schemas of one database interfered whenever
  workflow IDs and topics coincided (for example prod and staging schemas with business-key IDs).
- **`::` ambiguity.** The payload is `f"{workflow_id}::{topic}"`, so (`X::b`, `c`) and
  (`X`, `b::c`) collide.
- **Confidentiality.** The same payloads broadcast workflow IDs, topics and event keys to any
  listener.

**Mitigation.** One database per application and environment, with `CONNECT` revoked from
`PUBLIC`:

```sql
REVOKE ALL ON DATABASE dbos_app FROM PUBLIC;
GRANT CONNECT ON DATABASE dbos_app TO dbos_migrator, dbos_runtime, dbos_pruner;
```

Alternatively set `use_listen_notify=False` (tested immune; costs about 1 s of delivery latency
and must be chosen before the first migration). Also: keep `::` and business data out of
workflow IDs, topics and keys, and treat a `None` from `recv`/`get_event` as "re-check".

### S4. The stock role grant is far wider than needed [medium, executed]

`dbos migrate --app-role` grants `ALL` on tables (including `TRUNCATE`), sequences and functions.
A full workload ran with only `USAGE` on the schema and `SELECT, INSERT, UPDATE` on the tables.
`DELETE` is needed only by `delete_workflow(s)`, `rewind_workflow`, `delete_schedule` and
`delete_queue`; a runtime role that has it can empty the system database through
`reset_system_database(truncate=True)` (S5).

**Mitigation (tested).** Three roles, in `hardening/sql/01_roles_and_database.sql` and
`02_after_migrate.sql`:

```sql
-- dbos_migrator: owns the schema, used only by `dbos migrate`
-- dbos_runtime : what the application logs in with
-- dbos_pruner  : retention job only
ALTER DEFAULT PRIVILEGES FOR ROLE dbos_migrator IN SCHEMA dbos
    GRANT SELECT, INSERT, UPDATE ON TABLES TO dbos_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE dbos_migrator IN SCHEMA dbos
    GRANT SELECT, DELETE ON TABLES TO dbos_pruner;
GRANT USAGE ON SCHEMA dbos TO dbos_runtime, dbos_pruner;
```

Do not give the application role `CREATEDB`: with it, a plain `launch()` silently creates a
missing database.

### S5. `dbos reset` destroys more than DBOS state [medium, executed]

| Path | Effect |
|---|---|
| `dbos reset` / `DBOS.reset_system_database()` on Postgres | `DROP DATABASE IF EXISTS <db> WITH (FORCE)` on the database named in the URL, including any non-DBOS data in it |
| `reset_system_database(truncate=True)` | `pg_terminate_backend` on every other session in the database, then `DELETE FROM` every table in the schema (non-DBOS tables included); errors are only logged |
| SQLite | deletes the file |

The CLI prompt says only "deleting metadata about past workflows and steps", and `-y` skips it.
The CLI resolves the URL from `--sys-db-url`, then the environment, then `dbos-config.yaml`, so a
stale variable in an operator shell is the realistic accident. The instance-path guard is an
`assert`, which disappears under `python -O`. Neither path is reachable except by explicit call.

**Mitigation.** Dedicated database; runtime role without `DELETE` and not the database owner
(`dbos reset` then fails with `must be owner of database`); never run Python with `-O`.

### S6. Environment variables can redirect the database connection and leak the password [high, executed]

libpq reads its environment even when a full URL is configured. With a plain URL and
`PGHOSTADDR` pointing elsewhere, the client connected to a test listener that declined TLS and
asked for cleartext authentication, and the client sent the database password in clear. The
compiled default is `sslmode=prefer` (no certificate verification, plaintext fallback).

**Mitigation (tested).** Pin TLS and the auth method in the URL, and scrub the environment:

```text
postgresql://dbos_runtime:<password>@db.intranet.example:5432/dbos_app?sslmode=verify-full&sslrootcert=/etc/myapp/ca.crt&require_auth=scram-sha-256
```

Pinning makes a redirect fail closed and neutralises `PGSSLMODE`, `PGSSLROOTCERT` and
`PGREQUIREAUTH`. It does **not** neutralise `PGHOSTADDR` (redirect) or `PGOPTIONS`
(for example `-c default_transaction_read_only=on` broke every write), so those must be removed:

```sh
# hardening/deploy/dbos-launch: env -i allow-list wrapper
deploy/dbos-launch -- /opt/myapp/venv/bin/python -m myapp
```

```python
# in-process fallback, before the first `import dbos`
import dbos_hardening
dbos_hardening.preimport()   # scrubs DBOS__*, DBOS_DOMAIN, PG*, OPENSSL_*, KRB5*, LDAP*, SASL_*, OTEL_*, proxies
```

### S7. `DBOS__CLOUD=true` and related switches [low for MIT-only, executed]

`DBOS__CLOUD` is read once at import (`_utils.py:158`, exact string `"true"`). With the
enterprise package installed it skips the entitlement check, takes the database URL and app name
from `DBOS_SYSTEM_DATABASE_URL` / `DBOS_APP_NAME`, forces OTLP on, exports every logger in the
process, disables local recovery and can start Conductor from `DBOS__CONDUCTOR_*`.

On an MIT-only install it is only a startup failure: `DBOS()` raises because `dbos_enterprise`
cannot be imported. `DBOS_DOMAIN` redirects the default Conductor host.

**Mitigation.** Scrub `DBOS__*` and `DBOS_DOMAIN` (S6) and assert at start:

```python
dbos_hardening.postconfig()   # asserts GlobalParams.dbos_cloud is False and dbos_enterprise is absent
```

### S8. The enterprise loader and entitlement call [medium, executed]

Core loads the proprietary package by name:

```python
# dbos/_enterprise.py:395
return cast(Enterprise, importlib.import_module("dbos_enterprise"))
```

Whatever module of that name is first on `sys.path` is imported when `conductor_key` is set, an
enterprise feature is configured, or `DBOS__CLOUD=true`. Core hands it the whole `DBOS` instance
(database URL with password, engine, every registered workflow).

If an enterprise feature flag (`auto_upgrade`, `sharding`, `suspend_mode`, `external_stores`)
is set together with a key, `DBOS()` performs an HTTPS GET to
`<conductor>/v2/entitlements` with `Authorization: Bearer <key>` **before** it tries the import,
so blocking the import alone does not prevent that request. `conductor_key` alone fails closed
with no network activity when the package is absent.

**Mitigation (tested).**

```text
# hardening/constraints-mit-only.txt, used with every pip invocation
dbos-enterprise<0.dev0
psycopg-binary<0.dev0
psycopg-c<0.dev0
```

```python
dbos_hardening.preimport()            # meta-path finder that refuses dbos_enterprise
dbos_hardening.check_config(config)   # refuses conductor_*, enterprise flags and OTLP settings
```

Also reserve or block the name `dbos-enterprise` on your internal package index.

### S9. CLI and scaffolding [low to medium]

- **`dbos start` / `dbos migrate` run config commands through the shell** (`cli.py:170`, `:398`,
  `shell=True`). Treat `dbos-config.yaml` as code and never run these in an untrusted directory.
  [read]
- **`${VAR}` substitution happens before YAML parsing.** A multi-line environment value injected
  a `runtimeConfig.start` entry in a test. [executed]
- **`dbos init -t dbos-toolbox | dbos-app-starter`** downloads the unpinned `main` branch of
  `dbos-inc/dbos-demo-apps` and overwrites files in the current directory without confirmation;
  both templates install `dbos[otel,enterprise]` and read a Conductor key. The templates are
  clean today. [executed against a mocked response]
- **`dbos postgres start`** publishes Postgres on all interfaces with the default password
  `dbos`, logs the password, and puts it on a `docker run` command line. [read]
- **`--sys-db-url`** is the only CLI way to pass a URL, so the password is visible in `ps` and
  shell history. [read]
- **Default SQLite file** `./<app>.sqlite` is created mode 0644 and holds every payload.
  [executed]

**Mitigation.** Use only the local template (`dbos init <name> -t dbos-db-starter`) or none;
block `api.github.com` from developer machines; do not use `dbos postgres` on corporate
machines; pass the URL via a config file for CLI use.

---

## 4. Data exposure in logs and telemetry

All of these fire at the default log level unless noted.

### L1. Bound SQL parameters in WARNING logs on database errors [medium, executed]

No engine sets `hide_parameters`, and many sites log `str(e)` of a SQLAlchemy error. Killing a
backend mid-insert produced:

```text
[ WARNING] (dbos:_sys_db.py:640) Database connection failed: (psycopg.errors.AdminShutdown) ...
[SQL: INSERT INTO dbos.operation_outputs (workflow_uuid, function_id, function_name, output, ...
[parameters: {'workflow_uuid': '...', 'output': 'gASVGgAAAAAAAACM...', ...
```

The `output` value is the base64 pickle of the step result. SQLAlchemy prints each parameter in
full up to roughly 300 characters.

```python
config["db_engine_kwargs"] = {"hide_parameters": True}
```

Set it separately on any custom `system_database_engine` and on every datasource engine. It does
not cover PostgreSQL `DETAIL: Failing row contains (...)` text; the log filter in L3 does.

### L2. Serialization failure logs the whole object [medium, executed]

```python
# dbos/_serialization.py:107
dbos_logger.error(f"Error serializing object: {data}", exc_info=e)
```

`data` is the full `{"args": ..., "kwargs": ...}` dict, a step output, a message or an event
value. It fires whenever something is not picklable.

### L3. Cancelled async step logs its arguments [medium, executed]

```python
# dbos/_outcome.py:242
dbos_logger.warning(f"Asyncio task cancelled for workflow or step {func}")
```

For an async step with `retries_allowed=False` (the default) called inside a workflow, `func` is
a `functools.partial` whose repr contains every argument:

```text
Asyncio task cancelled for workflow or step functools.partial(<function call_api at 0x...>, 'sk-live-...', {'ssn': '...'})
```

Triggers include client disconnects, `asyncio.wait_for` timeouts and shutdown. Workflow
arguments, sync steps and steps with retries enabled are not affected.

**Mitigation for L1 to L3 (tested).**

```python
dbos_hardening.install_log_redaction()   # filter on the "dbos" logger, matched by source location
```

Marker counts with hardening off and on: database error 1 to 0, CHECK-violation row dump 3 to 0,
cancelled async step 3 to 0, unserialisable argument 2 to 0. Handlers that format `exc_info`
themselves (JSON, OTLP) are not covered.

### L4. Credentials outside the URL password field are logged [medium, executed]

```text
(dbos:_sys_db.py:800) DBOS system database engine parameters: {'connect_args': {'password': '...', ...
postgresql://user:***@h:5432/db?sslmode=require&sslpassword=zzz
```

Engine kwargs are logged verbatim at INFO (also `_datasource.py:169`), and only the URL's
password component is masked. Keep credentials in the URL password field only; never in
`connect_args` or the query string.

### L5. Exception text is logged with tracebacks [medium, executed]

Every step retry (`_core.py:2478`, WARNING) and every failed background or queued workflow
(`_core.py:1217`, `:1261`, ERROR) logs the exception with full traceback. If your exceptions
embed record data, that data is logged. With argument validation enabled
(`validate_args=pydantic_args_validator`), a failed validation logs the offending value
(`input_value='...'`) and stores it in the error column. No library mitigation; keep sensitive
values out of exception messages.

### L6. What OTLP exports when you enable it [medium, executed]

- **Spans:** workflow and step function names, workflow ID, queue name, application version,
  executor ID, `authenticatedUser`, `authenticatedUserRoles`, `authenticatedUserAssumedRole`,
  and the exception message as span status and in a `Step attempt N failed` event.
- **Logs:** every `dbos` log record (so L1 to L5 as well), with file, function and line.
- **Not exported:** workflow inputs, step outputs, messages, events, stream values.

If the host application already installed a global tracer or logger provider, DBOS attaches to
it. Once enabled, the SDK honours about 50 `OTEL_*` variables plus proxy and netrc settings.

### L7. Log volume during outages and cancellation [low, executed]

A database outage produced about 200 WARNING records per minute (roughly 13 MB/h of log when
idle) with fixed 1 s reconnects; a 48 s outage at 10 workflows/s produced 1.18 MB. Every
cancelled or timed-out workflow whose handle is awaited logs an ERROR with a ~40-line traceback.
`delete_workflows` logs the full ID list at INFO. Size your log pipeline accordingly.

---

## 5. Operational and durability findings

### O1. Default `executor_id` makes replicas re-run each other's work [high, executed]

```python
# dbos/_utils.py:155
executor_id: str = os.environ.get("DBOS__VMID") or "local"
```

Startup recovery re-enqueues every `PENDING` workflow with this process's executor ID. With the
default, a second replica launching re-dispatched the first replica's in-flight workflows (20 of
20 in two of three runs) and steps executed twice, concurrently. With distinct IDs, 0 of 480
steps ran twice.

### O2. A code change or a `dbos` upgrade strands in-flight workflows [high, executed]

The default application version is an MD5 over the source of all registered workflows plus the
`dbos` version and app name (`_dbos.py:415-440`). Startup recovery and dequeue both filter on it.
After a one-line workflow change, 60 of 60 in-flight workflows stayed `PENDING`; the only signal
is an INFO line `No workflows to recover from application version ...`.
`DBOS.recover_workflows` and `resume_workflow` only move them to `ENQUEUED`, where they stay.

**Fix for O1 and O2:**

```python
config = {
    "name": "myapp",
    "executor_id": os.environ["APP_EXECUTOR_ID"],        # stable and unique per instance
    "application_version": os.environ["APP_VERSION"],    # set by your release process
    ...
}
```

With a pinned version, changed source recovered 60 of 60. A pinned version that you then bump
strands the old version's workflows the same way, so either drain before bumping or rescue:

```python
# Rescue workflows stranded under an old version (tested: 10/10 forks succeeded,
# running only the remaining steps). Run as a role that may write; add your own retry (O9).
from dbos import DBOS
from dbos._utils import GlobalParams

for wf in DBOS.list_workflows(status="PENDING", app_version="<old version>",
                              load_input=False, load_output=False):
    steps = DBOS.list_workflow_steps(wf.workflow_id, load_output=False)
    next_step = max((s["function_id"] for s in steps), default=0) + 1
    DBOS.fork_workflow(wf.workflow_id, next_step,
                       application_version=GlobalParams.app_version)
    DBOS.cancel_workflow(wf.workflow_id)   # the original stays PENDING otherwise
```

The harness that was tested computed the next step from `operation_outputs` directly; the
`list_workflow_steps` form above is equivalent in intent but was not itself run. Verify it in
staging.

### O3. A dead worker's tasks are never taken over [high, executed]

There is no heartbeat. Two tasks held by a killed worker were still `PENDING` 90 s later, and a
new executor joining did not take them. With `global_concurrency=3`, a killed worker holding all
three slots stopped the queue for the live workers (0 of 17 tasks in 120 s). Restarting with the
same executor ID drained them in 1.9 s.

**Mitigation.** Stable executor IDs plus a supervisor that restarts them, or a watchdog:

```python
handles = DBOS.recover_workflows(["worker-3"])   # tested: 20/20 recovered, each body once
```

Note `recover_workflows` re-enqueues pending workflows of **every** application version on the
named executors (the commit message says otherwise), and never call it for a live executor.

### O4. Launch-time migrations can freeze every worker [high, executed]

Migrations run automatically at `launch()`, forward only, with no `lock_timeout`. With one
session holding an open transaction that had read `workflow_status`, an `ALTER TABLE` queued
behind it and every other query on the table queued behind the `ALTER`; a plain `SELECT` from
another session was blocked until the reader ended.

Related, all executed:

- The migration advisory lock times out **open**: `launch()` waits 30 s, logs a warning and
  migrates without the lock. Only `DBOS.migrate()` / `dbos migrate` fail instead (since 3.6.0).
- A database whose version is ahead of the library is accepted silently. There are no
  down-migrations.
- A 2.31.1 worker on a schema migrated by 3.6.0 launched without error, returned `None` for a
  result that was really 202, and left a dequeued workflow stuck `PENDING`. A 2.x to 3.x upgrade
  cannot be a rolling deploy and cannot be rolled back without a restore.
- Within 3.x the upgrade itself is fast (0.3 s on 220,000 step rows under live traffic) and a
  running 3.2.0 worker was unaffected.

**Mitigation.**

```python
config["run_migrations"] = False     # workers verify the schema version instead of migrating
```

```sh
# deploy step, as the migrator role, after a backup
dbos migrate --sys-db-url "$MIGRATOR_URL"
psql -d dbos_app -f hardening/sql/02_after_migrate.sql
```

```sql
-- Standard Postgres; not exercised in this audit. Makes migration DDL give up instead of
-- queueing in front of all traffic.
ALTER ROLE dbos_migrator IN DATABASE dbos_app SET lock_timeout = '5s';
```

Never point a pre-release at a database you keep: three already-published migrations were edited
in place during alpha windows, and there is no checksum.

### O5. One bad enqueue blocks a concurrency-limited queue [high, executed]

`_queue.py:697-712` catches every exception from dispatch and only logs
`Error executing workflow <id>`. A row that fails before dispatch stays `PENDING` under the live
executor and keeps its concurrency slot. Triggers confirmed through public interfaces: an
unregistered workflow name (a typo in `DBOSClient.enqueue`), an unknown class or config name,
`authenticated_roles` that is not a JSON list. A restart does not heal it, and neither does
deploying a version that has the function.

```sql
-- Monitor: PENDING rows that have not moved (timestamps are epoch milliseconds)
SELECT workflow_uuid, name, queue_name, executor_id, application_version,
       to_timestamp(updated_at / 1000.0) AS last_update
FROM dbos.workflow_status
WHERE status = 'PENDING'
  AND updated_at < (extract(epoch FROM now()) * 1000)::bigint - 15 * 60 * 1000
ORDER BY updated_at;
```

```python
DBOS.cancel_workflow(stuck_id)   # releases the slot (tested)
```

### O6. No backpressure by default; capping threads has a catch [medium, executed]

```python
# dbos/_dbos.py:903
max_executor_threads = (... .get("max_executor_threads") or sys.maxsize)
```

- A burst of 3,000 workflows peaked at 4,088 threads and 452 MB, and the threads did not go away.
- A queue with no limits claimed 20,000 rows in one poll; threads reached 12,502.
- DBOS replaces the host application's default asyncio executor with its own on the first async
  DBOS call.
- **With `max_executor_threads` set, nested fan-out deadlocks:** 300 parents each doing
  `start_workflow(child).get_result()` with a cap of 32 left 284 stuck.

```python
config["max_executor_threads"] = 32
config["sys_db_pool_size"] = 10

# Set worker_concurrency on every queue, and admit fan-out parents through a queue
# whose worker_concurrency is well below the thread cap (tested: 300/300 complete).
DBOS.register_queue("parents", worker_concurrency=16)
```

A sync `recv` holds one thread per waiting workflow (the thread-free "suspend" mode is
enterprise-only).

### O7. No history pruning in the MIT package [high, read and executed]

Time-based retention and garbage collection were MIT from June 2025, lost their last
non-Conductor entry point at 3.0.0 and became proprietary at 3.3.0. Core at 3.6.0 has no pruning;
tables grow without bound (about 3.3 kB per workflow of seven checkpoints, roughly 3.3 GB per
million).

**Mitigation (tested).** `hardening/prune_workflows.py`, using only public APIs under a
`SELECT`+`DELETE` role:

```sh
prune_workflows.py --url-file /run/credentials/pruner_url --older-than-days 30 --dry-run
prune_workflows.py --url-file /run/credentials/pruner_url --older-than-days 30
```

It never deserializes payloads, deleted about 5,000 workflows/s with zero orphans in all eight
tables, and holds back children of parents that are still running (see O8). Disk space is not
returned without `VACUUM`.

### O8. Deleting history has three traps [medium]

- **Children of running parents.** Deleting a completed child whose parent is still running is
  harmless until that parent crashes; on recovery it then waits forever for a workflow that no
  longer exists (20 of 20). Delete only root workflows with `delete_children=True`, or skip rows
  whose parent is not terminal. [executed]
- **Raw SQL.** Since 3.0 the payload tables (`workflow_input`, `workflow_output`,
  `operation_outputs`) have no foreign key to `workflow_status`. A manual
  `DELETE FROM dbos.workflow_status`, or a delete issued by a pre-3.0 library, leaves the
  sensitive payloads behind. Use `DBOS.delete_workflows`; check with
  `hardening/sql/check_orphans.sql`. [read; orphans observed with a 2.x library]
- **Not atomic with children in 3.6.0.** A child started during a delete-with-children can
  survive as an orphan (fixed after 3.6.0). [read]

### O9. Rewind and fork [medium, read unless stated]

| | Rewind | Fork |
|---|---|---|
| Database retry | none | none |
| Called inside a workflow | a transient connection error is checkpointed as the step's permanent failure | same |
| Messages | deletes messages the workflow had not yet consumed (the commit description says "marked as unconsumed") | not affected |
| Streams | entries from the discarded run are kept, so the re-run duplicates them | not affected |
| Datasource transaction steps | rewinding a cancelled or timed-out workflow from `DBOSClient` or another process replays the old recorded result instead of re-running; for a finished workflow they re-run and repeat their writes | not affected |
| Atomicity | datasource checkpoints are deleted before the system-database rewind | single transaction |
| Tested | not executed | 60 of 60 forks ran exactly the remaining steps [executed] |

Since 3.6.0 cancel, resume, fork and rewind keep the original queue, partition and priority, so
the result needs a live worker on that queue.

```python
import time
from sqlalchemy.exc import DBAPIError, OperationalError

def with_retry(fn, attempts=5):
    for i in range(attempts):
        try:
            return fn()
        except (OperationalError, DBAPIError):
            if i == attempts - 1:
                raise
            time.sleep(min(2 ** i, 30))

with_retry(lambda: DBOS.fork_workflow(workflow_id, start_step))
```

Run rewind and delete from an operator tool under a role with `DELETE`, not from workers.

### O10. Executor fencing is write-time only [medium, read]

Each execution holds a random token on its status row, checked under a row lock when a step
result is written, so two executors cannot both commit the same step result in the system
database. A superseded executor still finishes any step body already running, so external side
effects can happen twice; this is the documented at-least-once contract and fencing does not
narrow it. Datasource transaction steps checkpoint in the application database and cannot be
fenced atomically. A superseded execution parks and holds a thread until the workflow finishes.

A custom `system_database_engine` does not get the 60 s `idle_in_transaction_session_timeout`
that DBOS-created engines get; with one, a frozen process can hold a workflow's row lock
indefinitely.

**Consequence.** Make every step idempotent.

### O11. Cron behaviour [medium, executed]

```python
from croniter import croniter
from datetime import datetime

# croniter 6.2.4: a single-value range expands to the whole field
it = croniter("0 9-9 * * *", datetime(2026, 1, 1), second_at_beginning=True)
# next fire times: 01:00, 02:00, 03:00, ...  (every hour; "0 9 * * *" gives 09:00 daily)
```

- `N-N` in any field means "every" under croniter 6.2.4 (`5-5 * * * *` fires every minute).
- In a non-UTC zone, an ambiguous local time fires twice on fall-back day (different workflow
  IDs, so both run), and a skipped local time fires once at the next valid instant.
- `0 0 31 2 *` passes validation and then logs an error on every poll.
- Since 3.5.0 only one leader process fires schedules; after failover the new leader replays up
  to an hour of missed ticks. With `automatic_backfill=False`, ticks older than 30 s at startup
  are skipped.
- `automatic_backfill` has no cap: a per-second schedule three days stale ran one thread at 82%
  CPU and blocked other schedules.
- `croniter>=6.2.4` is unbounded upstream; 7.0.0 changes step semantics again.

**Mitigation.** Write `9`, not `9-9`; keep schedules in UTC; pin `croniter==6.2.4`; lint
expressions before `create_schedule`.

### O12. Timeouts and delays follow the application host's clock [medium, executed with a simulated clock]

Workflow deadlines, delayed enqueues, sleeps and `recv`/`get_event` timeouts use the host's wall
clock. A host two hours fast cancelled workflows with one-hour timeouts within 70 s, ran a
one-hour-delayed enqueue at once, and made a 30-minute `recv` return `None`. Cancellation is
terminal. Run NTP on every worker and alert on skew.

### O13. Unvalidated numeric parameters [medium, executed]

| Input | Result |
|---|---|
| `global_concurrency`, `worker_concurrency` or limiter `limit` of 0 or negative | accepted; queue silently never dequeues |
| `polling_interval_sec=float("nan")` on Postgres | accepted; 53% CPU and 768 transactions/s |
| `polling_interval_sec=inf` | worker thread dies and is respawned every second |
| `scheduler_polling_interval_sec` of -1 or 1e-9 | hot loop, 1,300 to 1,600 transactions/s |
| `SetWorkflowTimeout(0)` | no timeout for a direct start; "deadline = dequeue time" when enqueued |
| step `interval_seconds=-1` or `backoff_rate=-2.0` | sync step fails with `ValueError`, replacing the real error; the async twin behaves differently |

`DBOSClient` can register queues, so validate these values in your own code.

### O14. Unbounded reads [medium, executed]

`list_workflows()` defaults to no limit with inputs and outputs loaded: 300,000 rows of 1 KB
took 26.8 s and 2.1 GB. Always pass `limit=`, and `load_input=False, load_output=False` unless
you need them. There is no payload size limit (a 500 MB input peaked at 2.5 GB RSS).

### O15. Config file falls back to SQLite silently [medium, executed]

In `dbos-config.yaml`, `system_database_url: ${DBOS_SYSTEM_DATABASE_URL}` with the variable unset
becomes empty, and the CLI and app use `./<app>.sqlite` with no error. A lost secret therefore
runs production on a local file. Pass configuration in code and fail hard when the URL is absent:

```python
url = dbos_hardening.read_database_url("APP_DBOS_DB_URL_FILE")   # raises if missing or not TLS-pinned
```

### O16. Application name is a filter, not an isolation boundary [medium, executed]

With two applications in one schema, B did not dequeue or recover A's work, but by workflow ID or
explicit filter B could read A's results and events, `send` to A's workflows, and cancel, resume
or delete them. Queue names, schedule names and application version strings must be unique
across apps in a schema or launch fails. Use one database per application (S3).

### O17. Known defects in 3.6.0 and upgrade notes

- **Open upstream:** workflows enqueued in the same millisecond can start out of order (#966).
- **Fixed only after 3.6.0:** delete-with-children orphan (O8); async result waiters each poll
  the database separately.
- **By design:** cancellation does not interrupt a running step (the in-flight step body
  finished after cancel in about half of 240 trials; no checkpoint was written after cancel);
  a cancel can be lost when it races completion; a datasource transaction can commit after
  cancellation.
- **3.6.0 step numbering:** DBOS and `DBOSClient` calls made inside a workflow body are now
  recorded steps. In-flight workflows that make such calls cannot replay across the upgrade;
  drain them first.
- **Rolling upgrades across 3.4 to 3.5:** queue claiming switched from transaction isolation to
  advisory locks. Workers on both sides may not exclude each other, so global concurrency limits
  could be exceeded while both run. [inferred]
- **No 3.x line has ever received a patch release.** A fix means taking the next minor, which
  arrives about every ten days with schema changes.
- **Restart storms:** a step that always kills the process ran 101 times before the workflow was
  dead-lettered. Lower `max_recovery_attempts` on workflows with expensive steps.

---

## 6. Supply chain

### C1. Upstream publish pipeline has no gate beyond repository write access [high, read]

`publish.yml` runs on `workflow_dispatch` and on every push to `main`, with `id-token: write`
and no GitHub environment. PyPI provenance shows `environment: None` and accepts
`refs/heads/main` and `refs/heads/release/*`; the version hook treats any branch whose name
contains "release" as a release branch. Every merge reaches PyPI as an alpha about 90 seconds
later without waiting for tests. Actions are pinned by mutable tag, the build backend is
unpinned, and the job installs all dev dependencies before building. There is no `SECURITY.md`,
dependabot, code scanning or published advisory. Branch protection settings were not visible.

### C2. Alphas can be installed without `--pre` [medium, executed]

| Requirement | Resolves to |
|---|---|
| `dbos`, `dbos>=3.6.0`, `dbos~=3.6` | 3.6.0 |
| `dbos>3.6.0`, `dbos!=3.6.0,>=3.6` | 3.7.0a2 |
| `dbos[enterprise]==3.7.0a2` | plus `dbos-enterprise` 3.7.0a1 (the alpha extra floats) |

### C3. All dependency requirements are open-ended [medium, executed]

A fresh `pip install dbos` today pulls SQLAlchemy 2.1.9 (3 days old), croniter 7.0.0 and
python-dateutil 4.0.0 (new majors this month). Upstream CI tests only its lockfile, which has
older versions.

**Mitigation for C1 to C3 (tested).**

```sh
pip install --require-hashes --no-deps --only-binary=:all: \
    -c hardening/constraints-mit-only.txt -r hardening/requirements-min.lock.txt
python hardening/verify_install.py      # wheel hash, RECORD, no .pth, no forbidden packages
```

```text
dbos==3.6.0            SQLAlchemy==2.0.50     greenlet==3.2.4      psycopg==3.3.9
croniter==6.2.4        python-dateutil==2.9.0.post0   six==1.16.0
click==8.4.2           PyYAML==6.0.3          typing_extensions==4.16.0
```

The upstream suite at tag 3.6.0 passed against this exact set (1,256 passed; the 11 failures were
all harness artefacts). The lock accepts every platform's files; trim it to the one file per
package your platform installs. SQLAlchemy 2.0.50 is eight patch releases behind 2.0.58 (no
security-labelled fixes, several identifier-quoting fixes).

### C4. `psycopg[binary]` is a hard requirement with weak provenance [medium, executed]

The default install bundles 14 C libraries (its own libpq, OpenSSL, Kerberos, OpenLDAP, and
several from end-of-life CentOS 7) that OS patching never touches. The wheels are uploaded by
hand without attestation, have no source distribution, and their SBOM omits the self-built
libraries. `--no-deps` with pure-Python `psycopg` uses the OS-patched system libpq instead.

### C5. `import dbos` spawns subprocesses [low, executed]

`croniter` runs `file -b <python>` (resolved through `PATH`) at import; pure-Python `psycopg`
runs `/sbin/ldconfig -p` twice. Both are benign but will trip exec-deny rules. Keep writable
directories out of the service `PATH`.

### C6. Do not run the upstream test suite on a machine with credentials [medium, read]

`tests/test_package.py` runs `dbos init` with the remote templates (unpinned code from another
repository, executed with the full environment), runs an unpinned `pip install`, and the
fixtures drop and recreate local Postgres databases.

### C7. Commit attribution is unreliable [low]

The maintainer pushes his own changes onto external contributors' pull requests and
squash-merges under the contributor's original description (13 of 25 recent external PRs).
Several commit messages contradict their diffs; 9 of 67 maintainer commits have empty bodies,
including the ones that added the entitlement network call. Nothing was found concealed, but
commit messages cannot serve as a changelog and `git blame` does not tell you who wrote or
reviewed a line.

---

## 7. Licensing and vendor

### V1. Open-core timeline [confirmed from git and PyPI]

| When | What |
|---|---|
| 2024-07-19 | `LICENSE` (MIT) created; never changed since |
| 2026-09-15 (3.0.0) | admin HTTP server removed; retention loses its last non-Conductor entry point |
| 2026-10-01 (#873, first in 3.3.0) | Conductor client, retention/GC, metrics, export/import and fork-from-failure removed from MIT core; `dbos-enterprise` first published |
| 2026-10-24 (#895, 3.4.0) | "material breach" license language added to the MIT file `dbos/_enterprise.py`; enterprise wheels become comment-stripped and wheel-only |
| 3.4.0 to 3.5.0 | auto-upgrade, sharding, suspend and external storage ship as enterprise-only |

3.2.0 is the last release whose MIT tree contains the Conductor client and retention code, but
it lacks the durability fixes in 3.3 to 3.6. Releases up to 2.28.0 run an unauthenticated admin
HTTP server on `0.0.0.0:3001` by default.

The `enterprise` extra is injected into wheel metadata at build time by `pdm_build.py` and does
not appear in `pyproject.toml`. There has never been a CLA or DCO.

### V2. The Conductor license was not read first-hand [open item]

The vendor site was unreachable from the audit environment, and the package ships only a URL
pointer, so the terms can change without a release. From search-engine excerpts only (verify
every point before relying on it): acceptance is by downloading, installing or using; without a
paid key only test and development use is licensed; modification, redistribution and reverse
engineering are barred; benchmark results are confidential; the data clause is broad; there is
an audit right; governing law is Massachusetts.

Using only the MIT `dbos` package appears to be entirely outside that license. The clause in
`dbos/_enterprise.py` can only bind someone who has accepted the Conductor license; MIT itself
permits modifying the file. **Have counsel read the actual text before any enterprise use, and
before mirroring `dbos-enterprise` internally.**

### V3. What Conductor can do if you ever set `conductor_key` [read]

The enterprise client opens a persistent websocket (default `cloud.dbos.dev`) over which the
server can:

- read workflow inputs, outputs, errors, step outputs, events, notifications and streams;
- cancel, delete, resume, fork and rewind workflows, trigger and backfill schedules;
- issue a `retention` command with a server-chosen cutoff that deletes completed history for
  **every application in the schema**, with no client-side lower bound;
- send an `import_workflow` message whose payload is unpickled before validation.

`conductor_metadata_only_mode` blocks payload reads and import/export only; every mutating
command remains, and workflow IDs, names, user, roles, custom attributes and hostname are still
sent. The API key is in the websocket URL path. One key reaches every application sharing the
system database. Vendor documentation says a self-hosted Conductor validates its license against
`cloud.dbos.dev` at startup and exits if it cannot. This was confirmed by reading the client
code; the wire behaviour was not observed.

### V4. Vendor and project risk

- One author wrote 74% of the last twelve months' commits; earlier core contributors have
  stopped committing (one still reviews).
- Only a seed round (about $8.5M, March 2024) is publicly reported.
- No public commitment to keep the core MIT was found, and the next history-management feature
  (workflow archiving, an open pull request) loads through the enterprise package.
- Public downstream use on GitHub is small (206 dependent repositories).

### V5. Documentation claims that do not match the audited behaviour

| Docs say | Audited reality |
|---|---|
| Strict semantic versioning; minors never break | 3.3.0 broke any 3.0 to 3.2 app using a Conductor key; 3.1.0 removed client options |
| "Configure a retention policy" (Conductor only) | No open-source pruning exists and none is documented |
| Conductor is "privacy-preserving", a "metadata-only connection" | Payload reads and destructive commands are available by default; metadata-only mode needs a paid plan |
| Pickle is the default | True, but with no trust warning; the row-selects-decoder behaviour (S1) is undocumented |
| `dbos migrate` fails after 30 s on a held lock | True; undocumented that `launch()` proceeds without the lock |
| (nothing) | The log leaks in section 4 and the `DBOS__CLOUD` switch are undocumented for Python |

---

## 8. Not covered

- The Conductor license text (V2), and Conductor's behaviour on the wire or at license expiry.
- Kafka consumers, datasource transactions under crash, SQLite under faults, CockroachDB, and
  all enterprise features at run time.
- Anything over hours: soak tests, memory over long periods, backoff caps in long outages.
- Network partitions, replica failover, host or power loss, real multi-host clock skew.
- Native binaries in dependencies were inspected (linked libraries, imports, strings), not
  rebuilt or disassembled.
- Upstream repository settings: branch protection, required reviews, who has write access, PyPI
  account security.
- The `systemd` unit and `Dockerfile` in `hardening/deploy/` were written but not executed.
- Individual libpq variables beyond `PGHOSTADDR`, `PGOPTIONS`, `PGSSLMODE`, `PGSSLROOTCERT` and
  `PGREQUIREAUTH` are scrubbed as a family but were not tested one by one.
- GitHub issue and pull-request details came through summarised page fetches and are medium
  confidence.
- One planned run-time analysis was stopped by the auditing tool's safety filter and replaced
  with an observation-only run; the Conductor code-execution path (V3) is therefore confirmed by
  reading only.

## 9. Deployment checklist

In priority order. Details and test evidence for each are in
[`hardening/HARDENING.md`](hardening/HARDENING.md).

1. **Install** from `hardening/requirements-min.lock.txt` with `--require-hashes --no-deps`,
   under `constraints-mit-only.txt`; run `verify_install.py`. Never `--pre`. (C1 to C4)
2. **Dedicated database** per application and environment; `REVOKE CONNECT ... FROM PUBLIC`.
   (S3, S5, O16)
3. **Three database roles**; the runtime role has no `DELETE` and owns nothing. (S4, S5)
4. **Explicit `executor_id` and `application_version`.** (O1, O2)
5. **Non-pickle serializer everywhere, plus the pickle-rejecting triggers.** (S1)
6. **TLS-pinned URL read from a file; scrubbed environment via `dbos-launch`.** (S6, S7)
7. **`run_migrations=False`; `dbos migrate` as a deploy step after a backup.** (O4)
8. **`hide_parameters=True` and the log redaction filter.** (L1 to L4)
9. **`max_executor_threads`, pool size, and `worker_concurrency` on every queue.** (O6)
10. **Retention job from day one; alert on stale `PENDING` rows.** (O5, O7, O8)
11. **Supervisor or watchdog for dead executors.** (O3)
12. **Block `dbos-enterprise` on the package index and `api.github.com` from dev machines.**
    (S8, S9)
13. **NTP on every worker; schedules in UTC; idempotent steps.** (O10 to O12)
14. **Upgrade policy:** pin exactly, let a new minor age two to three weeks, read every commit,
    drain in-flight workflows, and rehearse against a restored copy of the system database.
    (O17)

A reference application wiring items 4 to 9 together is in
[`hardening/app_example.py`](hardening/app_example.py).
