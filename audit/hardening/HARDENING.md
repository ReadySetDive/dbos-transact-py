# Hardening guide: MIT-only intranet deployment of `dbos==3.6.0`

Scope: `dbos` 3.6.0 (tag `3.6.0`, commit `2cf279c`) on PostgreSQL, **without** the proprietary
`dbos-enterprise` package and **without** Conductor. Every control below was built and then
executed in the audit sandbox; "Observed" is what actually happened, not what is expected.

Test bed: Python 3.13.18, PostgreSQL 16.15 (throwaway local cluster, TLS with a private CA),
system libpq 16.15, the hash-locked minimal dependency set (`requirements-min.lock.txt`),
`strace` for network observation. No Docker daemon and no systemd PID 1 were available, so the
container and systemd examples are **written but not executed** (their building blocks were).

R-numbers refer to the round-1 findings (R2 egress, R3 pickle, R4 logs, R5 environment,
R6 Conductor, R7 retention, R8 supply chain, R9 stability).

## Files

| File | Purpose |
|---|---|
| `requirements-min.lock.txt` | hash-locked minimal dependency set (round 1) |
| `constraints-mit-only.txt` | pip constraints that make `dbos-enterprise`, `psycopg-binary`, `psycopg-c` uninstallable |
| `verify_install.py` | pre-deployment verification of an installed environment (control 10) |
| `dbos_hardening.py` | process-side controls: env scrub, enterprise import block, config check, restricted unpickler, log redaction, URL pin check |
| `json_serializer.py` | strict pickle-free `Serializer` |
| `app_example.py` | reference wiring of all process-side controls + recommended config block |
| `prune_workflows.py` | retention job using public MIT APIs only (control 9) |
| `sql/01_roles_and_database.sql`, `sql/02_after_migrate.sql` | three-role least-privilege setup (control 2) |
| `sql/03_reject_pickle.sql`, `sql/03_reject_pickle_remove.sql` | optional DB-side rejection of `py_pickle` rows (control 3b) |
| `sql/census_serialization.sql`, `sql/check_orphans.sql`, `sql/table_counts.sql` | inspection queries |
| `deploy/dbos-launch` | environment allow-list wrapper (control 5) |
| `deploy/myapp-dbos.service`, `deploy/Dockerfile.example`, `deploy/pg_hba.conf.snippet` | deployment examples |
| `tests/`, `evidence/` | the test programs and raw outputs referenced below; **not included in this repository copy** (they lived in the audit sandbox) |

---

## Control 1 - Installation (R8)

**Risk.** Unpinned install pulls `psycopg-binary` (bundled libpq/OpenSSL), whatever is newest
on the index, and possibly the proprietary package; upstream CI never tests psycopg 3.3.9 in
pure-Python mode.

**Config.**

```
python -m venv /opt/myapp/venv
/opt/myapp/venv/bin/pip install --require-hashes --no-deps --only-binary=:all: \
    -c constraints-mit-only.txt -r requirements-min.lock.txt
/opt/myapp/venv/bin/python -I verify_install.py --lock requirements-min.lock.txt
```

**Tests and observed results.**

* Install: exactly 10 distributions + pip; nothing else pulled; `pip check` reports
  "No broken requirements found" (pip does not enforce the `psycopg[binary]` extra).
* `psycopg.pq.__impl__ == "python"`, `psycopg.pq.version() == 160015` (system libpq 16.15).
* `tests/workload.py` on PostgreSQL (sync + async workflows, steps with retries, child workflow,
  queue of 12, cron schedule, send/recv, events, streams, failing workflow with exception round
  trip, cancel, fork, `list_workflows`/`list_workflow_steps`, `DBOSClient` enqueue/send/
  get_event/read_stream/list, delete): **passes** (15 s).
* Upstream test suite at tag 3.6.0 against the *installed wheel* and this exact dependency set
  (test-only extras added under a constraints file that pins the ten locked versions; port
  rewritten to the throwaway cluster; skipped: `test_package.py`, `test_cockroachdb.py`,
  `test_kafka.py`, `test_pdm_build.py`; proxy variables removed so nothing could reach the
  network): **1256 passed, 13 skipped, 11 failed** in 7 min 15 s with `-n 6`. All 11 failures
  are harness artefacts, re-run individually:
  * 6 x `test_schema_migration.py::test_migrate*` - the `dbos` console script was not on `PATH`; pass with it on `PATH`.
  * 2 (`test_client_send_idempotent`, `test_queue_workflow_in_recovered_workflow`) - subprocess could not import `tests`; pass with `PYTHONPATH` set.
  * 1 `test_check_async_raises_or_warns_on_an_event_loop` - passes 3/3 in isolation (order-dependent under xdist).
  * 1 `test_pool_connection_times_out_by_default` - resolves `example.com`; needs external DNS (not allowed here).
  * 1 `test_enqueue_in_transaction_on_another_driver` - needs `psycopg2`, deliberately not installed.

  No failure is attributable to psycopg 3.3.9 pure-Python / libpq 16. The marker `serial`
  selects 0 tests at this tag.

**Residual risk.** The lock still lists the sdist hash for `dbos`; `--only-binary=:all:` prevents
its use. CockroachDB, Kafka and SQLite paths were not exercised. The interpreter of the audit
sandbox ships its own `sitecustomize.py` (image artefact, unrelated to dbos); `verify_install.py`
flags any such file and needs `--allow-file` for a reviewed one.

---

## Control 2 - Database privileges (R3, R9)

**Risk.** With the default single role the application can run DDL, auto-migrate at launch,
`DROP DATABASE` (`dbos reset`), wipe all tables, and reach other databases.

**Config.** `sql/01_roles_and_database.sql` (once, as DBA), then at each deploy
`dbos migrate -s <migrator URL>` followed by `sql/02_after_migrate.sql`; application config
`run_migrations=False`. Three roles:

| Role | Used by | Privileges in schema `dbos` |
|---|---|---|
| `dbos_migrator` | `dbos migrate` only | owner of the pre-created schema; no CREATEDB, no CREATE on the database |
| `dbos_runtime` | application, `DBOSClient` | USAGE; SELECT, INSERT, UPDATE on tables; SELECT only on `dbos_migrations` |
| `dbos_pruner` | `prune_workflows.py` | USAGE; SELECT, DELETE on tables (not `dbos_migrations`) |

Never use `dbos migrate --app-role`: it grants ALL on tables, sequences and functions.
Optionally `deploy/pg_hba.conf.snippet` (TLS-only, one database, reject everything else) and
`REVOKE CONNECT ON DATABASE postgres FROM PUBLIC`.

**Tests and observed results.**

* What the 3.6.0 migrations create (132 migrations): 14 tables, **0 sequences**, 3 functions
  (`enqueue_workflow`, `send_message`, trigger function `notifications_function`, all SECURITY
  INVOKER), 1 trigger, no extension (uses built-in `gen_random_uuid()`).
* Full workload as `dbos_runtime` with `run_migrations=False`: **passes with no additional
  grant.** Nothing extra was needed for functions (PUBLIC EXECUTE default suffices, the trigger
  function runs for the inserting role), LISTEN/NOTIFY and `pg_notify` (no privilege), advisory
  locks, `SET LOCAL statement_timeout`. No TEMP privilege is needed.
* **DELETE is not needed for normal execution.** In 3.6.0 `DELETE` is issued only by
  `delete_workflow(s)`, `rewind_workflow`, `delete_schedule`, `delete_queue` (code reading,
  then confirmed): the workload minus those calls passes as a role with SELECT/INSERT/UPDATE
  only; `DBOS.delete_workflow` and `DBOS.delete_schedule` then fail with "permission denied"
  (raised once, no retry loop). `02_after_migrate.sql` lists the per-table grants if an
  application needs those APIs.
* Launch-time connection to the `postgres` maintenance database happens only with
  `run_migrations=True` (and in `dbos migrate`). With CONNECT revoked both log
  `Could not connect to postgres database to verify existence of dbos_app. Continuing...` and
  proceed normally.
* `run_migrations=True` left on by mistake with the runtime role: launch succeeds without DDL
  when the schema is current (it would fail on a pending migration).
* `run_migrations=False` against an unmigrated database: launch fails closed
  (`... is at schema version 0, but this version of DBOS requires 132`).
* `dbos migrate` as `dbos_migrator` (pre-created schema, no CREATE on the database,
  `search_path=pg_catalog`): works; re-running at the same version is a no-op.
* Denied for `dbos_runtime` (each tried): CREATE TABLE in `dbos` and `public`, CREATE SCHEMA,
  DROP/ALTER/TRUNCATE table, UPDATE/DELETE on `dbos_migrations`, CREATE DATABASE, CREATE ROLE,
  DROP FUNCTION, CREATE OR REPLACE FUNCTION, CREATE TRIGGER, DROP DATABASE, COPY TO file,
  `pg_read_file`, CREATE TEMP TABLE.
* Reset paths as `dbos_runtime`:
  * `dbos reset -y` / `DBOS.reset_system_database()` -> `must be owner of database dbos_app`.
  * `reset_system_database(truncate=True)`: **with DELETE granted it silently emptied every
    table** (30 workflows -> 0; it also terminates the role's other sessions). Without DELETE it
    fails (`permission denied for table notifications`, swallowed and logged as a warning) and
    the data is intact. This is the reason for the separate pruner role.
* With the `pg_hba` snippet: non-TLS, other-database and unix-socket logins of the DBOS roles
  are rejected by the server.

**Residual risk.** `dbos_runtime` can still read and UPDATE every row (it must), so a stolen
runtime credential can corrupt or exfiltrate workflow state; it can connect to any other database
whose CONNECT is still granted to PUBLIC unless `pg_hba`/REVOKE closes that. `dbos_pruner` can
delete everything. Only one real schema upgrade (3.5.0 -> 3.6.0, migration 132) was exercised
under this model.

---

## Control 3 - Deserialization exposure (R3)

**Risk.** Whoever can write rows can make any reader unpickle attacker bytes: a row tagged
`serialization='py_pickle'` is unpickled even when a custom serializer is configured, and a
NULL tag means "the reader's configured serializer", which is pickle when none is configured.
Reproduced: `tests/test_pickle_guard.py off` - four planted rows (tagged output, NULL-tagged
output, tagged input, dotted-name gadget) each executed their (benign, directory-creating)
payload inside `DBOSClient.list_workflows()`.

Columns that select a decoder (enumerated from the schema and migrations):
`workflow_status.serialization` (governs `workflow_input.inputs`, `workflow_output.output/error`
and the legacy inline columns), `operation_outputs.serialization`, `notifications.serialization`,
`workflow_events.serialization`, `workflow_events_history.serialization`,
`streams.serialization`. `workflow_schedules.context` has **no** tag and is always decoded with
the configured serializer. If `SQLAlchemyDatasource` is used, `datasource_outputs.serialization`
in the application database is a seventh (not tested; the datasource takes its own
`serializer=` argument, default pickle).

### 3a - Configure a non-pickle serializer

**Config.** `"serializer": StrictJSONSerializer()` (`json_serializer.py`) or
`DBOSPortableJSONSerializer()` in `DBOSConfig`, and the same `serializer=` for every
`DBOSClient`.

**Test.** Full workload on fresh databases with each serializer, then
`sql/census_serialization.sql`.

| Serializer | Tags written (rows) | `py_pickle` rows |
|---|---|---|
| default | `py_pickle` 82, `portable_json` 9, NULL 14 | 82 |
| `DBOSPortableJSONSerializer` | `portable_json` 91, NULL 14 | **0** |
| `StrictJSONSerializer` | `strict_json` 82, `portable_json` 9, NULL 14 | **0** |

The workload passes with all three. With a non-pickle serializer the library writes no pickle
rows at all: exceptions, internal steps, client enqueue, messages, events and streams all use
the configured format. `DBOS.sleep` checkpoints and the stream-closed sentinel are always
`portable_json`. NULL-tagged rows are (i) scheduler-created workflows, whose inputs are written
with the configured serializer, and (ii) `operation_outputs` rows with no payload (child-workflow
links, `setEvent`, `writeStream`, `closeStream`).

Behaviour changes to accept: exceptions are no longer rebuilt as their original class
(`PortableWorkflowError` / `RemoteError` instead of `AppError`); only JSON-shaped values are
storable.

The one remaining way to *write* pickle is explicit:
`serialization_type=WorkflowSerializationFormat.NATIVE` (enqueue options, `send`, `set_event`,
`write_stream`) stores `py_pickle` regardless of the configured serializer
(`tests/test_native_format.py`: default -> `strict_json`, portable -> `portable_json`,
native -> `py_pickle`).

**Residual risk.** 3a changes what this process *writes*; it does **not** stop it from
*reading* a `py_pickle`-tagged row someone else inserts. On its own it is not a defence.

### 3b - Reject `py_pickle` rows in the database

**Config.** `sql/03_reject_pickle.sql` (BEFORE INSERT OR UPDATE OF serialization triggers on the
six tagged tables, owned by the migrator). Requires 3a everywhere.

**Tests and observed results.**

* Workload with `StrictJSONSerializer` and with `DBOSPortableJSONSerializer` as `dbos_runtime`:
  **passes**. With the default serializer: fails immediately and closed
  (`dbos hardening: serialization py_pickle is not permitted in dbos.workflow_status`).
* `NATIVE` requests are rejected.
* As `dbos_runtime`: INSERT and UPDATE of a `py_pickle` tag rejected; `ALTER TABLE ... DISABLE
  TRIGGER`, `DROP TRIGGER`, `SET session_replication_role`, `CREATE OR REPLACE FUNCTION` all
  denied. So a stolen runtime credential can no longer plant a row that selects the pickle decoder.
* Upgrade path: `dbos migrate` at the same version with triggers installed - no-op, exit 0.
  Real schema migration with triggers installed: 3.5.0 (131) -> 3.6.0 (132) applied cleanly and
  the workload passes afterwards. 3.7.0a2 has no migration beyond 132; its `dbos migrate` is a
  no-op and its workload passes on the trigger-protected schema.
* A CHECK constraint was tried first and **rejected as a design**: PostgreSQL attaches
  `DETAIL: Failing row contains (...)` - the whole row including payload columns - to the error,
  and dbos logs it (`hide_parameters` does not cover server messages; reproduced in control 4).
  The trigger raises a fixed message.

**Residual risk / fragility.** A future migration that rewrites or renames these tables or the
`serialization` column could collide with the triggers (remove with
`03_reject_pickle_remove.sql`, migrate, re-add). Pre-existing pickle rows are not touched (the
script lists them). NULL-tagged rows cannot be forbidden because the library writes them, so a
reader that forgot to configure the JSON serializer still unpickles NULL-tagged content - that
gap is closed only by 3c. The schema owner and superusers bypass the triggers.

### 3c - Restrict the built-in pickle decoder in the process

**Config.** `dbos_hardening.install_pickle_guard(allow_modules=(...), allow_classes=(...))`
(called by `postconfig()`). It replaces `dbos._serialization.DefaultSerializer.deserialize` -
the single `pickle.loads` call site in the 3.6.0 MIT core (`_serialization.py:112`, asserted by
`verify_install.py`) - with a `pickle.Unpickler` whose `find_class` admits only: safe builtins
and built-in `Exception` classes; `datetime`, `Decimal`, `UUID`, `OrderedDict`, `deque`,
`Fraction`; exception classes *defined in* `dbos._error`; `PortableWorkflowError`;
`dbos._sys_db.WorkflowStatus`; and classes *defined in* explicitly allow-listed application
modules (re-exported names such as `mymodule.os.system` are refused). It self-tests at install
and refuses to start if a `__reduce__` probe gets through or the patch is not in effect.

**Tests and observed results.**

* `tests/test_pickle_guard.py on`: the four gadget rows and a planted `SystemExit` error are
  refused (`refusing to unpickle global posix.mkdir` / `__main__.os.mkdir` /
  `builtins.SystemExit`); nothing executed; `list_workflows` returns the raw string with a
  warning; `get_result` raises `PickleDenied`. Legitimate rows still load: builtin containers,
  `KeyError`, `DBOSAwaitedWorkflowCancelledError` and `DBOSMaxStepRetriesExceeded` (both define
  `__reduce__`), an allow-listed application class.
* Full workload with the default (pickle) serializer and the guard on: **passes**, twice on the
  same database (second run re-reads the first run's rows), including the `AppError` round trip
  and the cancelled-workflow error.
* `tests/test_guard_internal_types.py`: objects the library itself pickles into step outputs
  (`WorkflowStatus`, lists of them, step lists, schedules, versions) survive a full replay
  (fork from the last step) with zero denials.

**Residual risk / fragility.** This is a monkey-patch of a private module: it is pinned to
3.6.0 (`assert_mit_only()` refuses other versions) and must be re-validated on every upgrade.
The allow-list of dbos-internal types was derived from the workload and reading, not from the
whole upstream suite; an unlisted internal type would surface as a `PickleDenied` on replay
(use `report_only=True` in staging first). An allow-listed application class is still
constructed with attacker-chosen arguments/state. Restricted unpickling does not bound memory or
CPU. Other languages'/versions' readers are not covered.

### Verdict

| Approach | Robust? | Across upgrades |
|---|---|---|
| **DB write access control (control 2)** | **Primary control.** Nothing below matters if untrusted parties can write the schema as owner/superuser | stable |
| 3a JSON serializer | Necessary enabler, not a defence by itself | stable (public API) |
| 3b triggers | Robust against a compromised *runtime* role once 3a is universal | low fragility; one migration tested |
| 3c restricted unpickler | Effective in tests, covers the NULL-tag and misconfigured-reader gaps | **fragile**: private attribute, version-pinned |

Recommended: control 2 + 3a + 3b, and 3c as defence in depth where pickle cannot be given up
or readers cannot all be trusted to configure the serializer. The application cannot disable
the pickle decoder through any supported setting.

---

## Control 4 - Log hygiene (R4)

**Risk.** Workflow arguments/outputs and credentials reach the logs.

**Config.**

* `db_engine_kwargs={"hide_parameters": True}`.
* Credentials only in the URL's password field. Never `connect_args`, never `?password=`.
* `dbos_hardening.install_log_redaction()` - a `logging.Filter` on the `dbos` logger that
  (1) replaces, matched by source location (`record.filename`/`record.funcName` under a `dbos`
  path), the cancelled-task line from `_outcome.py::_wrap` and the "Error serializing object"
  line from `_serialization.py::serialize` (dropping its traceback, keeping the exception type);
  (2) scrubs `Failing row contains (...)` and, as a backstop, `[parameters: ...]` from the
  message and the formatted traceback of every dbos record.
* Log level INFO. DEBUG adds workflow/step ids and function names, event keys, topic names,
  notification payloads of the form `<workflow id>::<topic|key>`, queue names - identifiers,
  no values (reviewed all `debug()` call sites; DEBUG run below shows no marker).

**Test.** `tests/test_log_hygiene.py` with marker secrets, hardening off vs on; a root handler
captures every logger. Lines containing each marker:

| Scenario | off | on (INFO) | on (DEBUG) |
|---|---|---|---|
| A. DB error mid-insert (step checkpoint rejected by a test trigger); needle = exact base64 parameter | 1 | **0** | **0** |
| G. CHECK violation on the same insert (`[parameters:` + `Failing row contains`) | 3 | **0** (still 2 with `hide_parameters` alone, before the text scrub was added) | **0** |
| B. Cancelled async workflow/step (`functools.partial(... 'secret')`) | 3 | **0** | **0** |
| C. Unserialisable argument, sync call and `start_workflow` | 2 | **0** | **0** |
| E. Unserialisable argument, async workflow | 1 | **0** | **0** |
| F. Unserialisable workflow output | 1 | **0** | **0** |
| D. Step raises `RuntimeError("... secret")` | 1 | 1 | 1 |

The source-location match fires on both the sync paths (C, F) and the async paths (B, E).
`[parameters:` appears 2x off, 0x on (`[SQL parameters hidden due to hide_parameters=True]`).

Credential placement (`tests/test_credential_logging.py`): password in the URL -> masked
(`dbos_runtime:***@`); `?password=` in the query string -> **logged verbatim** at INFO
(`_sys_db.py:792`); `connect_args={"password": ...}` -> **logged verbatim** at INFO
(`_sys_db.py:800`). `dbos_hardening.check_config` / `require_pinned_url` refuse the last two.

**Residual risk - say it plainly.**

* **Exception messages are application-controlled and are still logged** (scenario D), with
  tracebacks, at ERROR. Do not put secrets in exception text.
* The SQL statement text (no values) is still logged on database errors.
* PostgreSQL unique-violation details (`Key (...)=(...)`) carry identifiers such as workflow
  ids, event keys, deduplication ids.
* The exception object returned to the *application* still carries server detail text
  (`Failing row contains ...`) - `hide_parameters` hides parameters only; do not log `str(e)`
  of database errors in application code.
* The traceback scrub relies on `logging.Formatter` honouring a pre-set `exc_text`; handlers
  that format `exc_info` themselves (JSON/OTLP handlers) are not covered.
* The filter matches file and function names of 3.6.0; a refactor silently disables rule (1).
  Re-run `tests/test_log_hygiene.py` on every upgrade.
* `DBOS.delete_workflows` logs the workflow ids at INFO; `dbos migrate` prints the masked URL.

---

## Control 5 - Environment hygiene (R5)

**Risk.** Variables inherited from the parent environment change behaviour: `DBOS__CLOUD=true`
(latched at `import dbos`), `DBOS_*` overrides, libpq `PG*`, OpenSSL/Kerberos/proxy variables.

**Config.**

1. `deploy/dbos-launch -- <command>`: `env -i` allow-list (fixed `PATH`, `HOME`, `USER`,
   `LOGNAME`, `LANG`, `LC_ALL`, `TZ`, `TMPDIR`, anything named `APP_*`, plus explicit `-k`/`-e`);
   `-k`/`-e` refuse the dangerous families, so it cannot be used to re-introduce them.
2. `dbos_hardening.preimport()` before `import dbos`: in-process scrub (same families) + import
   block; `postconfig()` asserts `GlobalParams.dbos_cloud is False`, dbos version 3.6.0 and
   that `dbos_enterprise` is neither installed nor imported.
3. Database URL from a file (`read_database_url`), pinned:
   `...?sslmode=verify-full&sslrootcert=/path/ca.crt&require_auth=scram-sha-256`
   (`require_pinned_url` enforces it).
4. systemd: `deploy/myapp-dbos.service` (`Environment=` + explicit `UnsetEnvironment=` list +
   `LoadCredential=` + the wrapper). Container: `deploy/Dockerfile.example` (wrapper as
   `ENTRYPOINT`).

**Tests and observed results** (`evidence/out_env_tests.log`; rogue endpoint =
`tests/rogue_pg_listener.py` on 127.0.0.2, a loopback listener that declines TLS and asks for a
cleartext password; the real server listens only on 127.0.0.1).

| # | URL | Hostile environment | Wrapped | Observed |
|---|---|---|---|---|
| 1 | plain | none | - | connects to 127.0.0.1, `ssl=True` (opportunistic, unverified) |
| 3 | plain | `PGHOSTADDR=127.0.0.2` | no | **connection redirected; client sent the cleartext password to the rogue listener** |
| 9 | plain + `require_auth=scram-sha-256` | `PGHOSTADDR` | no | redirected, but client refuses: `authentication method requirement "scram-sha-256" failed`; no password sent |
| 4 | pinned | `PGHOSTADDR`, `PGSSLMODE=disable`, `PGREQUIREAUTH=password` | no | still redirected to 127.0.0.2, then **fails closed**: `server does not support SSL, but SSL was required`; nothing disclosed |
| 5 | pinned | `PGSSLMODE=disable`, `PGSSLROOTCERT=<other CA>`, `PGREQUIREAUTH=password` | no | no effect: correct server, `ssl=True` |
| 6 | pinned | `PGOPTIONS=-c default_transaction_read_only=on` | no | **still applied**: every write fails (`cannot execute UPDATE in a read-only transaction`) |
| 7/8 | pinned / plain | `PGSERVICEFILE`+`PGSERVICE` (hostaddr) | no | not redirected in this stack (psycopg 3 passes an explicit `hostaddr`) |
| 10 | pinned + `hostaddr=127.0.0.1` | `PGHOSTADDR` | no | no effect |
| - | plain | `PGSSLMODE=disable` | no | **downgraded**: `ssl=False` (and refused server-side once the `pg_hba` snippet is active) |
| 11 | pinned | full hostile set incl. `DBOS__CLOUD=true` and all families below | no | start-up fails: `Connecting to DBOS Conductor requires the dbos-enterprise package` (denial of service, nothing sent) |
| 13 | pinned | full hostile set | in-process `scrub_environment()` only | normal: 127.0.0.1, `ssl=True`, `cloud=False`, configured name/version/executor |
| 14 | pinned | full hostile set | `dbos-launch` | normal, same as 13; rogue listener saw nothing |
| 15 | plain | full hostile set | `dbos-launch` | normal; rogue listener saw nothing |

Full hostile set: `PGHOSTADDR PGSSLMODE PGREQUIREAUTH PGSERVICEFILE PGSERVICE PGPORT PGUSER
PGDATABASE PGPASSWORD PGOPTIONS DBOS__CLOUD DBOS_APP_NAME DBOS_SYSTEM_DATABASE_URL
DBOS__APPVERSION DBOS__VMID DBOS__APPID DBOS_DOMAIN DBOS__CONDUCTOR_KEY DBOS__CONDUCTOR_URL
DBOS__CONDUCTOR_APP_NAME DBOS__OTLP_TRACES_ENDPOINT DBOS__OTLP_LOGS_ENDPOINT
OTEL_EXPORTER_OTLP_ENDPOINT HTTPS_PROXY HTTP_PROXY ALL_PROXY OPENSSL_CONF SSL_CERT_FILE
SSL_CERT_DIR KRB5_CONFIG KRB5CCNAME LDAPCONF SASL_PATH PYTHONPATH LD_LIBRARY_PATH`.

`strace -f` of the wrapped, hardened workload started from that hostile environment, followed by
a 300 s idle period (333 s trace): `connect()` only to 127.0.0.1:5743 (12) and to the local
`/var/run/nscd/socket` (4, ENOENT); no UDP socket, no `bind`/`listen`; **0 connects during the
idle window** (`evidence/strace_hardened_idle_network_calls.txt`).

**What pinning does and does not fix.** With `sslmode`, `sslrootcert` and `require_auth` in the
URL, `PGSSLMODE`, `PGSSLROOTCERT` and `PGREQUIREAUTH` no longer downgrade. These **still act and
must be scrubbed**: `PGHOSTADDR` (redirects the TCP connection; harmless only because
verify-full then fails - or pin `hostaddr=` too), `PGOPTIONS` (session settings: read-only,
`search_path`, ...). Not individually tested, scrubbed as part of `PG*`: `PGSSLCERT`,
`PGSSLKEY`, `PGSSLCRL`, `PGSSLMINPROTOCOLVERSION`, `PGCHANNELBINDING`, `PGGSSENCMODE`,
`PGGSSDELEGATION`, `PGSYSCONFDIR`, `PGPASSFILE`, `PGTARGETSESSIONATTRS`.

**Residual risk.** Whoever controls the service's environment usually controls its command line
too; this control removes accidental inheritance and cheap redirection, not a root attacker.
The systemd unit and Dockerfile were not executed here (`systemd-analyze verify` reports only
the missing binary path). `require_auth` needs libpq >= 16. The in-process scrub runs after the
interpreter has started, so it cannot undo `LD_*`/`PYTHON*` effects - only the wrapper can.

---

## Control 6 - Blocking the proprietary package (R5, R6)

**Risk.** `dbos-enterprise` (Conductor client = remote control channel) gets installed by an
extra or a transitive dependency and is imported when a key or `DBOS__CLOUD` appears.

**Config.**

* Build: `-c constraints-mit-only.txt` on every pip call (`dbos-enterprise<0.dev0`,
  `psycopg-binary<0.dev0`, `psycopg-c<0.dev0`); internal index/proxy that does not mirror
  `dbos-enterprise` (and ideally serves only the locked files); `verify_install.py` in CI.
* Runtime: `dbos_hardening.preimport()` (a `sys.meta_path` finder that raises
  `ModuleNotFoundError(name="dbos_enterprise")`), `check_config()` (refuses `conductor_key`,
  `conductor_url`, `transact_enterprise_key`, `auto_upgrade`, `sharding`, `suspend_mode`,
  `external_stores`, `enable_otlp`, OTLP endpoints), `assert_mit_only()`.

**Tests and observed results.**

* Constraints: `pip install --dry-run -c constraints-mit-only.txt` of `dbos[enterprise]==3.6.0`,
  `dbos-enterprise`, `psycopg[binary]==3.3.9` -> `ResolutionImpossible`. (So does a plain
  `dbos==3.6.0`, because of its `psycopg[binary]` requirement: the constraints force the
  `--no-deps` hash-locked path.)
* Normal MIT operation with all guards on: workload and `app_example.py` pass.
* `conductor_key` set, package absent, no hardening: fails at `DBOS()` with
  `Connecting to DBOS Conductor requires the dbos-enterprise package`; `strace` shows **no**
  network `connect()` at all (only nscd).
* `conductor_key` + a stub `dbos_enterprise` on the path: without hardening the stub **is
  imported**; with the import block it is not, and start-up fails with the same clean error;
  with no key, `assert_mit_only()` refuses to start (`the proprietary dbos-enterprise package
  is installed`).
* `check_config()` refuses the key before `DBOS()` is constructed.
* **Not fail-closed without `check_config()`:** `auto_upgrade=True` (or `sharding`,
  `suspend_mode`, `external_stores`) together with a key makes `DBOS()` perform the entitlement
  request to `https://cloud.dbos.dev/conductor/v2/entitlements` (key in the `Authorization`
  header) **before** it tries to import the package. Observed: DNS lookup attempt
  (`connect(... 8.8.8.8:53)`), then `Could not verify the DBOS key's entitlements ...; starting
  anyway`, then the missing-package error. The import block does not prevent that request;
  `check_config()` and the egress firewall do (with `check_config()`: 0 network connects).
  The same check runs at launch for a workflow declared with `auto_upgrade=True`.

**Residual risk.** `check_config()` only sees the dict passed to it; `DBOS(conductor_key=...)`
constructor arguments and per-workflow `auto_upgrade=True` are application code - review for
them. The entitlement check itself was deliberately left untouched.

---

## Control 7 - Egress (R2)

**Allow-list.** TCP from the application hosts to the database host:port. Nothing else. Add the
resolver only if the URL uses a host name. No inbound port: dbos 3.6.0 MIT core never calls
`bind`/`listen`.

**Tests.** `strace -f -e trace=socket,connect,bind,listen,sendto,sendmsg` over the full workload
plus 300 s idle, twice:

| Run | `connect()` targets | UDP sockets | `bind`/`listen` | connects in idle window |
|---|---|---|---|---|
| default config, clean environment, `run_migrations=True` (317 s) | 127.0.0.1:5743 x10; nscd unix socket x2 (ENOENT) | 0 | 0 | 0 |
| hardened, wrapped, hostile parent environment (333 s) | 127.0.0.1:5743 x12; nscd unix socket x4 (ENOENT) | 0 | 0 | 0 |

This confirms round-1 R2 at syscall level, including the idle period. The INFO line
`To view and manage workflows, connect to DBOS Conductor at: https://console.dbos.dev/...` is
text only.

**Residual risk.** Observed for this workload and 5 minutes of idle only; code paths that were
not run (Kafka, datasources, `dbos init`, entitlement check - see control 6) were not observed.
The firewall rule is the control; the observation is its justification.

---

## Control 8 - Operational settings (R9)

**Recommended config block** (complete version in `app_example.py`):

```python
config: DBOSConfig = {
    "name": "myapp",
    "system_database_url": dbos_hardening.read_database_url("APP_DBOS_DB_URL_FILE"),
    "run_migrations": False,
    "application_version": os.environ["APP_VERSION"],
    "executor_id": os.environ["APP_EXECUTOR_ID"],
    "max_executor_threads": 32,
    "sys_db_pool_size": 10,
    "db_engine_kwargs": {"hide_parameters": True, "pool_timeout": 30, "pool_pre_ping": True},
    "log_level": "INFO",
    "serializer": StrictJSONSerializer(),
}
...
DBOS.destroy(workflow_completion_timeout_sec=20)
```

| Setting | Prevents | Test / observed |
|---|---|---|
| `run_migrations=False` | DDL and the maintenance-DB connection at launch; 30 s advisory-lock "time out open" path | control 2 |
| `application_version` explicit | version = hash of workflow source, so any code change orphans in-flight workflows | `tests/test_shutdown_recovery.py`: explicit -> `Recovering 1 workflows`, steps 7->10 after restart with changed source; implicit -> `No workflows to recover`, workflow stays PENDING forever (steps 6->6) |
| `executor_id` explicit, stable, unique per instance | default `"local"` on every host: each instance recovers the others' workflows | same test (identity recorded on the row) |
| `max_executor_threads` | unbounded thread creation (default) | `tests/test_burst.py`, below |
| `sys_db_pool_size` | connection exhaustion on the server | peak server connections = pool size + 1 (LISTEN connection); `max_overflow` is 0 |
| `destroy(workflow_completion_timeout_sec=N)` + `os._exit` if threads remain | hang at shutdown | destroy returned after 3.0 s with 1 workflow thread still alive; workflow threads are non-daemon, so without `os._exit` the process stays up until they end (seen: ~40 s after "successfully shut down") |

Burst of 300 concurrent workflows (each one 0.3 s step), runtime role:

| Pattern | cap / pool | Result | Peak threads | Peak DB conns |
|---|---|---|---|---|
| independent workflows | unbounded / 20 | 300 done, 3.9 s | 79 | 21 |
| independent workflows | 32 / 10 | 300 done, 3.6 s | 42 | 11 |
| independent workflows | 32 / 4 | 300 done, 3.5 s | 42 | 5 |
| parent `start_workflow(child)` + `get_result()` | unbounded / 20 | 300 done, 6.0 s | 81 | 20 |
| **parent `start_workflow(child)` + `get_result()`** | **32 / 10** | **deadlock: 16 done, 284 stuck after 60 s** | 42 | 11 |
| parent calls child inline | 32 / 10 | 300 done, 4.7 s | 42 | 11 |
| same parents via a queue with `worker_concurrency=16` | 32 / 10 | 300 done, 10.2 s | 42 | 11 |
| queue of leaf workflows, `worker_concurrency=16` | 32 / 10 | 300 done, 7.7 s | 26 | 11 |
| workflows blocked 2 s in `recv` | 32 / 10 | 300 done, 24 s | 42 | 11 |
| workflows blocked 2 s in `recv` | 8 / 10 | 300 done, 89 s | 18 | 9 |

**The cap is not free.** A bounded pool deadlocks when more parents than threads block on
children that need a thread of the same pool. Rule: admit work through queues whose total
`worker_concurrency` is at most half of `max_executor_threads` (more if nesting is deeper), call
children inline where possible, and never `start_workflow(...).get_result()` from an unbounded
number of concurrent workflows. No pool-timeout error occurred in any run, even with a pool of 4.

**Residual risk.** Whether a deadlocked executor recovers after a restart with the same cap was
not tested (recovery resubmits everything to the same pool). Explicit `application_version`
means recovered workflows replay against whatever code is deployed: step order/shape
compatibility becomes the deployer's responsibility. `cancel_workflow` does not interrupt a
thread blocked in `recv`/`sleep`. `db_retry` retrying forever and the forward-only migrations
(R9) are unchanged.

---

## Control 9 - Retention without the proprietary package (R7)

**Risk.** MIT core has no time-based pruning; tables grow without bound.

**Config.** `prune_workflows.py --url-file <pruner URL file> --older-than-days N [--dry-run]`
from cron/systemd timer as `dbos_pruner` (SELECT + DELETE only). Uses only
`DBOSClient.list_workflows(load_input=False, load_output=False)` and
`DBOSClient.delete_workflows`; never deserializes a payload. Deletes terminal workflows
(`SUCCESS`, `ERROR`, `CANCELLED`, `MAX_RECOVERY_ATTEMPTS_EXCEEDED`) older than the cut-off;
holds back any workflow whose parent still exists and is not terminal.

**Tests and observed results** (`tests/prune_seed.py`: workflows with 2 steps, an inline child,
an event, a stream, an unconsumed message; 10 % failing; plus 5 parents left PENDING with a
finished child).

* Seeded: 6010 `workflow_status`, 6010 `workflow_input`, 6005 `workflow_output`, 27020
  `operation_outputs`, 3000 `notifications`, 3000 `workflow_events`, 3000
  `workflow_events_history`, 6000 `streams`.
* Dry run: `would delete=6000 held_back_active_parent=5`, row counts unchanged.
* Real run: 6000 workflows (about 60 000 rows across the eight tables) in 1.2 s = **about 5000 workflows/s** at
  `--batch 300`.
* Afterwards: only the 5 PENDING parents and their 5 held-back children remain;
  `sql/check_orphans.sql` = **0 in all eight tables** (payload tables are deleted explicitly by
  dbos, the others by ON DELETE CASCADE).
* Concurrency: 33 prune runs with a 2 s cut-off while a live process executed 1500 parent +
  1500 child workflows: all 3000 deleted as they aged out, the live process finished with exit 0
  and no error, 0 orphans. The full workload also passes while a prune loop runs.
* `dbos_pruner` cannot UPDATE or INSERT.

**Residual risk.** A terminal workflow that is resumed, forked or rewound at the instant it is
pruned loses the race (use a retention far longer than any manual intervention window). A
finished child is kept as long as its parent is active, however old. Throughput was measured on
small payloads with `fsync=off`; expect less in production. Listing uses `OFFSET` paging over
`workflow_status`; very large backlogs should be worked off with `--max-seconds` over several
runs. `workflow_schedules`, `queues` and `application_versions` are not pruned.

---

## Control 10 - Pre-deployment verification (R8)

**Config.** `python -I verify_install.py --lock requirements-min.lock.txt [--wheel <file>]` with
the interpreter of the environment to be shipped; fail the build on non-zero exit.

Checks: dbos is 3.6.0; every dbos file matches its RECORD sha256; the set of (path, sha256)
equals the genuine PyPI wheel's manifest (wheel sha256
`bed76236c8225d9da34d3f5c641dbc55249e113da071757f0d99fde6d1af58ac`, confirmed against PyPI JSON
and a fresh download; manifest digest pinned in the script); no unrecorded file in `dbos/`;
exactly one unpickling call site; `dbos_enterprise`, `psycopg_binary`, `psycopg_c`, `psycopg2`,
`opentelemetry`, `websockets` absent as distributions and as importable modules; no `.pth`, no
`sitecustomize`/`usercustomize`; psycopg implementation `python` + libpq version; installed set
equals the lock; prints resolved versions.

**Tests and observed results.** Genuine environment: PASS (59 files) - after allowing the
sandbox image's own `sitecustomize.py`, which the script correctly reported. Tampered copies,
each detected: appended line in `dbos/_utils.py` (hash mismatch); same change **with RECORD
rewritten to match** (manifest digest mismatch); extra file in `dbos/`; a `.pth` file; a
`sitecustomize.py`; stub `dbos_enterprise`; stub `opentelemetry`; `psycopg-binary` installed
(four separate failures).

**Residual risk.** Verifies dbos byte-for-byte; the nine dependencies are verified by version
against the lock and by hash at install time only (their installed files are not re-hashed).
It checks the environment it runs in, not the running process. The known-good digest is only as
good as round 1's conclusion that the 3.6.0 wheel matches the tagged source.

---

## Controls that did not work, or are too fragile to rely on alone

* **JSON serializer alone (3a)** does not stop pickle deserialization of planted rows.
* **CHECK constraints** for 3b leak whole rows into error text; use the trigger.
* **`hide_parameters` alone** does not hide server-side `DETAIL` row dumps.
* **Runtime role with DELETE** can empty the system database via `reset_system_database(truncate=True)`.
* **Import block alone** does not stop the entitlement HTTPS request when an enterprise feature
  flag and a key are both configured.
* **URL pinning alone** does not neutralise `PGHOSTADDR` or `PGOPTIONS`.
* **`max_executor_threads` alone** turns nested `start_workflow().get_result()` fan-out into a deadlock.
* **Restricted unpickler (3c) and the source-location log filter** depend on private names of
  3.6.0 and must be re-tested at every upgrade; both fail safe only as far as their self-tests go.
* **systemd unit / Dockerfile**: not executed in this sandbox.

## Re-running the tests

```
export U=postgresql://dbos_runtime:...@host:5432/dbos_app
WL_URL=$U WL_NO_DELETE=1 python tests/workload.py                      # controls 1, 2
WL_URL=$U WL_NO_DELETE=1 WL_SERIALIZER=customjson python tests/workload.py   # 3a/3b
WL_URL=$U WL_NO_DELETE=1 WL_HARDEN=1 python tests/workload.py          # 3c, 4, 6 together
python tests/test_pickle_guard.py <superuser URL> on|off <empty dir>   # 3c (plants rows; test DB only)
python tests/test_log_hygiene.py <URL> on|off [DEBUG]                  # 4 (NEEDLES=<file>; needs the test trigger)
python tests/test_burst.py $U 32 10 300 nested                         # 8
python tests/test_shutdown_recovery.py <URL> start|restart 1|0 a|b     # 8
python tests/prune_seed.py <URL> 3000 5 ; python prune_workflows.py ... # 9
python -I verify_install.py --lock requirements-min.lock.txt           # 10
```

`tests/rogue_pg_listener.py`, `tests/test_pickle_guard.py` and the planted rows are loopback /
test-database harnesses for verifying the mitigations; do not run them against production.

---

## One-page prioritised checklist

**P0 - before first deployment**

1. Install only with `pip install --require-hashes --no-deps --only-binary=:all: -c constraints-mit-only.txt -r requirements-min.lock.txt`; run `verify_install.py` in the build and fail on non-zero. (C1, C10)
2. Dedicated database and schema; three roles from `sql/01` + `sql/02`; application uses `dbos_runtime` (no DDL, no DELETE); never `dbos migrate --app-role`. (C2)
3. `run_migrations=False`; run `dbos migrate` as `dbos_migrator` in the deploy pipeline, then `sql/02_after_migrate.sql`. (C2)
4. Firewall: application hosts may reach the database host:port only (plus resolver if needed). (C7)
5. Database URL from a secret file, password in the URL's password field only, pinned `sslmode=verify-full&sslrootcert=...&require_auth=scram-sha-256`; server side `hostssl` + `reject` lines in `pg_hba.conf`. (C5, C2, C4)
6. Start through `deploy/dbos-launch` (or an equivalent clean environment); call `dbos_hardening.preimport()` before `import dbos`. (C5)
7. `check_config()` + `postconfig()`: no Conductor/enterprise/OTLP keys, `dbos_enterprise` blocked and asserted absent, `DBOS__CLOUD` asserted off. (C6)
8. `db_engine_kwargs={"hide_parameters": True}`, no `connect_args`, log redaction filter installed, level INFO. (C4)

**P1 - before production traffic**

9. Explicit `application_version` and a stable, unique `executor_id` per instance. (C8)
10. `max_executor_threads` and `sys_db_pool_size` set; fan-out admitted through queues with total `worker_concurrency` <= half the thread cap; no unbounded `start_workflow().get_result()` nesting. (C8)
11. Shutdown: SIGTERM -> `DBOS.destroy(workflow_completion_timeout_sec=N)` -> `os._exit` if workflow threads remain; service manager stop timeout > N. (C8)
12. Configure a non-pickle serializer in the application **and every DBOSClient**; then install `sql/03_reject_pickle.sql`. (C3a, C3b)
13. Schedule `prune_workflows.py` as `dbos_pruner`; first run with `--dry-run`. (C9)

**P2 - defence in depth / ongoing**

14. Enable the restricted unpickler (`postconfig(allow_pickle_modules=...)`), first with `report_only=True` in staging. (C3c)
15. Keep secrets out of exception messages and do not log `str(e)` of database errors. (C4)
16. Internal package index that does not carry `dbos-enterprise`; re-run `verify_install.py` on every image build. (C6, C10)
17. On every dbos upgrade: re-pin `EXPECTED_DBOS_VERSION` and the wheel/manifest digests, re-run `tests/workload.py` (plain, JSON, hardened), `test_pickle_guard.py`, `test_log_hygiene.py`, the census and the strace idle check, before production. (all)
