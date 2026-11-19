"""Reference wiring of every process-side control for an MIT-only dbos==3.6.0 service.

Start it through the launcher so the environment is clean before Python starts:

    APP_DBOS_DB_URL_FILE=/run/credentials/myapp/db_url \\
    APP_VERSION=2026.11.1 APP_EXECUTOR_ID=$(hostname) \\
    deploy/dbos-launch -- /opt/myapp/venv/bin/python -m myapp      # or: python app_example.py

The URL file holds e.g.
    postgresql://dbos_runtime:<password>@db.intranet.example:5432/dbos_app?sslmode=verify-full&sslrootcert=/etc/myapp/ca.crt&require_auth=scram-sha-256
"""
import os
import signal
import sys
import threading

import dbos_hardening

# 1. Before `import dbos`: scrub dangerous variables that survived (in-process fallback for the
#    launcher) and block the proprietary package.
dbos_hardening.preimport()

from dbos import DBOS, DBOSConfig  # noqa: E402

from json_serializer import StrictJSONSerializer  # noqa: E402

config: DBOSConfig = {
    "name": "myapp",
    # Credentials only in the URL (masked in logs), read from a file, TLS pinned.
    "system_database_url": dbos_hardening.read_database_url("APP_DBOS_DB_URL_FILE"),
    "dbos_system_schema": "dbos",
    # Never migrate from the service: the runtime role has no DDL rights; `dbos migrate` runs at deploy.
    "run_migrations": False,
    # Explicit identity: without these, version = hash of workflow source (changes on every code
    # change -> interrupted workflows are NOT recovered) and executor_id = "local" on every host
    # (-> every instance recovers every other instance's workflows).
    "application_version": os.environ["APP_VERSION"],
    "executor_id": os.environ["APP_EXECUTOR_ID"],
    # Bounded threads (default is unbounded).  See HARDENING.md control 8 for the starvation rule.
    "max_executor_threads": 32,
    # Pool: at most pool_size connections + 1 LISTEN connection per process (max_overflow is 0).
    "sys_db_pool_size": 10,
    "db_engine_kwargs": {
        "hide_parameters": True,   # keep bound parameters (= workflow payloads) out of error text/logs
        "pool_timeout": 30,
        "pool_pre_ping": True,
        # no connect_args: dbos logs engine kwargs verbatim at INFO
    },
    "log_level": "INFO",           # DEBUG adds workflow/step ids and names, event keys, topics; no payloads
    # No pickle for anything this process writes.
    "serializer": StrictJSONSerializer(),
}
dbos_hardening.check_config(config)   # refuses conductor_key, OTLP endpoints, enterprise switches, ...
DBOS(config=config)
# 2. After DBOS(): assert MIT-only, install the log redaction filter, restrict the built-in
#    pickle decoder (still reachable through rows tagged 'py_pickle' / NULL-tagged rows read by a
#    process without a serializer).  With StrictJSONSerializer no app type needs allow-listing.
dbos_hardening.postconfig()


@DBOS.step()
def do_work(x: int) -> int:
    return x * 2


@DBOS.workflow()
def example_workflow(x: int) -> int:
    return do_work(x)


def main() -> int:
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    DBOS.launch()
    try:
        print("result:", example_workflow(21), flush=True)
        if os.environ.get("APP_ONESHOT") != "1":
            stop.wait()
    finally:
        # Give in-flight workflows a bounded time to finish; whatever is still running is
        # recovered at the next launch with the same executor_id and application_version.
        DBOS.destroy(workflow_completion_timeout_sec=20)
    stragglers = [t for t in threading.enumerate() if t is not threading.main_thread() and not t.daemon]
    if stragglers:
        os._exit(0)  # workflow threads are non-daemon: do not let them hold the process open
    return 0


if __name__ == "__main__":
    sys.exit(main())
