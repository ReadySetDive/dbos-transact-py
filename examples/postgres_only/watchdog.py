"""Postgres-only recovery of jobs owned by a dead machine.

DBOS has no built-in liveness detection without Conductor: a job owned by a
machine that never comes back stays PENDING forever. This watchdog fills the gap.
Every process writes a heartbeat row; any survivor that sees PENDING workflows
owned by an executor with no fresh heartbeat calls DBOS.recover_workflows().

Usage (every process):

    DBOS(config={..., "executor_id": MY_ID})   # unique per machine
    start_watchdog(DBOS_URL, MY_ID)            # before launch: heartbeat lands first
    DBOS.launch()

The database in the URL must already exist, because the first heartbeat is
written before DBOS.launch() would create it. The heartbeat table can live in
any database every machine can reach; it does not have to be the system database.

Caveat: a machine that is only stalled (long pause, network partition) also stops
heartbeating. Recovering it while it is still alive runs its in-flight step twice,
concurrently. Pick dead_after_sec well above your worst pause, and wrap steps
that must never overlap in job_lock.JobLock.
"""

import threading
import time

import psycopg

from dbos import DBOS

TABLE = "public.executor_heartbeat"


def start_watchdog(
    dsn: str,
    executor_id: str,
    *,
    heartbeat_sec: float = 2.0,
    dead_after_sec: float = 30.0,
) -> threading.Thread:
    """Write the first heartbeat, then heartbeat and recover in a daemon thread."""
    conn = psycopg.connect(dsn, autocommit=True)
    conn.execute(
        f"CREATE TABLE IF NOT EXISTS {TABLE} "
        "(executor_id text PRIMARY KEY, ts timestamptz NOT NULL)"
    )
    beat = (
        f"INSERT INTO {TABLE} VALUES (%s, now()) "
        "ON CONFLICT (executor_id) DO UPDATE SET ts = now()"
    )
    conn.execute(beat, (executor_id,))
    conn.close()

    def loop() -> None:
        ready = False  # recovery needs DBOS launched; stay quiet until it first works
        while True:
            try:
                with psycopg.connect(dsn, autocommit=True) as c:
                    while True:
                        c.execute(beat, (executor_id,))
                        try:
                            _recover_dead(c, dead_after_sec)
                            ready = True
                        except Exception as e:
                            if ready:
                                DBOS.logger.warning(f"watchdog recovery: {e!r}")
                        time.sleep(heartbeat_sec)
            except Exception as e:  # lost the heartbeat connection
                DBOS.logger.warning(f"watchdog heartbeat: {e!r}; reconnecting")
                time.sleep(heartbeat_sec)

    thread = threading.Thread(target=loop, name="dbos-watchdog", daemon=True)
    thread.start()
    return thread


def _recover_dead(c: "psycopg.Connection", dead_after_sec: float) -> None:
    owners = {
        w.executor_id
        for w in DBOS.list_workflows(
            status="PENDING", load_input=False, load_output=False
        )
        if w.executor_id
    }
    if not owners:
        return
    live = {
        row[0]
        for row in c.execute(
            f"SELECT executor_id FROM {TABLE} "
            "WHERE ts > now() - make_interval(secs => %s)",
            (dead_after_sec,),
        )
    }
    dead = sorted(owners - live)
    if dead:
        handles = DBOS.recover_workflows(dead)
        DBOS.logger.warning(
            f"watchdog: executors {dead} look dead; "
            f"recovered {[h.get_workflow_id() for h in handles]}"
        )
