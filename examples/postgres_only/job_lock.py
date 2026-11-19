"""Postgres-only mutual exclusion for a logical job, for use inside a DBOS step.

DBOS stops a superseded execution from recording results, but not from finishing
the step it is in. If a job is handed off while its old worker is still alive
(recovery of a stalled machine, a workflow timeout, cancel then resume), two
copies of the step body can run at once. Wrap the body in JobLock to prevent it:

    @DBOS.step()
    def sync_orders() -> None:
        with JobLock(DSN, "sync_orders") as lock:
            lock.guarded(lambda conn: conn.execute("UPDATE ..."))

The lock is a session-level advisory lock on a dedicated connection:
  - it is held for as long as that database session lives, even if this process
    is frozen, so a second copy waits instead of overlapping;
  - it is released automatically when the session dies (process death, network
    loss detected by keepalives, pg_terminate_backend).

If the session dies while this process is paused, the process does not know it
lost the lock. Two tools for that:
  - check():   raises LockLost if the session no longer holds the lock. Narrows
               the window, but a pause between check and side effect still races.
  - guarded(): runs SQL on the lock connection itself, in a transaction. If the
               session is gone the statement fails, so a stale holder cannot write.
               This is airtight only for writes to the same Postgres server.

Do not use through PgBouncer in transaction-pooling mode: session locks need a
direct or session-pooled connection.
"""

import hashlib
import time
from typing import Any, Callable, Optional, TypeVar

import psycopg

T = TypeVar("T")


class LockLost(Exception):
    """The lock session died or no longer holds the lock."""


class LockBusy(Exception):
    """Another holder has the lock and waiting was disabled or timed out."""


def key_for(name: str) -> int:
    digest = hashlib.sha256(("joblock:" + name).encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


class JobLock:
    def __init__(
        self,
        dsn: str,
        name: str,
        *,
        wait: bool = True,
        poll_sec: float = 0.5,
        timeout_sec: Optional[float] = None,
    ) -> None:
        self.dsn, self.name, self.key = dsn, name, key_for(name)
        self.wait, self.poll_sec, self.timeout_sec = wait, poll_sec, timeout_sec
        self.conn: Any = None

    def __enter__(self) -> "JobLock":
        # Keepalives let the server notice a vanished client and drop the session.
        self.conn = psycopg.connect(
            self.dsn,
            autocommit=True,
            keepalives=1,
            keepalives_idle=5,
            keepalives_interval=2,
            keepalives_count=3,
        )
        start = time.time()
        while True:
            row = self.conn.execute(
                "SELECT pg_try_advisory_lock(%s)", (self.key,)
            ).fetchone()
            if row[0]:
                return self
            timed_out = (
                self.timeout_sec is not None
                and time.time() - start > self.timeout_sec
            )
            if not self.wait or timed_out:
                self.conn.close()
                raise LockBusy(self.name)
            time.sleep(self.poll_sec)

    def check(self) -> None:
        try:
            row = self.conn.execute(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' "
                "AND pid = pg_backend_pid() AND granted "
                "AND ((classid::bigint << 32) | objid::bigint) = %s",
                (self.key,),
            ).fetchone()
        except psycopg.Error as e:
            raise LockLost(f"{self.name}: lock connection dead") from e
        if row[0] < 1:
            raise LockLost(f"{self.name}: session no longer holds the lock")

    def guarded(self, fn: Callable[[Any], T]) -> T:
        """Run fn(conn) in a transaction on the lock connection."""
        try:
            with self.conn.transaction():
                return fn(self.conn)
        except psycopg.OperationalError as e:
            raise LockLost(f"{self.name}: lock connection dead") from e

    def __exit__(self, *exc: Any) -> bool:
        try:
            self.conn.execute("SELECT pg_advisory_unlock(%s)", (self.key,))
            self.conn.close()
        except Exception:
            pass
        return False
