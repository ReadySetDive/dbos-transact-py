#!/usr/bin/env python3
"""Time-based retention for a DBOS 3.6.0 system database using ONLY public MIT-core APIs
(DBOSClient.list_workflows / DBOSClient.delete_workflows).  No dbos-enterprise, no Conductor.

    prune_workflows.py --url-file /run/credentials/pruner_url --older-than-days 30 --dry-run
    prune_workflows.py --url-file ... --older-than-days 30 [--batch 500] [--max-seconds 3000]

What it deletes: workflows in a terminal state (SUCCESS, ERROR, CANCELLED,
MAX_RECOVERY_ATTEMPTS_EXCEEDED) whose completion time (completed_at, else updated_at) is older
than the cut-off, together with all their rows in workflow_input, workflow_output,
operation_outputs (deleted explicitly by dbos) and notifications, workflow_events,
workflow_events_history, streams (ON DELETE CASCADE).

What it never deletes:
  * anything not terminal (PENDING / ENQUEUED / DELAYED / SUSPENDED);
  * a terminal workflow whose PARENT workflow still exists and is not terminal -- the parent
    would need the child's recorded result if it is recovered or replayed.

Safety properties (tested, see HARDENING.md control 9):
  * payloads are never deserialized (load_input=False, load_output=False), so this job cannot be
    made to unpickle anything and never sees business data;
  * runs with a role that has only SELECT + DELETE on the DBOS schema (dbos_pruner);
  * each batch is one short transaction issued by dbos itself; safe to run while the
    application is live and safe to run from several hosts at once (double deletes are no-ops).

Exit status: 0 ok, 1 error, 3 stopped on --max-seconds with work remaining.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

TERMINAL = ["SUCCESS", "ERROR", "CANCELLED", "MAX_RECOVERY_ATTEMPTS_EXCEEDED"]


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--url-file", help="file containing the system database URL (preferred)")
    src.add_argument("--url", help="system database URL (visible in the process list; testing only)")
    age = ap.add_mutually_exclusive_group(required=True)
    age.add_argument("--older-than-days", type=float)
    age.add_argument("--older-than-seconds", type=float, help="for testing")
    ap.add_argument("--schema", default="dbos")
    ap.add_argument("--batch", type=int, default=500, help="workflows per delete transaction")
    ap.add_argument("--max-seconds", type=float, default=0, help="stop after this long (0 = no limit)")
    ap.add_argument("--sleep", type=float, default=0.0, help="pause between batches (throttle)")
    ap.add_argument("--application-name", default=None, help="only this application's workflows")
    ap.add_argument("--dry-run", action="store_true", help="report what would be deleted; delete nothing")
    ap.add_argument("--json-serializer", action="store_true",
                    help="construct the client with StrictJSONSerializer (payloads are not read either way)")
    args = ap.parse_args(argv)

    if args.url_file:
        with open(args.url_file, "r", encoding="utf-8") as fh:
            url = fh.read().strip()
    else:
        url = args.url

    import logging

    from dbos import DBOSClient

    logging.getLogger("dbos").setLevel(logging.WARNING)

    seconds = args.older_than_seconds if args.older_than_seconds is not None else args.older_than_days * 86400
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    cutoff_ms = int(cutoff.timestamp() * 1000)
    cutoff_iso = cutoff.isoformat()

    kwargs: Dict[str, object] = {"system_database_url": url, "dbos_system_schema": args.schema,
                                 "system_database_pool_size": 2}
    if args.json_serializer:
        from json_serializer import StrictJSONSerializer

        kwargs["serializer"] = StrictJSONSerializer()
    client = DBOSClient(**kwargs)  # type: ignore[arg-type]

    t0 = time.monotonic()
    deleted = skipped_parent = scanned = 0
    by_status: Dict[str, int] = {}
    skip_ids: set = set()  # held back this run (active parent); excluded via paging offset
    rc = 0
    try:
        offset = 0
        while True:
            if args.max_seconds and time.monotonic() - t0 > args.max_seconds:
                rc = 3
                break
            # created-before the cut-off is implied by completed-before it; `end_time` lets the
            # query use the created_at index and bounds the scan.
            page = client.list_workflows(
                status=TERMINAL,
                end_time=cutoff_iso,
                limit=args.batch,
                offset=offset,
                sort_desc=False,
                load_input=False,
                load_output=False,
                application_name=args.application_name,
            )
            if not page:
                break
            scanned += len(page)
            candidates = []
            for w in page:
                done_ms = w.completed_at if w.completed_at is not None else w.updated_at
                if done_ms is None or done_ms >= cutoff_ms:
                    continue
                candidates.append(w)
            # hold back children of parents that are still active
            parent_ids = sorted({w.parent_workflow_id for w in candidates if w.parent_workflow_id})
            active_parents = set()
            for i in range(0, len(parent_ids), 500):
                for p in client.list_workflows(workflow_ids=parent_ids[i:i + 500],
                                               load_input=False, load_output=False):
                    if p.status not in TERMINAL:
                        active_parents.add(p.workflow_id)
            ids = []
            for w in candidates:
                if w.parent_workflow_id in active_parents:
                    if w.workflow_id not in skip_ids:
                        skip_ids.add(w.workflow_id)
                        skipped_parent += 1
                    continue
                ids.append(w.workflow_id)
                by_status[w.status] = by_status.get(w.status, 0) + 1
            if args.dry_run:
                deleted += len(ids)
                offset += len(page)
            else:
                if ids:
                    client.delete_workflows(ids, delete_children=False)
                    deleted += len(ids)
                # rows we did not delete stay in the result set: page past them
                offset += len(page) - len(ids)
            if args.sleep:
                time.sleep(args.sleep)
    except Exception as e:  # never print payloads; dbos errors here carry SQL text only
        print(f"prune_workflows: ERROR {type(e).__name__}: {str(e).splitlines()[0][:300]}", file=sys.stderr)
        rc = 1
    finally:
        client.destroy()
    dt = time.monotonic() - t0
    verb = "would delete" if args.dry_run else "deleted"
    print(f"prune_workflows: cutoff={cutoff_iso} scanned={scanned} {verb}={deleted} "
          f"held_back_active_parent={skipped_parent} by_status={by_status} "
          f"elapsed={dt:.1f}s rate={deleted / dt if dt > 0 else 0:.0f}/s"
          + (" (stopped on --max-seconds; work remains)" if rc == 3 else ""))
    return rc


if __name__ == "__main__":
    sys.exit(main())
