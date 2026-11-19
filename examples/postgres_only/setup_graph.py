"""Toy: a setup graph with tasks pinned to worker roles, then repeating jobs
that start as soon as *their own* prerequisites are done.  Postgres only.

Run one process per machine:   DBOS_URL=postgresql://... python setup_graph.py db   (and: ... search)
"""
import os, sys, time
from datetime import datetime
from typing import Any, Dict, List

from dbos import DBOS, SetWorkflowID

ROLE, ENV = sys.argv[1], "prod"

# ---- the whole thing, declared as data ------------------------------------
SETUP = {  # task -> which worker role runs it, and what must succeed first
    "create_schema": {"on": "db",     "needs": []},
    "seed":          {"on": "db",     "needs": ["create_schema"]},
    "build_index":   {"on": "search", "needs": ["seed"]},
    "warm_cache":    {"on": "search", "needs": ["build_index"]},
}
REPEATING = {  # job -> role, prerequisites, cron (6 fields, seconds first)
    "sync_orders":   {"on": "db",     "needs": ["seed"],        "cron": "*/2 * * * * *"},
    "refresh_index": {"on": "search", "needs": ["build_index"], "cron": "*/3 * * * * *"},
}
ROLES = sorted({v["on"] for v in {**SETUP, **REPEATING}.values()})

DBOS(config={
    "name": "toy",
    "system_database_url": os.environ["DBOS_URL"],
    "executor_id": f"{ROLE}-{os.environ.get('HOSTNAME', '1')}",  # unique + stable per machine
    "application_version": "v1",                                  # pinned: redeploys don't strand work
})
DBOS.listen_queues([ROLE])  # this machine only takes jobs for its role


def say(msg: str) -> None:
    print(f"{time.strftime('%H:%M:%S')} [{ROLE}] {msg}", flush=True)


# ---- task bodies (must be idempotent: a crash mid-task re-runs that task) --
@DBOS.step()
def do_task(task: str) -> None:
    say(f"setup  {task} ...")
    time.sleep(3 if task == "warm_cache" else 1)


@DBOS.workflow()
def run_task(task: str) -> str:
    do_task(task)
    return task


@DBOS.step()
def do_job(job: str) -> None:
    say(f"repeat {job}")


@DBOS.workflow()
def run_job(scheduled_at: datetime, job: str) -> None:  # signature the scheduler requires
    do_job(job)


# ---- the runner: walks the graph, routes tasks, switches repeating jobs on -
@DBOS.workflow()
def run_setup(setup: Dict[str, Any], repeating: Dict[str, Any]) -> List[str]:
    done: List[str] = []
    started: set = set()
    scheduled: set = set()
    running: Dict[str, Any] = {}
    while True:
        for job in sorted(repeating):  # prerequisites met -> start the cron
            if job not in scheduled and set(repeating[job]["needs"]) <= set(done):
                scheduled.add(job)
                try:
                    DBOS.create_schedule(schedule_name=f"{ENV}:{job}", workflow_fn=run_job,
                                         schedule=repeating[job]["cron"], context=job,
                                         queue_name=repeating[job]["on"])
                except Exception:  # already exists (e.g. after a rewind)
                    pass
        for task in sorted(setup):     # prerequisites met -> enqueue on its role's queue
            if task not in started and set(setup[task]["needs"]) <= set(done):
                started.add(task)
                with SetWorkflowID(f"setup:{ENV}:{task}"):  # one run per env, ever
                    h = DBOS.enqueue_workflow(setup[task]["on"], run_task, task)
                running[h.workflow_id] = h
        if not running:
            return done
        h = DBOS.wait_first(list(running.values()))
        del running[h.workflow_id]
        done.append(h.get_result())  # a failed task raises here: dependents never start


if __name__ == "__main__":
    DBOS.launch()
    for role in ROLES:
        DBOS.register_queue(role)  # queues are database rows; safe from every machine
    with SetWorkflowID(f"setup:{ENV}:runner:v1"):  # every machine asks; exactly one runner runs
        handle = DBOS.start_workflow(run_setup, SETUP, REPEATING)
    say(f"setup finished: {handle.get_result()}")
    time.sleep(float(os.environ.get("RUN_FOR", "1e9")))
    DBOS.destroy()
