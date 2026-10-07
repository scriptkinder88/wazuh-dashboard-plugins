#!/usr/bin/env python3
"""ciscat-scheduler.py - MANAGER side, run by cron every 5 minutes.

Replaces ciscat-orchestrator.sh. On each tick it:
  1. publishes the benchmark sheets and OS list for the dashboard (at most hourly);
  2. applies pending dashboard requests ("apply": regenerate and publish the policies);
  3. starts the schedule jobs that are due, each as a separate `ciscat-fleet.py trigger`, so a
     run in waves does not block later ticks;
  4. records next runs, missed runs and its heartbeat in ciscat-status;
  5. once a day, has the fleet record how many agents of each OS group were assessed
     (ciscat-history, the coverage trend of the dashboard).
Data contract: CONTRACT.md. Nothing here takes a command from the lists: a list can only choose
among fixed actions and validated parameters.
"""
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta

BIN_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BIN_DIR)
import ciscat_schedule as schedule  # noqa: E402
import ciscat_store as store  # noqa: E402

LISTS_DIR = os.environ.get("CISCAT_LISTS_DIR", store.LISTS_DIR)
RUN_DIR = os.environ.get("CISCAT_RUN_DIR", "/opt/ciscat/run")
LOG_DIR = os.environ.get("CISCAT_LOG_DIR", "/opt/ciscat/log")
FLEET = os.environ.get("CISCAT_FLEET_CMD", os.path.join(BIN_DIR, "ciscat-fleet.py"))
TICK = timedelta(minutes=5)
SYNC_EVERY = timedelta(hours=1)
RUNNING_LIMIT = timedelta(hours=12)  # a job reported running longer than this is presumed dead
KEEP_PROCESSED = 200
FMT = "%Y-%m-%dT%H:%M:%S"
SCHEDULED_KEY = re.compile(r"^job-j[0-9a-f]{12}$")
KEEP_RUNS = 20


def log(msg):
    print("{0} {1}".format(datetime.now().strftime(FMT), msg), flush=True)


def parse(value):
    try:
        return datetime.strptime((value or "")[:19], FMT)
    except ValueError:
        return None


def fleet(*args):
    p = subprocess.run([sys.executable, FLEET] + list(args), stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT)
    for line in p.stdout.decode(errors="replace").splitlines()[-40:]:
        log("  | " + line)
    return p.returncode


def start_trigger(key, job):
    os.makedirs(LOG_DIR, exist_ok=True)
    out = open(os.path.join(LOG_DIR, "ciscat-job-{0}.log".format(key)), "a")
    cmd = [sys.executable, FLEET, "trigger", "--targets", ",".join(job["targets"]),
           "--wave-size", str(job["wave_size"]), "--wave-pause", str(job["wave_pause_s"]),
           "--job", key]
    subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                     start_new_session=True, close_fds=True)
    return cmd


def tick(now):
    status, errors = store.read_list(store.STATUS, LISTS_DIR)
    for e in errors:
        log("WARNING status: " + e)
    last_tick = parse(status.get("scheduler", {}).get("last_tick")) or now - TICK
    if last_tick > now:  # clock moved back
        last_tick = now - TICK
    patches, remove = {}, []

    # 1. dashboard data
    last_sync = parse(status.get("scheduler", {}).get("last_sync"))
    synced = None
    if not last_sync or now - last_sync >= SYNC_EVERY:
        log("sync: benchmark sheets and OS list")
        if fleet("sync") == 0:
            synced = now.strftime(FMT)

    # 1b. daily coverage snapshot (the first tick of each day)
    today = now.strftime("%Y-%m-%d")
    history = None
    if status.get("scheduler", {}).get("last_history") != today:
        log("history: coverage of {0}".format(today))
        if fleet("history", "--day", today) == 0:
            history = today

    # 2. requests (several pending applies run once)
    raw, errors = store.read_list(store.REQUESTS, LISTS_DIR)
    requests, verrors = store.validate_records(raw, store.validate_request)
    for e in errors + verrors:
        log("WARNING request rejected: " + e)
    processed = list(status.get("requests", {}).get("processed", []))
    pending = sorted(k for k in requests if k not in processed)
    applies = [k for k in pending if requests[k]["action"] == "apply"]
    if applies:
        log("apply requested by {0} ({1} request(s))".format(
            requests[applies[-1]].get("requested_by") or "?", len(applies)))
        rc = fleet("apply", "--request", applies[-1])
        log("apply finished rc={0}".format(rc))
    # "Run now" requests start after a pending apply, so they assess the new policies
    for key in (k for k in pending if requests[k]["action"] == "run"):
        req = requests[key]
        log("run now requested by {0}: start {1}".format(
            req.get("requested_by") or "?", " ".join(start_trigger(key, req)[2:])))
        patches["job-" + key] = {"state": "starting", "last_run": now.strftime(FMT),
                                 "label": req.get("label") or "Run now",
                                 "requested_by": req.get("requested_by", "")}
    if pending:
        processed = (processed + pending)[-KEEP_PROCESSED:]
        patches["requests"] = {"processed": processed}

    # 3. jobs
    raw, errors = store.read_list(store.SCHEDULE, LISTS_DIR)
    jobs, verrors = store.validate_records(raw, store.validate_job)
    for e in errors + verrors:
        log("WARNING job rejected: " + e)
    for key, job in sorted(jobs.items()):
        skey = "job-" + key
        run, missed = schedule.due(job, last_tick, now)
        patch = {}
        if missed:
            log("job {0}: missed {1}".format(key, ", ".join(t.strftime("%Y-%m-%d %H:%M") for t in missed)))
            patch["missed"] = (status.get(skey, {}).get("missed", []) +
                               [t.strftime("%Y-%m-%dT%H:%M") for t in missed])[-20:]
        if run:
            cur = status.get(skey, {})
            started = parse(cur.get("last_run"))
            if cur.get("state") == "running" and started and now - started < RUNNING_LIMIT:
                log("job {0}: still running since {1}, this run is skipped".format(key, cur["last_run"]))
                patch["overlap"] = now.strftime(FMT)
            else:
                log("job {0} ({1}): start {2}".format(key, job.get("label") or job["type"],
                                                      " ".join(start_trigger(key, job)[2:])))
                patch.update({"state": "starting", "last_run": now.strftime(FMT)})
        nxt = schedule.next_run(job, now) if job["enabled"] else None
        patch["next_run"] = nxt.strftime("%Y-%m-%dT%H:%M") if nxt else ""
        patches[skey] = patch
    # status of deleted jobs goes; "Run now" results keep the most recent KEEP_RUNS
    remove = [k for k in status if SCHEDULED_KEY.match(k) and k[4:] not in jobs]
    runs = sorted((k for k in status if k.startswith("job-r")),
                  key=lambda k: status[k].get("last_run", ""), reverse=True)
    remove += runs[KEEP_RUNS:]

    sched = {"last_tick": now.strftime(FMT), "jobs": len(jobs),
             "tz": time.strftime("%Z"), "utc_offset": time.strftime("%z")}
    if synced:
        sched["last_sync"] = synced
    if history:
        sched["last_history"] = history
    patches["scheduler"] = sched
    store.update_records(store.STATUS, patches, LISTS_DIR, RUN_DIR, remove=remove)


def main():
    import fcntl
    os.makedirs(RUN_DIR, exist_ok=True)
    lock = open(os.path.join(RUN_DIR, "scheduler.lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        log("previous tick still running; skipping")
        return 0
    now = parse(os.environ.get("CISCAT_NOW", "")) or datetime.now().replace(microsecond=0)
    tick(now)
    return 0


if __name__ == "__main__":
    sys.exit(main())
