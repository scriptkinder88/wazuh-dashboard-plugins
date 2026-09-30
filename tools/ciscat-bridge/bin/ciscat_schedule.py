"""When CIS-CAT jobs run. Pure functions over naive local datetimes (master local time).

Job types (validated by ciscat_store.validate_job):
  once     at "YYYY-MM-DDTHH:MM"
  monthly  day 1..31 (a short month uses its last day) or -1..-28 (-1 = last day), time "HH:MM"
  weekly   weekday 0..6 (0 = Monday), time "HH:MM"
"""
import calendar
from datetime import datetime, timedelta

# Occurrences missed for longer than this (scheduler down) are reported, not run.
CATCH_UP = timedelta(hours=6)


def _at(value):
    return datetime.strptime(value, "%Y-%m-%dT%H:%M")


def _hm(job):
    h, m = job["time"].split(":")
    return int(h), int(m)


def _month_occurrence(job, year, month):
    last = calendar.monthrange(year, month)[1]
    day = job["day"]
    day = min(day, last) if day > 0 else last + day + 1
    h, m = _hm(job)
    return datetime(year, month, day, h, m)


def occurrences(job, start, end):
    """Scheduled times t with start < t <= end, oldest first."""
    if end <= start:
        return []
    t = job["type"]
    if t == "once":
        at = _at(job["at"])
        return [at] if start < at <= end else []
    out = []
    if t == "monthly":
        y, mo = start.year, start.month
        while (y, mo) <= (end.year, end.month):
            occ = _month_occurrence(job, y, mo)
            if start < occ <= end:
                out.append(occ)
            y, mo = (y + 1, 1) if mo == 12 else (y, mo + 1)
        return out
    if t == "weekly":
        h, m = _hm(job)
        day = start.replace(hour=0, minute=0, second=0, microsecond=0)
        day += timedelta(days=(job["weekday"] - day.weekday()) % 7)
        while True:
            occ = day.replace(hour=h, minute=m)
            if occ > end:
                return out
            if occ > start:
                out.append(occ)
            day += timedelta(days=7)
    raise ValueError("unknown job type: {}".format(t))


def next_run(job, after):
    """First scheduled time after `after`, or None (a past one-shot)."""
    if job["type"] == "once":
        at = _at(job["at"])
        return at if at > after else None
    horizon = after + timedelta(days=62 if job["type"] == "monthly" else 8)
    occ = occurrences(job, after, horizon)
    return occ[0] if occ else None


def due(job, last_tick, now):
    """(run_now, missed): whether to run at this tick, and the occurrences that are too old.

    Several occurrences inside one tick window run once. Occurrences older than CATCH_UP (the
    scheduler was not running) are not run late: they are returned so they can be reported.
    """
    if not job.get("enabled", True):
        return False, []
    occ = occurrences(job, last_tick, now)
    recent = [t for t in occ if now - t <= CATCH_UP]
    missed = [t for t in occ if now - t > CATCH_UP]
    return bool(recent), missed
