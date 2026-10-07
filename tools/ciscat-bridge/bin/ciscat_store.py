"""Shared store for the CIS-CAT bridge: records kept in Wazuh CDB list files.

The dashboard reads and writes these files through the Wazuh API (/lists/files), the master
reads and writes them on disk. Wazuh 4.x only accepts list values without ':' and '"'
(validate_cdb_list), so every value is compact JSON encoded as unpadded base64url.

Each file has one writer:
  dashboard  ciscat-exclusions, ciscat-schedule, ciscat-requests
  master     ciscat-status, ciscat-oskeys, ciscat-bench-<os_key>
so neither side overwrites records the other one just wrote.

Stdlib only; runs on Python 3.6+.
"""
import base64
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime

LISTS_DIR = "/var/ossec/etc/lists"
EXCLUSIONS = "ciscat-exclusions"
SCHEDULE = "ciscat-schedule"
REQUESTS = "ciscat-requests"
STATUS = "ciscat-status"
OSKEYS = "ciscat-oskeys"
TARGETS = "ciscat-targets"
HISTORY = "ciscat-history"
BENCH_PREFIX = "ciscat-bench-"
SCHEMA_VERSION = 1

KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
OS_KEY_RE = re.compile(r"^[a-z0-9_]{1,64}$")
RULE_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){0,9}$")
ROLE_RE = re.compile(r"^[A-Za-z0-9_ -]{0,64}$")
# Agent names and Wazuh group names.
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,255}$")
TIME_RE = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")
AT_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-5][0-9]$")

SCOPES = ("os", "global", "host", "app_group")
LEVELS = ("L1", "L2", "NG", "ALL")
JOB_TYPES = ("once", "monthly", "weekly")
REQUEST_ACTIONS = ("apply", "run")
# waves of a run when the schedule (or the command line) does not say
DEFAULT_WAVE_SIZE = 50
DEFAULT_WAVE_PAUSE_S = 300


class StoreError(ValueError):
    """A record or a list file that does not follow the contract."""


# --- encoding --------------------------------------------------------------------------------

def encode(obj):
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def decode(value):
    if not re.match(r"^[A-Za-z0-9_-]*$", value or ""):
        raise StoreError("value is not base64url")
    data = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    obj = json.loads(data.decode("utf-8"))
    if not isinstance(obj, dict):
        raise StoreError("value is not a JSON object")
    return obj


def parse_list(text):
    """Return ({key: record}, [errors]). Lines that cannot be decoded are reported, not kept."""
    records, errors = {}, []
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        key, sep, value = line.partition(":")
        if not sep or not KEY_RE.match(key):
            errors.append("line {}: invalid key".format(lineno))
            continue
        try:
            records[key] = decode(value.strip())
        except (StoreError, ValueError) as exc:
            errors.append("line {}: {}".format(lineno, exc))
    return records, errors


def render_list(records):
    lines = []
    for key in sorted(records):
        if not KEY_RE.match(key):
            raise StoreError("invalid key: {!r}".format(key))
        lines.append("{}:{}".format(key, encode(records[key])))
    return "\n".join(lines) + ("\n" if lines else "")


def list_path(name, lists_dir=LISTS_DIR):
    if not KEY_RE.match(name) or not name.startswith("ciscat-"):
        raise StoreError("invalid list name: {!r}".format(name))
    return os.path.join(lists_dir, name)


def bench_list_name(os_key):
    if not OS_KEY_RE.match(os_key or ""):
        raise StoreError("invalid os_key: {!r}".format(os_key))
    return BENCH_PREFIX + os_key


def read_list(name, lists_dir=LISTS_DIR):
    path = list_path(name, lists_dir)
    if not os.path.exists(path):
        return {}, []
    with open(path, encoding="utf-8") as f:
        return parse_list(f.read())


def write_list(name, records, lists_dir=LISTS_DIR):
    """Atomic write with the owner and mode Wazuh gives list files (wazuh:wazuh 0660)."""
    path = list_path(name, lists_dir)
    content = render_list(records)
    fd, tmp = tempfile.mkstemp(prefix=".ciscat-", dir=lists_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(tmp, 0o660)
        if os.geteuid() == 0:
            try:
                import grp
                import pwd
                os.chown(tmp, pwd.getpwnam("wazuh").pw_uid, grp.getgrnam("wazuh").gr_gid)
            except KeyError:
                pass
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
    return path


def update_records(name, patches, lists_dir=LISTS_DIR, lock_dir="/opt/ciscat/run", remove=()):
    """Merge {key: fields} into a master-owned list under an exclusive lock.

    Several master processes (scheduler, apply, triggers running in waves) update ciscat-status;
    the lock keeps one from losing another's write. A patch value of None removes the field.
    """
    import fcntl
    os.makedirs(lock_dir, exist_ok=True)
    with open(os.path.join(lock_dir, name + ".lock"), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        records, _ = read_list(name, lists_dir)
        for key, patch in patches.items():
            rec = dict(records.get(key, {}))
            for field, value in patch.items():
                if value is None:
                    rec.pop(field, None)
                else:
                    rec[field] = value
            rec["v"] = SCHEMA_VERSION
            records[key] = rec
        for key in remove:
            records.pop(key, None)
        write_list(name, records, lists_dir)
        return records


# --- record validation ------------------------------------------------------------------------

def _text(rec, field, limit, required=False, default=""):
    value = rec.get(field, default)
    if value is None:
        value = default
    if not isinstance(value, str):
        raise StoreError("{}: text expected".format(field))
    value = " ".join(value.split())
    if len(value) > limit:
        raise StoreError("{}: longer than {} characters".format(field, limit))
    if required and not value:
        raise StoreError("{}: required".format(field))
    return value


def _int(rec, field, low, high, default=None):
    value = rec.get(field, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise StoreError("{}: integer {}..{} expected".format(field, low, high))
    return value


def exclusion_key(rec):
    ident = "|".join([rec["os_key"], rec["scope"], rec["scope_value"].lower(), rec["level"],
                      rec["role"].lower(), rec["rule"]])
    return "e" + hashlib.sha1(ident.encode("utf-8")).hexdigest()[:16]


def validate_exclusion(rec):
    """Normalized copy of an exclusion record, or StoreError."""
    if not isinstance(rec, dict):
        raise StoreError("record must be an object")
    out = {"v": SCHEMA_VERSION}
    out["os_key"] = _text(rec, "os_key", 64, required=True)
    if not OS_KEY_RE.match(out["os_key"]):
        raise StoreError("os_key: invalid")
    out["scope"] = _text(rec, "scope", 16, required=True).lower()
    if out["scope"] not in SCOPES:
        raise StoreError("scope: one of {}".format(", ".join(SCOPES)))
    value = _text(rec, "scope_value", 255)
    if out["scope"] == "os":
        value = out["os_key"]
    elif out["scope"] == "global":
        value = "all"
    elif not NAME_RE.match(value):
        raise StoreError("scope_value: agent or group name expected")
    out["scope_value"] = value
    out["level"] = _text(rec, "level", 3, default="ALL").upper() or "ALL"
    if out["level"] not in LEVELS:
        raise StoreError("level: one of {}".format(", ".join(LEVELS)))
    out["role"] = _text(rec, "role", 64)
    if not ROLE_RE.match(out["role"]):
        raise StoreError("role: invalid")
    out["rule"] = _text(rec, "rule", 64, required=True)
    if not RULE_RE.match(out["rule"]):
        raise StoreError("rule: CIS recommendation number expected (e.g. 1.1.1)")
    out["reason"] = _text(rec, "reason", 500) or "n/a"
    out["ticket"] = _text(rec, "ticket", 128) or "n/a"
    out["owner"] = _text(rec, "owner", 128) or "n/a"
    out["updated_by"] = _text(rec, "updated_by", 128)
    out["updated_at"] = _text(rec, "updated_at", 40)
    return out


def validate_exclusions(records):
    """({key: record} valid and keyed as the contract says, [errors])."""
    valid, errors = {}, []
    for key, rec in records.items():
        if key.startswith("_"):  # metadata / placeholder, not a record
            continue
        try:
            norm = validate_exclusion(rec)
        except StoreError as exc:
            errors.append("{}: {}".format(key, exc))
            continue
        expected = exclusion_key(norm)
        if key != expected:
            errors.append("{}: key does not match the record (expected {})".format(key, expected))
            continue
        valid[key] = norm
    return valid, errors


def validate_job(rec):
    if not isinstance(rec, dict):
        raise StoreError("record must be an object")
    out = {"v": SCHEMA_VERSION}
    out["type"] = _text(rec, "type", 16, required=True)
    if out["type"] not in JOB_TYPES:
        raise StoreError("type: one of {}".format(", ".join(JOB_TYPES)))
    if out["type"] == "once":
        out["at"] = _text(rec, "at", 16, required=True)
        if not AT_RE.match(out["at"]):
            raise StoreError("at: YYYY-MM-DDTHH:MM expected (master local time)")
        try:
            datetime.strptime(out["at"], "%Y-%m-%dT%H:%M")
        except ValueError:
            raise StoreError("at: not a valid date")
    else:
        out["time"] = _text(rec, "time", 5, required=True)
        if not TIME_RE.match(out["time"]):
            raise StoreError("time: HH:MM expected")
        if out["type"] == "monthly":
            # 1..31 = day of month (short months use their last day); -1..-28 = days from the end
            day = rec.get("day")
            if isinstance(day, bool) or not isinstance(day, int) or not (
                    1 <= day <= 31 or -28 <= day <= -1):
                raise StoreError("day: 1..31, or -1..-28 counted from the end of the month")
            out["day"] = day
        else:
            out["weekday"] = _int(rec, "weekday", 0, 6)  # 0 = Monday
    targets = rec.get("targets", ["*"])
    if not isinstance(targets, list) or not targets or len(targets) > 64:
        raise StoreError("targets: non-empty list expected")
    for t in targets:
        if t != "*" and not (isinstance(t, str) and OS_KEY_RE.match(t)):
            raise StoreError("targets: os keys or '*' expected")
    out["targets"] = sorted(set(targets))
    out["wave_size"] = _int(rec, "wave_size", 1, 100000, default=DEFAULT_WAVE_SIZE)
    out["wave_pause_s"] = _int(rec, "wave_pause_s", 0, 86400, default=DEFAULT_WAVE_PAUSE_S)
    enabled = rec.get("enabled", True)
    if not isinstance(enabled, bool):
        raise StoreError("enabled: true/false expected")
    out["enabled"] = enabled
    out["label"] = _text(rec, "label", 80)
    out["created_by"] = _text(rec, "created_by", 128)
    out["created_at"] = _text(rec, "created_at", 40)
    return out


def validate_request(rec):
    if not isinstance(rec, dict):
        raise StoreError("record must be an object")
    out = {"v": SCHEMA_VERSION}
    out["action"] = _text(rec, "action", 16, required=True)
    if out["action"] not in REQUEST_ACTIONS:
        raise StoreError("action: one of {}".format(", ".join(REQUEST_ACTIONS)))
    if out["action"] == "run":  # "Run now": same parameters as a job, no time
        job = validate_job(dict(rec, type="once", at="2000-01-01T00:00"))
        out.update({k: job[k] for k in ("targets", "wave_size", "wave_pause_s", "label")})
    out["requested_by"] = _text(rec, "requested_by", 128)
    out["requested_at"] = _text(rec, "requested_at", 40)
    return out


def validate_target(rec):
    """Wazuh group an OS (benchmark) applies to, chosen in the dashboard. Keyed by os key."""
    if not isinstance(rec, dict):
        raise StoreError("record must be an object")
    out = {"v": SCHEMA_VERSION}
    out["group"] = _text(rec, "group", 255, required=True)
    if not NAME_RE.match(out["group"]):
        raise StoreError("group: Wazuh group name expected")
    out["updated_by"] = _text(rec, "updated_by", 128)
    out["updated_at"] = _text(rec, "updated_at", 40)
    return out


def validate_targets(records):
    """({os_key: record}, [errors])."""
    valid, errors = {}, []
    for key, rec in records.items():
        if key.startswith("_"):
            continue
        if not OS_KEY_RE.match(key):
            errors.append("{}: os key expected".format(key))
            continue
        try:
            valid[key] = validate_target(rec)
        except StoreError as exc:
            errors.append("{}: {}".format(key, exc))
    return valid, errors


def validate_records(records, validator):
    valid, errors = {}, []
    for key, rec in records.items():
        if key.startswith("_"):  # metadata / placeholder, not a record
            continue
        try:
            valid[key] = validator(rec)
        except StoreError as exc:
            errors.append("{}: {}".format(key, exc))
    return valid, errors


# --- CSV bridge for csv_to_custom_xccdf.py ----------------------------------------------------

CSV_HEADER = ["scope", "scope_value", "level", "role", "rule", "reason", "ticket", "owner"]


def exclusions_to_csv_rows(exclusions, os_key):
    """Rows (header first) of the exclusions of one OS, in the format csv_to_custom_xccdf reads."""
    rows = [list(CSV_HEADER)]
    chosen = [r for r in exclusions.values() if r["os_key"] == os_key]
    chosen.sort(key=lambda r: (r["scope"], r["scope_value"].lower(), r["level"],
                               [int(p) for p in r["rule"].split(".")]))
    for r in chosen:
        rows.append([r["scope"], r["scope_value"], r["level"].lower(), r["role"], r["rule"],
                     r["reason"], r["ticket"], r["owner"]])
    return rows


def exclusions_from_csv_rows(rows, os_key, updated_by="migration", updated_at=""):
    """Records from an existing exclusions CSV (header or legacy positional layout)."""
    rows = [r for r in rows if r and not r[0].lstrip().startswith("#")]
    if not rows:
        return {}, []
    header = [h.strip().lower() for h in rows[0]]
    if header[:3] == ["scope", "scope_value", "level"]:
        idx = {name: i for i, name in enumerate(header)}
        body = rows[1:]
    else:
        idx = {"scope": 0, "scope_value": 1, "level": 2, "rule": 3,
               "reason": 4, "ticket": 5, "owner": 6}
        body = rows
    records, errors = {}, []
    for n, raw in enumerate(body, 1):
        def cell(name):
            i = idx.get(name)
            return raw[i].strip() if i is not None and i < len(raw) else ""
        scope, values = cell("scope").lower(), [cell("scope_value")]
        # scopes written by the old HTML exclusion composer
        if scope == "group":
            scope = "app_group"
        elif scope == "host_list":
            scope, values = "host", [v for v in re.split(r"[\s,;|]+", values[0]) if v]
        for value in values or [""]:
            rec = {"os_key": os_key, "scope": scope, "scope_value": value,
                   "level": cell("level") or "ALL", "role": cell("role"), "rule": cell("rule"),
                   "reason": cell("reason"), "ticket": cell("ticket"), "owner": cell("owner"),
                   "updated_by": updated_by, "updated_at": updated_at}
            try:
                norm = validate_exclusion(rec)
            except StoreError as exc:
                errors.append("row {}: {}".format(n, exc))
                continue
            records[exclusion_key(norm)] = norm
    return records, errors
