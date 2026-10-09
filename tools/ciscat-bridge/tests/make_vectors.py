"""Writes the shared contract test vectors checked by both the Python and the TypeScript tests.

    python3 tools/ciscat-bridge/tests/make_vectors.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "bin"))
import ciscat_store as s  # noqa: E402

OUT = os.path.join(HERE, "..", "..", "..", "plugins", "main", "common", "ciscat",
                   "contract-vectors.json")


def build():
    exclusions = [
        {"os_key": "rhel7", "scope": "os", "scope_value": "", "level": "L1", "role": "Server",
         "rule": "1.1.1.1", "reason": 'Needed: "cramfs" | see KB:1, è', "ticket": "CHG-1"},
        {"os_key": "windows_server_2025", "scope": "HOST", "scope_value": "Web-01",
         "level": "all", "role": "", "rule": "18.10.4", "reason": ""},
        {"os_key": "rhel7", "scope": "app_group", "scope_value": "app-sap", "level": "L2",
         "role": "Workstation", "rule": "5.2.1", "owner": "  ops   team "},
    ]
    out = {"exclusions": [], "jobs": [], "invalid_exclusions": [], "invalid_jobs": [],
           "targets": [], "invalid_targets": []}
    for rec in ({"group": "linux-prod", "updated_by": " alice ", "updated_at": "2026-10-01T12:00:00Z"},
                {"group": "os-rhel9_v2.0.0", "extra": 1}):
        out["targets"].append({"input": rec, "normalized": s.validate_target(rec)})
    out["invalid_targets"] = [{"group": ""}, {"group": "two words"}, {"group": 5}, {},
                              {"group": "ciscat-rhel7-base"}, {"group": ".."}]
    for rec in out["invalid_targets"]:
        try:
            s.validate_target(rec)
            raise AssertionError("expected invalid: {}".format(rec))
        except s.StoreError:
            pass
    for rec in exclusions:
        norm = s.validate_exclusion(rec)
        out["exclusions"].append({"input": rec, "normalized": norm,
                                  "key": s.exclusion_key(norm), "encoded": s.encode(norm)})
    for rec in ({"type": "once", "at": "2026-10-31T22:00", "targets": ["rhel7"]},
                {"type": "monthly", "day": -3, "time": "23:30", "wave_size": 20},
                {"type": "weekly", "weekday": 0, "time": "01:15", "targets": ["*"],
                 "label": "Monday night"},
                {"type": "once", "at": "2026-11-02T08:00", "agents": ["017", "003", "003"],
                 "targets": []},
                {"type": "weekly", "weekday": 4, "time": "20:00", "groups": ["web-prod", "os-rhel7"]}):
        out["jobs"].append({"input": rec, "normalized": s.validate_job(rec)})
    out["invalid_exclusions"] = [
        {"os_key": "rhel7", "scope": "group", "scope_value": "x", "rule": "1.1"},
        {"os_key": "rhel7", "scope": "host", "scope_value": "a b", "rule": "1.1"},
        {"os_key": "rhel7", "scope": "os", "rule": "1.x"},
        {"os_key": "RHEL7", "scope": "os", "rule": "1.1"},
        {"os_key": "rhel7", "scope": "os", "rule": "1.1", "level": "L3"},
    ]
    out["invalid_jobs"] = [
        {"type": "cron"}, {"type": "once", "at": "2026-02-30T10:00"},
        {"type": "monthly", "day": 0, "time": "01:00"}, {"type": "monthly", "day": -29, "time": "01:00"},
        {"type": "weekly", "weekday": 7, "time": "01:00"}, {"type": "weekly", "weekday": 1, "time": "24:00"},
        {"type": "once", "at": "2026-10-31T22:00", "wave_size": 0},
        {"type": "once", "at": "2026-10-31T22:00", "agents": ["000"]},
        {"type": "once", "at": "2026-10-31T22:00", "agents": ["3"]},
        {"type": "once", "at": "2026-10-31T22:00", "groups": ["ciscat-rhel7-base"]},
        {"type": "once", "at": "2026-10-31T22:00", "agents": ["003"], "groups": ["web"]},
        {"type": "once", "at": "2026-10-31T22:00", "targets": []},
        {"type": "once", "at": "2026-10-31T22:00", "groups": [".."]},
    ]
    for rec in out["invalid_exclusions"]:
        try:
            s.validate_exclusion(rec)
            raise AssertionError("expected invalid: {}".format(rec))
        except s.StoreError:
            pass
    for rec in out["invalid_jobs"]:
        try:
            s.validate_job(rec)
            raise AssertionError("expected invalid: {}".format(rec))
        except s.StoreError:
            pass
    return out


def render():
    return json.dumps(build(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(render())
    print("wrote", os.path.normpath(OUT))
