#!/usr/bin/env python3
"""
benchmark_to_sheet.py  (MANAGER side) - Stage A: extraction

Given a CIS XCCDF benchmark, produces a per-OS CSV SHEET: one row per control,
one column per profile (level x role) actually present in the benchmark. The
operator marks 'x' in the cell of the profile a control should be excluded from.

Versionable and auditable:
  - header with benchmark name + version + sha256 (stable context, no timestamp)
  - rows sorted by CIS number (deterministic order -> clean diff)
  - profile columns derived from the benchmark (data-driven)
  - who/when = git (not in the file)

Profile cell: '' = control not present in that profile; 'applicable' = present;
'x' = operator excludes it from that profile (per-level AND per-role).
"""

import argparse
import csv
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ciscat_xccdf as xccdf  # noqa: E402


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def rule_num_key(num):
    """Sort key for CIS rule numbers like 1.10.2 (numeric, dotted)."""
    parts = []
    for p in num.split("."):
        parts.append(int(p) if p.isdigit() else 0)
    return parts


def col_name(short):
    """Profile column of the sheet: Level_1_-_Member_Server -> L1_Member_Server."""
    s = short.replace("Level_1", "L1").replace("Level_2", "L2")
    s = s.replace("Next_Generation_Windows_Security", "NG")
    return s.replace("_-_", "_")


def extract(benchmark_path):
    """(benchmark id, version, profile keys, profile columns, {profile key: {rule numbers}},
    {rule number: title}, rule numbers sorted) of a benchmark."""
    bench = xccdf.load(benchmark_path)
    # standard profiles (no TAILORED) -> {profile_short: set(rule_num)}
    profiles = {}
    for p in bench.profiles:
        pid = p.get("id", "")
        if "TAILORED" in pid:
            continue
        short = pid.split("_profile_")[-1]   # e.g. Level_1_-_Member_Server
        profiles[short] = {n for n in map(xccdf.rule_number, bench.selected(p)) if n}
    titles = {}
    for rid in bench.rules:
        num = xccdf.rule_number(rid)
        if num:
            titles[num] = bench.rule_title(rid)
    prof_cols = sorted(profiles.keys(), key=lambda s: (
        0 if "Level_1" in s else 1 if "Level_2" in s else 2, s))
    all_nums = sorted(set().union(*profiles.values()) if profiles else set(), key=rule_num_key)
    return (bench.id or "unknown", bench.version or "unknown", prof_cols,
            [col_name(p) for p in prof_cols], profiles, titles, all_nums)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--benchmark", required=True)
    ap.add_argument("--out", required=True, help="output CSV sheet")
    args = ap.parse_args()

    sha = sha256_of(args.benchmark)
    bench_id, version, prof_keys, col_names, profiles, titles, all_nums = extract(args.benchmark)

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        # context header (comments, stable: no timestamp)
        f.write(f"# benchmark: {bench_id}\n")
        f.write(f"# version: {version}\n")
        f.write(f"# sha256: {sha}\n")
        f.write("# --- tailoring sheet. To EXCLUDE a control from a profile, "
                "write 'x' in that profile's cell. Audit (who/when/why) in git. ---\n")
        w = csv.writer(f)
        w.writerow(["rule", "title"] + col_names)
        for num in all_nums:
            row = [num, titles.get(num, "")]
            for pk in prof_keys:
                row.append("applicable" if num in profiles[pk] else "")
            w.writerow(row)

    print(f"[OK] sheet generated: {args.out}")
    print(f"  benchmark: {bench_id} v{version}")
    print(f"  sha256: {sha[:16]}...")
    print(f"  controls: {len(all_nums)} | profile columns: {col_names}")


if __name__ == "__main__":
    main()
