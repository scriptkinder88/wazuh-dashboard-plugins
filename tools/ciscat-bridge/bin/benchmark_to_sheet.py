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

import argparse, csv, hashlib, re, sys


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


def extract(benchmark_path):
    data = open(benchmark_path, encoding="utf-8", errors="replace").read()

    # benchmark name + version
    bench_id = re.search(r'<xccdf:Benchmark\b[^>]*id="([^"]*)"', data)
    bench_id = bench_id.group(1) if bench_id else "unknown"
    ver = re.search(r'<xccdf:version[^>]*>([^<]+)</xccdf:version>', data)
    version = ver.group(1).strip() if ver else "unknown"

    # standard profiles (no TestResult, no TAILORED) -> {profile_short: set(rule_num)}
    profiles = {}
    for b in re.findall(r'<xccdf:Profile\b.*?</xccdf:Profile>', data, re.DOTALL):
        pid = re.search(r'id="([^"]*)"', b).group(1)
        if "TAILORED" in pid:
            continue
        short = pid.split("_profile_")[-1]   # e.g. Level_1_-_Member_Server
        nums = set()
        for idref in re.findall(r'idref="([^"]*)"\s+selected="true"', b):
            m = re.search(r'_rule_([0-9.]+)_', idref)
            if m:
                nums.add(m.group(1))
        profiles[short] = nums

    # control titles: num -> title
    titles = {}
    for rb in re.findall(r'<xccdf:Rule\b.*?</xccdf:Rule>', data, re.DOTALL):
        rid = re.search(r'id="([^"]*)"', rb)
        if not rid:
            continue
        m = re.search(r'_rule_([0-9.]+)_', rid.group(1))
        if not m:
            continue
        num = m.group(1)
        t = re.search(r'<xccdf:title[^>]*>(.*?)</xccdf:title>', rb, re.DOTALL)
        if t:
            titles[num] = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', '', t.group(1))).strip()

    # profile columns: short readable name. Stable ordering.
    # short is like "Level_1_-_Member_Server" -> column "L1_Member_Server"
    def col_name(short):
        s = short.replace("Level_1", "L1").replace("Level_2", "L2")
        s = s.replace("Next_Generation_Windows_Security", "NG")
        s = s.replace("_-_", "_")
        return s
    prof_cols = sorted(profiles.keys(), key=lambda s: (
        0 if "Level_1" in s else 1 if "Level_2" in s else 2, s))

    # all controls (union), sorted by number
    all_nums = sorted(set().union(*profiles.values()) if profiles else set(), key=rule_num_key)

    return bench_id, version, prof_cols, [col_name(p) for p in prof_cols], profiles, titles, all_nums


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
        f.write(f"# --- tailoring sheet. To EXCLUDE a control from a profile, "
                f"write 'x' in that profile's cell. Audit (who/when/why) in git. ---\n")
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
