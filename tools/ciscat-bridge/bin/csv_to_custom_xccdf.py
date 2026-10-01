#!/usr/bin/env python3
"""
csv_to_custom_xccdf.py  (MANAGER side) - multi-OS

CIS-CAT v4 has no -t option for a separate tailoring file. Native tailoring is done
by generating a custom XCCDF that CONTAINS the tailored profiles, selected with -p.
This converter:
  1. reads the central CSV (scope,scope_value,level,role,rule,...)
  2. for the given host, computes the applicable exclusions (additive)
  3. starts from the base XCCDF and ADDS tailored profiles (copies of the standard
     profiles with selected="false" on the excluded controls)
  4. writes a complete custom XCCDF; CIS-CAT uses it with -b <custom> -p <profile>

MULTI-OS: taxonomy (levels, roles) is data-driven, taken from maps/ciscat-profiles.json
per FAMILY (windows_server/rhel/debian), derived from os_key via maps/os-benchmark-map.json.
The profile id template is COMMON:
  xccdf_org.cisecurity.benchmarks_profile_{level}_-_{role}
Only the VALUES change: windows has NG and Member/DC; rhel/debian have Server/Workstation.
The CSV level tag (L1/L2/NG) is expanded to tokens valid PER FAMILY; a tag invalid for the
family (e.g. NG on Linux) -> explicit error.

Option X: exclusions only (selected="false"). idrefs unchanged (OVAL still matches).
"""

import argparse
import csv
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(_HERE, "maps", "ciscat-profiles.json"), encoding="utf-8") as f:
    PROFILES = json.load(f)
with open(os.path.join(_HERE, "maps", "os-benchmark-map.json"), encoding="utf-8") as f:
    OSMAP = json.load(f)

PROFILE_ID_TEMPLATE = PROFILES["profile_id_template"]
LEVEL_ALIASES = PROFILES["level_aliases"]          # L1->Level_1, L2->Level_2, NG->Next_Generation...
FAMILIES = PROFILES["families"]
OSKEYS = OSMAP["keys"]

VALID_SCOPES = ("host", "app_group", "os", "global")
EXPECTED_HEADER = ["scope", "scope_value", "level", "rule"]


def family_of(os_key):
    """Derive the family (windows_server/rhel/debian) from os_key via os-benchmark-map."""
    entry = OSKEYS.get(os_key)
    if entry and entry.get("family"):
        return entry["family"]
    # fallback: infer from prefix
    if os_key.startswith("windows"):
        return "windows_server"
    if os_key.startswith("rhel"):
        return "rhel"
    if os_key.startswith("debian"):
        return "debian"
    return None


def load_and_clean(csv_path):
    """Header-aware: supports both the legacy format (scope,scope_value,level,rule,reason,ticket,owner)
    and the new one with role (scope,scope_value,level,role,rule). role is optional: if absent,
    the exclusion applies to any role (None)."""
    valid, rejected = [], []
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        rows = [r for r in csv.reader(f) if not (r and r[0].lstrip().startswith("#"))]
    if not rows:
        return valid, [("(empty)", "empty file")]
    header = [h.strip().lower() for h in rows[0]]
    has_header = header[:3] == ["scope", "scope_value", "level"]
    # map column name -> index (if header present), otherwise legacy positions
    if has_header:
        idx = {name: i for i, name in enumerate(header)}
        start = 1
    else:
        idx = {"scope": 0, "scope_value": 1, "level": 2, "rule": 3,
               "reason": 4, "ticket": 5, "owner": 6}
        start = 0

    def cell(raw, name):
        i = idx.get(name)
        return raw[i].strip() if i is not None and i < len(raw) and raw[i].strip() else ""

    for lineno, raw in enumerate(rows[start:], start=start + 1):
        rawtext = ",".join(raw)
        if len(raw) < 4:
            rejected.append((rawtext, f"line {lineno}: fewer than 4 fields")); continue
        scope = cell(raw, "scope").lower()
        scope_value = cell(raw, "scope_value")
        level = cell(raw, "level").lower()
        rule = cell(raw, "rule")
        role = cell(raw, "role")           # new, optional; "" -> any role
        reason = cell(raw, "reason") or "n/a"
        ticket = cell(raw, "ticket") or "n/a"
        owner = cell(raw, "owner") or "n/a"
        if scope not in VALID_SCOPES:
            rejected.append((rawtext, f"line {lineno}: scope '{scope}' invalid")); continue
        if not rule:
            rejected.append((rawtext, f"line {lineno}: empty rule")); continue
        if level not in ("all", "l1", "l2", "ng"):
            rejected.append((rawtext, f"line {lineno}: level '{level}' invalid")); continue
        if scope != "global" and not scope_value:
            rejected.append((rawtext, f"line {lineno}: empty scope_value")); continue
        if scope == "global":
            scope_value = "all"
        valid.append({"scope": scope, "scope_value": scope_value, "level": level.upper(),
                      "role": role, "rule": rule, "reason": reason, "ticket": ticket, "owner": owner})
    return valid, rejected


def applies_to_host(e, host, app_groups, os_key):
    s, v = e["scope"], e["scope_value"].lower()
    if s == "global": return True
    if s == "host": return v == host.lower()
    if s == "os": return v == os_key.lower()
    if s == "app_group": return v in [g.lower() for g in app_groups]
    return False


def resolve_rule(rule_spec, idrefs):
    if rule_spec.startswith("xccdf_"):
        return [r for r in idrefs if r == rule_spec]
    pat = re.compile(r"_rule_" + re.escape(rule_spec) + r"_")
    return [r for r in idrefs if pat.search(r)]


def level_matches(entry_level, sigla):
    return entry_level == "ALL" or entry_level == sigla


def family_from_benchmark(data):
    """Levels and roles read from the benchmark's own profiles, for an OS without a family in
    ciscat-profiles.json (e.g. a benchmark discovered on the manager)."""
    levels, roles = [], []
    for level, r in re.findall(r'<xccdf:Profile\b[^>]*\bid="xccdf_org\.cisecurity\.benchmarks_profile_'
                               r'(Level_1|Level_2|Next_Generation_Windows_Security)_-_([A-Za-z0-9_]+)"',
                               data):
        if level not in levels:
            levels.append(level)
        if r not in roles:
            roles.append(r)
    if not roles:
        return None
    default = next((r for r in ("Server", "Member_Server") if r in roles), roles[0])
    return {"levels": levels, "roles": roles, "default_role": default}


def build_custom_xccdf(csv_path, benchmark_path, host, os_key, role, app_groups, out_path):
    family = family_of(os_key)
    if family in FAMILIES:
        fam = FAMILIES[family]
    else:
        with open(benchmark_path, encoding="utf-8") as f:
            fam = family_from_benchmark(f.read())
        if fam is None:
            sys.exit(f"[ERROR] cannot determine levels and roles for os_key '{os_key}' "
                     f"from {benchmark_path}")
        family = family or os_key
    fam_levels = fam["levels"]            # e.g. ['Level_1','Level_2'] or with NG for windows
    fam_roles = fam["roles"]              # e.g. ['Server','Workstation'] or Member/DC
    default_role = fam["default_role"]

    # role: use the provided one if valid for the family, otherwise default
    # accepts both the exact token (Server) and convenient aliases (member_server->Member_Server)
    role_norm = _normalize_role(role, fam_roles, default_role)

    # CSV level tags valid for this family: L1/L2 always; NG only if Next_Generation* in levels
    sigla_to_token = {}
    for sigla, token in LEVEL_ALIASES.items():
        if token in fam_levels:
            sigla_to_token[sigla] = token

    tailoring, rejected = load_and_clean(csv_path)
    data = open(benchmark_path, encoding="utf-8").read()

    profile_blocks = list(re.finditer(r'<xccdf:Profile\b.*?</xccdf:Profile>', data, re.DOTALL))
    std_profiles = {}
    for m in profile_blocks:
        pid = re.search(r'id="([^"]*)"', m.group(0)).group(1)
        selects = re.findall(r'idref="([^"]*)"\s+selected="true"', m.group(0))
        std_profiles[pid] = {"block": m.group(0), "selects": selects}

    host_entries = [e for e in tailoring if applies_to_host(e, host, app_groups, os_key)]

    # validation: an entry with level NG for a family without NG -> explicit error
    for e in host_entries:
        if e["level"] != "ALL" and e["level"] not in sigla_to_token:
            sys.exit(f"[ERROR] level '{e['level']}' invalid for family '{family}' "
                     f"(host {host}, rule {e['rule']}). Valid levels: {list(sigla_to_token)}")

    audit, custom_profiles_xml, summary = [], [], []
    for sigla, std_token in sigla_to_token.items():
        std_pid = PROFILE_ID_TEMPLATE.format(level=std_token, role=role_norm)
        if std_pid not in std_profiles:
            continue
        idrefs = std_profiles[std_pid]["selects"]
        excluded = set()
        for e in host_entries:
            if not level_matches(e["level"], sigla):
                continue
            # role filter: if the entry specifies a role, it must match the current one.
            # empty role (legacy or "any") -> applies to all roles.
            e_role = (e.get("role") or "").strip()
            if e_role and e_role.lower() != role_norm.lower():
                continue
            for mi in resolve_rule(e["rule"], idrefs):
                excluded.add(mi); audit.append((sigla, mi, e))

        tail_pid = PROFILE_ID_TEMPLATE.format(level="TAILORED_" + std_token, role=role_norm)
        block = std_profiles[std_pid]["block"]
        block = re.sub(r'(<xccdf:Profile\b[^>]*\bid=")[^"]*(")',
                       lambda mm: mm.group(1) + tail_pid + mm.group(2), block, count=1)
        block = re.sub(r'(<xccdf:title[^>]*>)(.*?)(</xccdf:title>)',
                       lambda mm: mm.group(1) + f"TAILORED {sigla} - {role_norm.replace('_',' ')} ({host})" + mm.group(3),
                       block, count=1, flags=re.DOTALL)
        for idref in excluded:
            block = re.sub(r'(idref="' + re.escape(idref) + r'"\s+selected=")true(")',
                           lambda mm: mm.group(1) + "false" + mm.group(2), block)
        custom_profiles_xml.append(block)
        summary.append((sigla, tail_pid, len(excluded)))

    insert_pos = profile_blocks[-1].end()
    new_data = data[:insert_pos] + "\n" + "\n".join(custom_profiles_xml) + data[insert_pos:]
    open(out_path, "w", encoding="utf-8").write(new_data)
    return summary, audit, rejected, family, role_norm


def _normalize_role(role, fam_roles, default_role):
    """Map a user-provided role to a valid family role token."""
    if not role:
        return default_role
    r = role.strip().lower()
    # exact token match (case-insensitive)
    for tok in fam_roles:
        if r == tok.lower():
            return tok
    # common aliases
    aliases = {
        "member_server": "Member_Server", "member": "Member_Server", "ms": "Member_Server",
        "domain_controller": "Domain_Controller", "dc": "Domain_Controller",
        "server": "Server", "workstation": "Workstation", "ws": "Workstation",
    }
    mapped = aliases.get(r)
    if mapped and mapped in fam_roles:
        return mapped
    # not valid for this family -> default, but warn
    sys.stderr.write(f"[WARN] role '{role}' invalid for roles {fam_roles}; using default '{default_role}'\n")
    return default_role


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--benchmark", required=True)
    ap.add_argument("--host", required=True)
    ap.add_argument("--os-key", required=True)
    ap.add_argument("--role", default="", help="role token or alias; empty = family default")
    ap.add_argument("--app-groups", default="")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    app_groups = [g.strip() for g in args.app_groups.split(",") if g.strip()]
    summary, audit, rejected, family, role_norm = build_custom_xccdf(
        args.csv, args.benchmark, args.host, args.os_key, args.role, app_groups, args.out)
    print(f"Custom XCCDF generated: {args.out}")
    print(f"Host: {args.host} | OS key: {args.os_key} | family: {family} | role: {role_norm} | app_groups: {app_groups}")
    if rejected:
        print(f"\nRejected CSV rows: {len(rejected)}")
        for rt, why in rejected: print(f"  [REJECTED] {why}")
    print(f"\nTailored profiles added: {len(summary)}")
    for sigla, pid, n in summary:
        print(f"  {sigla}: {n} excluded -> {pid}")
    print(f"\nExclusions AUDIT ({len(audit)}):")
    for sigla, idref, e in audit:
        num = re.search(r"_rule_([0-9.]+)_", idref)
        num = num.group(1) if num else idref
        print(f"  [{sigla}] excluded {num} (scope={e['scope']}:{e['scope_value']} ticket={e['ticket']})")


if __name__ == "__main__":
    main()
