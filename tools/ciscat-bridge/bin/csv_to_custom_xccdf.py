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
per FAMILY (windows_server/rhel/debian, from the os_key prefix); any other OS takes the levels
and roles of its benchmark's own profiles.
The profile id template is COMMON:
  xccdf_org.cisecurity.benchmarks_profile_{level}_-_{role}
Only the VALUES change: windows has NG and Member/DC; rhel/debian have Server/Workstation.
The CSV level tag (L1/L2/NG) is expanded to tokens valid PER FAMILY; a tag invalid for the
family (e.g. NG on Linux) -> explicit error.

Option X: exclusions only (selected="false"). idrefs unchanged (OVAL still matches).

BASE PROFILES (--base-profile, repeatable): for benchmarks without "Level_1_-_<role>" profiles
(STIG SEVERITY_CAT_I/II/III, Level_1, Level_1_L1, ...). One tailored profile, the union of the
base profiles, with the usual id TAILORED_Level_1_-_<role>; exclusions of level L1 or ALL apply,
whatever their role.
"""

import argparse
import csv
import json
import os
import re
import sys
from xml.sax.saxutils import escape

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import ciscat_xccdf as xccdf  # noqa: E402

PROFILES_MAP = os.path.join(_HERE, "maps", "ciscat-profiles.json")
PROFILE_PREFIX = xccdf.PROFILE_PREFIX
VALID_SCOPES = ("host", "app_group", "os", "global")
FAMILY_PREFIXES = (("windows_server", "windows_server"), ("rhel", "rhel"), ("debian", "debian"))
_TAXONOMY = {}


class TailoringError(ValueError):
    """Tailoring that cannot be built (unknown profile, level invalid for the OS family, ...)."""


def taxonomy():
    """maps/ciscat-profiles.json: profile id template, level aliases, families (read once)."""
    if not _TAXONOMY:
        with open(PROFILES_MAP, encoding="utf-8") as f:
            _TAXONOMY.update(json.load(f))
    return _TAXONOMY


def family_of(os_key):
    """Family of ciscat-profiles.json for an os_key (windows_server_2025 -> windows_server,
    rhel9 -> rhel), or None: the benchmark's own profiles give its levels and roles."""
    for prefix, family in FAMILY_PREFIXES:
        if os_key.startswith(prefix):
            return family
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
            rejected.append((rawtext, f"line {lineno}: fewer than 4 fields"))
            continue
        scope = cell(raw, "scope").lower()
        scope_value = cell(raw, "scope_value")
        level = cell(raw, "level").lower()
        rule = cell(raw, "rule")
        role = cell(raw, "role")           # optional; "" -> any role
        reason = cell(raw, "reason") or "n/a"
        ticket = cell(raw, "ticket") or "n/a"
        owner = cell(raw, "owner") or "n/a"
        if scope not in VALID_SCOPES:
            rejected.append((rawtext, f"line {lineno}: scope '{scope}' invalid"))
            continue
        if not rule:
            rejected.append((rawtext, f"line {lineno}: empty rule"))
            continue
        if level not in ("all", "l1", "l2", "ng"):
            rejected.append((rawtext, f"line {lineno}: level '{level}' invalid"))
            continue
        if scope != "global" and not scope_value:
            rejected.append((rawtext, f"line {lineno}: empty scope_value"))
            continue
        if scope == "global":
            scope_value = "all"
        valid.append({"scope": scope, "scope_value": scope_value, "level": level.upper(),
                      "role": role, "rule": rule, "reason": reason, "ticket": ticket, "owner": owner})
    return valid, rejected


def applies_to_host(e, host, app_groups, os_key):
    s, v = e["scope"], e["scope_value"].lower()
    if s == "global":
        return True
    if s == "host":
        return v == host.lower()
    if s == "os":
        return v == os_key.lower()
    if s == "app_group":
        return v in [g.lower() for g in app_groups]
    return False


def resolve_rule(rule_spec, idrefs):
    if rule_spec.startswith("xccdf_"):
        return [r for r in idrefs if r == rule_spec]
    pat = re.compile(r"_rule_" + re.escape(rule_spec) + r"_")
    return [r for r in idrefs if pat.search(r)]


def level_matches(entry_level, sigla):
    return entry_level == "ALL" or entry_level == sigla


def family_from_benchmark(bench):
    """Levels and roles read from the benchmark's own profiles, for an OS without a family in
    ciscat-profiles.json (e.g. a benchmark discovered on the manager)."""
    levels, roles = [], []
    for pid in bench.profile_ids():
        m = re.match(re.escape(PROFILE_PREFIX) + r"(Level_1|Level_2|Next_Generation_Windows_Security)"
                     r"_-_([A-Za-z0-9_]+)$", pid)
        if not m:
            continue
        if m.group(1) not in levels:
            levels.append(m.group(1))
        if m.group(2) not in roles:
            roles.append(m.group(2))
    if not roles:
        return None
    default = next((r for r in ("Server", "Member_Server") if r in roles), roles[0])
    return {"levels": levels, "roles": roles, "default_role": default}


# --- editing a copy of a profile, as written in the benchmark -----------------------------------
def _prefix(block):
    """Namespace prefix of the profile element ("xccdf:" or "")."""
    return re.match(r"<([\w.-]+:)?Profile\b", block).group(1) or ""


def set_selected(block, idrefs, value):
    """The block with selected="<value>" on the <select> elements of these idrefs."""
    def fix(m):
        tag = m.group(0)
        idref = re.search(r'\bidref="([^"]*)"', tag)
        if idref and idref.group(1) in idrefs:
            tag = re.sub(r'\bselected="[^"]*"', 'selected="{0}"'.format(value), tag)
        return tag
    return re.sub(r"<(?:[\w.-]+:)?select\b[^>]*>", fix, block)


def retitle(block, profile_id, title):
    """The block with a new profile id and title."""
    block = re.sub(r'(<(?:[\w.-]+:)?Profile\b[^>]*\bid=")[^"]*(")',
                   lambda mm: mm.group(1) + profile_id + mm.group(2), block, count=1)
    p = re.escape(_prefix(block))
    return re.sub(r"(<" + p + r"title\b[^>]*>)(.*?)(</" + p + r"title>)",
                  lambda mm: mm.group(1) + escape(title) + mm.group(3), block, count=1,
                  flags=re.DOTALL)


def union_profile(bench, profiles):
    """Profile block selecting every control selected in at least one of the profiles (the
    first profile is the template: its title, description and values are kept)."""
    block = bench.profile_text(profiles[0])
    selected = []
    for p in profiles:
        for idref in bench.selected(p):
            if idref not in selected:
                selected.append(idref)
    present = {idref for idref, _ in bench.selects(profiles[0])}
    block = set_selected(block, set(selected), "true")
    pfx = _prefix(block)
    extra = "".join('\n    <{0}select idref="{1}" selected="true"/>'.format(pfx, i)
                    for i in selected if i not in present)
    if extra:
        end = block.rindex("</")
        block = block[:end].rstrip() + extra + "\n  " + block[end:]
    return block, selected


def write_custom(bench, blocks, out_path):
    """The benchmark, byte for byte, with the tailored profiles after its last profile."""
    pos = bench.profiles_end()
    with open(out_path, "wb") as f:
        f.write(bench.raw[:pos] + ("\n" + "\n".join(blocks)).encode("utf-8") + bench.raw[pos:])


def build_from_base_profiles(csv_path, bench, host, os_key, role, app_groups, out_path,
                             base_profiles):
    by_id = {p.get("id"): p for p in bench.profiles}
    missing = [p for p in base_profiles if PROFILE_PREFIX + p not in by_id]
    if missing:
        raise TailoringError(f"profile(s) {missing} not found in the benchmark")
    role_norm = role or "Default"
    block, idrefs = union_profile(bench, [by_id[PROFILE_PREFIX + p] for p in base_profiles])

    tailoring, rejected = load_and_clean(csv_path)
    audit, excluded = [], set()
    for e in tailoring:
        # no role filter: a single profile, and the dashboard names these profiles' roles after
        # the benchmark's columns (e.g. L1 for Level_1_L1)
        if not applies_to_host(e, host, app_groups, os_key) or not level_matches(e["level"], "L1"):
            continue
        for mi in resolve_rule(e["rule"], idrefs):
            excluded.add(mi)
            audit.append(("L1", mi, e))

    tail_pid = taxonomy()["profile_id_template"].format(level="TAILORED_Level_1", role=role_norm)
    block = retitle(block, tail_pid, f"TAILORED L1 - {role_norm.replace('_', ' ')} ({host})")
    block = set_selected(block, excluded, "false")
    write_custom(bench, [block], out_path)
    return [("L1", tail_pid, len(excluded))], audit, rejected, "+".join(base_profiles), role_norm


def build_custom_xccdf(csv_path, benchmark_path, host, os_key, role, app_groups, out_path,
                       base_profiles=None):
    """Writes the custom XCCDF. Returns (summary, audit, rejected, family, role)."""
    bench = xccdf.load(benchmark_path)
    if not bench.profiles:
        raise TailoringError(f"no profile in {benchmark_path}")
    if base_profiles:
        return build_from_base_profiles(csv_path, bench, host, os_key, role, app_groups,
                                        out_path, base_profiles)
    tax = taxonomy()
    family = family_of(os_key)
    if family in tax["families"]:
        fam = tax["families"][family]
    else:
        fam = family_from_benchmark(bench)
        if fam is None:
            raise TailoringError(f"cannot determine levels and roles for os_key '{os_key}' "
                                 f"from {benchmark_path}")
        family = family or os_key
    fam_levels = fam["levels"]            # e.g. ['Level_1','Level_2'] or with NG for windows
    fam_roles = fam["roles"]              # e.g. ['Server','Workstation'] or Member/DC
    role_norm = _normalize_role(role, fam_roles, fam["default_role"])

    # CSV level tags valid for this family: L1/L2 always; NG only if Next_Generation* in levels
    sigla_to_token = {sigla: token for sigla, token in tax["level_aliases"].items()
                      if token in fam_levels}

    tailoring, rejected = load_and_clean(csv_path)
    std_profiles = {p.get("id"): p for p in bench.profiles}
    host_entries = [e for e in tailoring if applies_to_host(e, host, app_groups, os_key)]

    # validation: an entry with level NG for a family without NG -> explicit error
    for e in host_entries:
        if e["level"] != "ALL" and e["level"] not in sigla_to_token:
            raise TailoringError(f"level '{e['level']}' invalid for family '{family}' "
                                 f"(host {host}, rule {e['rule']}). Valid levels: {list(sigla_to_token)}")

    audit, blocks, summary = [], [], []
    for sigla, std_token in sigla_to_token.items():
        std_pid = tax["profile_id_template"].format(level=std_token, role=role_norm)
        if std_pid not in std_profiles:
            continue
        idrefs = bench.selected(std_profiles[std_pid])
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
                excluded.add(mi)
                audit.append((sigla, mi, e))

        tail_pid = tax["profile_id_template"].format(level="TAILORED_" + std_token, role=role_norm)
        block = retitle(bench.profile_text(std_profiles[std_pid]), tail_pid,
                        f"TAILORED {sigla} - {role_norm.replace('_', ' ')} ({host})")
        blocks.append(set_selected(block, excluded, "false"))
        summary.append((sigla, tail_pid, len(excluded)))

    write_custom(bench, blocks, out_path)
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


def audit_lines(audit):
    """One line per excluded control: [L1] excluded 1.1.1 (scope=os:rhel7 ticket=CHG-1)."""
    out = []
    for sigla, idref, e in audit:
        num = xccdf.rule_number(idref) or idref
        out.append(f"[{sigla}] excluded {num} (scope={e['scope']}:{e['scope_value']} ticket={e['ticket']})")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--benchmark", required=True)
    ap.add_argument("--host", required=True)
    ap.add_argument("--os-key", required=True)
    ap.add_argument("--role", default="", help="role token or alias; empty = family default")
    ap.add_argument("--app-groups", default="")
    ap.add_argument("--base-profile", action="append", default=[],
                    help="profile id without its prefix (e.g. SEVERITY_CAT_I); repeat for a union")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    app_groups = [g.strip() for g in args.app_groups.split(",") if g.strip()]
    try:
        summary, audit, rejected, family, role_norm = build_custom_xccdf(
            args.csv, args.benchmark, args.host, args.os_key, args.role, app_groups, args.out,
            args.base_profile)
    except (OSError, ValueError) as e:
        sys.exit(f"[ERROR] {e}")
    print(f"Custom XCCDF generated: {args.out}")
    print(f"Host: {args.host} | OS key: {args.os_key} | family: {family} | role: {role_norm} | app_groups: {app_groups}")
    if rejected:
        print(f"\nRejected CSV rows: {len(rejected)}")
        for _, why in rejected:
            print(f"  [REJECTED] {why}")
    print(f"\nTailored profiles added: {len(summary)}")
    for sigla, pid, n in summary:
        print(f"  {sigla}: {n} excluded -> {pid}")
    print(f"\nExclusions AUDIT ({len(audit)}):")
    for line in audit_lines(audit):
        print("  " + line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
