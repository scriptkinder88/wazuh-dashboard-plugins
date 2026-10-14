#!/usr/bin/env python3
"""
Manager-side generator: from a tailored XCCDF (custom) + chosen tailored profile,
produce a Wazuh SCA policy YAML for one host.

Model:
  - controls in policy = profile selects with selected=true, MINUS manual controls
  - manual controls = Rule elements WITHOUT <check>/<complex-check> (no OVAL) -> excluded, listed apart
  - each SCA check: integer id, title carries CIS rule number, rule reads flatten file:
        f:<flat_path> -> r:^<rule_escaped>:pass$
  - requirements: flatten file must exist (else policy not evaluated; avoids false 326-fail)

Output:
  - <out>.yml          Wazuh SCA policy
  - <out>.manual.txt   manual controls selected for this host (tracking, audit)
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ciscat_xccdf as xccdf  # noqa: E402

CHECK_ID_BASE = 5000  # integer id base; keep room and avoid collisions with stock policies
TEXT_LIMIT = 2000
TITLE_LIMIT = 250
SCRIPT_MARKERS = ("#!/usr/bin/env", "#!/bin/bash", "#!/bin/sh", "#!powershell")


def selected_rules(bench, profile):
    """[(rule_number, idref)] selected by the profile, in document order."""
    out = []
    for idref in bench.selected(profile):
        num = xccdf.rule_number(idref)
        if num:
            out.append((num, idref))
    return out


def manual_rule_numbers(bench):
    """Numbers of the rules without any check (no OVAL): assessed by hand."""
    return bench.manual_numbers()


def trim_remediation_scripts(text, num=None):
    """Keep the descriptive prose of a CIS remediation and drop embedded
    scripts: cut at the first script marker (shebang).
    The CIS fixtext always puts the prose steps BEFORE the script, so the
    actionable guidance is preserved; a pointer to the benchmark is appended."""
    if not text:
        return text
    cut = min([i for i in (text.find(mk) for mk in SCRIPT_MARKERS) if i != -1] or [len(text)])
    if cut == len(text):
        return text
    head = text[:cut].rstrip(" -\t")
    ref = " [Full remediation script: see the CIS benchmark{0}.]".format(
        ", rule {0}".format(num) if num else "")
    return head.rstrip() + ref


def yaml_sq(s):
    """Quote a string for YAML using single quotes (no escape interpretation).
    A literal single quote is doubled per YAML spec."""
    s = s.strip().replace("'", "''")
    return "'" + s + "'"


def esc_rule(num):
    return num.replace(".", r"\.")


def generate(xccdf_path, profile_id, flat_path, policy_id, policy_name, out):
    """Writes <out>.yml (the SCA policy) and <out>.manual.txt. Returns the counts."""
    bench = xccdf.load(xccdf_path)
    prof = bench.profile(profile_id)
    if prof is None:
        raise xccdf.XccdfError("profile not found: {0}".format(profile_id))

    sel = selected_rules(bench, prof)
    manual = manual_rule_numbers(bench)
    families = bench.family_titles()
    in_policy = [(n, idref) for (n, idref) in sel if n not in manual]
    in_manual = [(n, idref) for (n, idref) in sel if n in manual]

    L = []
    L.append("policy:")
    L.append(f"  id: {yaml_sq(policy_id)}")
    L.append(f"  file: {yaml_sq(policy_id + '.yml')}")
    L.append(f"  name: {yaml_sq(policy_name)}")
    L.append('  description: ' + yaml_sq('CIS-CAT tailored results bridged into Wazuh SCA (flatten-based).'))
    L.append("")
    L.append("requirements:")
    L.append('  title: ' + yaml_sq('CIS-CAT Pro installed and assessment results present'))
    L.append('  description: ' + yaml_sq('The flatten file is produced after a CIS-CAT assessment and withdrawn when CIS-CAT Pro is not found on the agent. If absent, the policy is not evaluated.'))
    L.append("  condition: all")
    L.append("  rules:")
    L.append(f"    - 'f:{flat_path}'")
    L.append("")
    L.append("checks:")

    cid = CHECK_ID_BASE
    for num, idref in in_policy:
        cid += 1
        title = bench.rule_title(idref)
        disp = f"{num} {title}" if title else num
        rationale = bench.rule_prose(idref, "rationale")
        remediation = trim_remediation_scripts(bench.rule_prose(idref, "fixtext"))
        cis_desc = bench.rule_prose(idref, "description")
        # description = CIS control description (what it verifies + recommended value),
        # plus a note clarifying the technical check reads the CIS-CAT flatten result.
        if cis_desc:
            full_desc = f"{cis_desc} [CIS-CAT rule {num}; the technical check below reads the CIS-CAT assessment result from the flatten file.]"
        else:
            full_desc = f"CIS-CAT rule {num} (bridged result)."
        L.append(f"  - id: {cid}")
        L.append(f"    title: {yaml_sq(disp[:TITLE_LIMIT])}")
        L.append(f"    description: {yaml_sq(full_desc[:TEXT_LIMIT])}")
        if rationale:
            L.append(f"    rationale: {yaml_sq(rationale[:TEXT_LIMIT])}")
        if remediation:
            L.append(f"    remediation: {yaml_sq(remediation[:TEXT_LIMIT])}")
        L.append("    condition: all")
        L.append("    rules:")
        L.append(f"      - 'f:{flat_path} -> r:^{esc_rule(num)}:pass$'")
        comp = bench.rule_controls_v8(idref)
        family = num.split(".")[0]
        family_title = families.get(family)
        if comp or family_title:
            # Compliance values must be YAML lists: the Wazuh 4.x agent drops a plain string.
            L.append("    compliance:")
            if comp:
                L.append("      - cis_csc_v8: [" + ", ".join(yaml_sq(c) for c in comp) + "]")
            if family_title:
                # Read by the dashboard and the reporting engine as the family title.
                L.append("      - cis_family: [" + yaml_sq(f"{family} {family_title}") + "]")
    L.append("")
    with open(out + ".yml", "w", encoding="utf-8") as f:
        f.write("\n".join(L))

    M = ["# Manual / not auto-evaluated controls selected for this host (excluded from SCA)",
         f"# profile: {profile_id}", ""]
    for num, idref in in_manual:
        M.append(f"{num}\t{bench.rule_title(idref)}")
    with open(out + ".manual.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(M) + "\n")
    return {"selected": len(sel), "manual": [n for n, _ in in_manual], "checks": len(in_policy),
            "last_id": cid, "families": len(families)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--xccdf", required=True, help="custom XCCDF path")
    ap.add_argument("--profile-id", required=True)
    ap.add_argument("--flat-path", required=True, help="agent path of the flatten file")
    ap.add_argument("--policy-id", required=True, help="SCA policy id, e.g. cis_win2025_tailored_l1_ms")
    ap.add_argument("--policy-name", required=True)
    ap.add_argument("--out", required=True, help="output basename (without extension)")
    args = ap.parse_args()
    try:
        r = generate(args.xccdf, args.profile_id, args.flat_path, args.policy_id,
                     args.policy_name, args.out)
    except (OSError, xccdf.XccdfError) as e:
        sys.exit("ERROR: {0}".format(e))
    print(f"[+] selected total : {r['selected']}")
    print(f"[+] manual excluded: {len(r['manual'])}  -> {r['manual']}")
    print(f"[+] checks in policy: {r['checks']}  (id range {CHECK_ID_BASE + 1}..{r['last_id']})")
    print(f"[+] family titles  : {r['families']}")
    print(f"[+] wrote {args.out}.yml and {args.out}.manual.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
