#!/usr/bin/env python3
"""
Manager-side generator: from a tailored XCCDF (custom) + chosen tailored profile,
produce a Wazuh SCA policy YAML for one host.

Model:
  - controls in policy = profile selects with selected=true, MINUS manual controls
  - manual controls = Rule elements WITHOUT <xccdf:check>/<complex-check> (no OVAL) -> excluded, listed apart
  - each SCA check: integer id, title carries CIS rule number, rule reads flatten file:
        f:<flat_path> -> r:^<rule_escaped>:pass$
  - requirements: flatten file must exist (else policy not evaluated; avoids false 326-fail)

Output:
  - <out>.yml          Wazuh SCA policy
  - <out>.manual.txt   manual controls selected for this host (tracking, audit)
"""
import re, argparse, sys, html

def load(path):
    return open(path, encoding="utf-8").read()

def get_profile_block(xml, profile_id):
    pat = r'<xccdf:Profile\b[^>]*id="' + re.escape(profile_id) + r'".*?</xccdf:Profile>'
    m = re.search(pat, xml, re.DOTALL)
    return m.group(0) if m else None

def selected_rules(profile_block):
    """Return list of (rule_number, idref) for selected=true, in document order."""
    out = []
    for idref, sel in re.findall(r'<xccdf:select\s+idref="([^"]+)"\s+selected="(true|false)"', profile_block):
        if sel != "true":
            continue
        m = re.search(r'_rule_([0-9.]+)_', idref)
        if m:
            out.append((m.group(1), idref))
    return out

def manual_rule_numbers(xml):
    """Rules without any check element are manual (no OVAL). Return set of rule numbers."""
    manual = set()
    for b in re.findall(r'<xccdf:Rule\b.*?</xccdf:Rule>', xml, re.DOTALL):
        if ('<xccdf:complex-check' in b) or ('<check system=' in b):
            continue
        m = re.search(r'id="[^"]*_rule_([0-9.]+)_', b)
        if m:
            manual.add(m.group(1))
    return manual

def rule_title(xml, idref):
    """Best-effort extract the Rule title for nicer SCA titles."""
    pat = r'<xccdf:Rule\b[^>]*id="' + re.escape(idref) + r'".*?<xccdf:title[^>]*>(.*?)</xccdf:title>'
    m = re.search(pat, xml, re.DOTALL)
    if not m:
        return ""
    t = re.sub(r'<[^>]+>', '', m.group(1))
    return re.sub(r'\s+', ' ', t).strip()

def _clean_xhtml(text):
    """Convert CIS XHTML markup (rationale/fixtext) into clean single-line text for YAML."""
    if not text:
        return ""
    t = text
    t = re.sub(r'<xhtml:br\s*/?>', '\n', t)
    t = re.sub(r'</xhtml:p>', '\n', t)
    t = re.sub(r'<xhtml:li>', '\n- ', t)
    # links: <a href="X">Y</a> -> Y (X)
    t = re.sub(r'<xhtml:a[^>]*href="([^"]*)"[^>]*>(.*?)</xhtml:a>', r'\2 (\1)', t, flags=re.DOTALL)
    t = re.sub(r'</?xhtml:[^>]+>', '', t)          # strip remaining xhtml tags
    t = re.sub(r'</?[a-zA-Z][^>]*>', '', t)         # strip any stray tags
    t = html.unescape(t)
    lines = [re.sub(r'[ \t]+', ' ', ln).strip() for ln in t.split('\n')]
    lines = [ln for ln in lines if ln]
    return ' '.join(lines).strip()


def _trim_remediation_scripts(text, num=None):
    """Keep the descriptive prose of a CIS remediation and drop embedded
    scripts: cut at the first script marker (shebang or opening brace block).
    The CIS fixtext always puts the prose steps BEFORE the script, so the
    actionable guidance is preserved; a pointer to the benchmark is appended."""
    if not text:
        return text
    markers = ["#!/usr/bin/env", "#!/bin/bash", "#!/bin/sh", "#!powershell"]
    cut = len(text)
    for mk in markers:
        i = text.find(mk)
        if i != -1 and i < cut:
            cut = i
    if cut == len(text):
        return text
    head = text[:cut].rstrip(" -\t")
    ref = " [Full remediation script: see the CIS benchmark{0}.]".format(
        ", rule {0}".format(num) if num else "")
    return head.rstrip() + ref

def rule_rationale_fix(xml, idref):
    """Extract cleaned (rationale, remediation) for a Rule by idref."""
    m = re.search(r'<xccdf:Rule\b[^>]*id="' + re.escape(idref) + r'".*?</xccdf:Rule>', xml, re.DOTALL)
    if not m:
        return "", ""
    rule = m.group(0)
    rat = re.search(r'<xccdf:rationale[^>]*>(.*?)</xccdf:rationale>', rule, re.DOTALL)
    fix = re.search(r'<xccdf:fixtext[^>]*>(.*?)</xccdf:fixtext>', rule, re.DOTALL)
    _rat = _clean_xhtml(rat.group(1) if rat else "")
    _fix = _trim_remediation_scripts(_clean_xhtml(fix.group(1) if fix else ""))
    return _rat, _fix

def rule_description(xml, idref):
    """Extract cleaned CIS <description> for a Rule by idref (what the control verifies + recommended value)."""
    m = re.search(r'<xccdf:Rule\b[^>]*id="' + re.escape(idref) + r'".*?</xccdf:Rule>', xml, re.DOTALL)
    if not m:
        return ""
    rule = m.group(0)
    desc = re.search(r'<xccdf:description[^>]*>(.*?)</xccdf:description>', rule, re.DOTALL)
    return _clean_xhtml(desc.group(1)) if desc else ""

def rule_compliance(xml, idref):
    """Extract CIS Controls v8 mappings (control.subcontrol) for a Rule by idref.
    The WS2025 benchmark maps natively only to CIS Controls v8 (cc8:controlURI)."""
    m = re.search(r'<xccdf:Rule\b[^>]*id="' + re.escape(idref) + r'".*?</xccdf:Rule>', xml, re.DOTALL)
    if not m:
        return []
    rule = m.group(0)
    uris = re.findall(r'cc8:controlURI="http://cisecurity\.org/20-cc/v8\.0/control/(\d+)/subcontrol/(\d+)"', rule)
    seen, out = set(), []
    for c, s in uris:
        v = f"{c}.{s}"
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out

def family_titles(xml):
    """Titles of the benchmark's top-level groups by family number, e.g. {"1": "Initial Setup"}.
    CIS group IDs carry the number: xccdf_org.cisecurity.benchmarks_group_<N>_...; sub-groups
    (<N>.<M>) are skipped. Works for any CIS benchmark (Linux, Windows, AIX, ...) and version."""
    out = {}
    for m in re.finditer(r'<xccdf:Group\b[^>]*\bid="[^"]*_group_(\d+)_[^"]*"[^>]*>', xml):
        t = re.search(r'<xccdf:title[^>]*>(.*?)</xccdf:title>', xml[m.end():m.end() + 4000], re.DOTALL)
        if not t or m.group(1) in out:
            continue
        title = re.sub(r'\s+', ' ', html.unescape(re.sub(r'<[^>]+>', '', t.group(1)))).strip()
        title = title.replace('|', '/')  # '|' separates fields in the manager's wazuh-db message
        if title:
            out[m.group(1)] = title
    return out

def yaml_sq(s):
    """Quote a string for YAML using single quotes (no escape interpretation).
    A literal single quote is doubled per YAML spec."""
    s = s.strip().replace("'", "''")
    return "'" + s + "'"

def esc_rule(num):
    return num.replace(".", r"\.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--xccdf", required=True, help="custom XCCDF path")
    ap.add_argument("--profile-id", required=True)
    ap.add_argument("--flat-path", required=True, help="agent path of the flatten file")
    ap.add_argument("--policy-id", required=True, help="SCA policy id, e.g. cis_win2025_tailored_l1_ms")
    ap.add_argument("--policy-name", required=True)
    ap.add_argument("--out", required=True, help="output basename (without extension)")
    args = ap.parse_args()

    xml = load(args.xccdf)
    prof = get_profile_block(xml, args.profile_id)
    if not prof:
        sys.exit(f"profile not found: {args.profile_id}")

    sel = selected_rules(prof)
    manual = manual_rule_numbers(xml)

    families = family_titles(xml)
    in_policy = [(n, idref) for (n, idref) in sel if n not in manual]
    in_manual = [(n, idref) for (n, idref) in sel if n in manual]

    # build YAML
    L = []
    L.append("policy:")
    L.append(f"  id: {yaml_sq(args.policy_id)}")
    L.append(f"  file: {yaml_sq(args.policy_id + chr(46) + 'yml')}")
    L.append(f"  name: {yaml_sq(args.policy_name)}")
    L.append('  description: ' + yaml_sq('CIS-CAT tailored results bridged into Wazuh SCA (flatten-based).'))
    L.append("")
    L.append("requirements:")
    L.append('  title: ' + yaml_sq('CIS-CAT Pro installed and assessment results present'))
    L.append('  description: ' + yaml_sq('The flatten file is produced after a CIS-CAT assessment and withdrawn when CIS-CAT Pro is not found on the agent. If absent, the policy is not evaluated.'))
    L.append("  condition: all")
    L.append("  rules:")
    L.append(f"    - 'f:{args.flat_path}'")
    L.append("")
    L.append("checks:")

    cid = 5000  # integer id base; keep room and avoid collisions with stock policies
    for num, idref in in_policy:
        cid += 1
        title = rule_title(xml, idref)
        disp = f"{num} {title}" if title else num
        rationale, remediation = rule_rationale_fix(xml, idref)
        cis_desc = rule_description(xml, idref)
        # description = CIS control description (what it verifies + recommended value),
        # plus a note clarifying the technical check reads the CIS-CAT flatten result.
        if cis_desc:
            full_desc = f"{cis_desc} [CIS-CAT rule {num}; the technical check below reads the CIS-CAT assessment result from the flatten file.]"
        else:
            full_desc = f"CIS-CAT rule {num} (bridged result)."
        L.append(f"  - id: {cid}")
        L.append(f"    title: {yaml_sq(disp[:250])}")
        L.append(f"    description: {yaml_sq(full_desc[:2000])}")
        if rationale:
            L.append(f"    rationale: {yaml_sq(rationale[:2000])}")
        if remediation:
            L.append(f"    remediation: {yaml_sq(remediation[:2000])}")
        L.append("    condition: all")
        L.append("    rules:")
        L.append(f"      - 'f:{args.flat_path} -> r:^{esc_rule(num)}:pass$'")
        comp = rule_compliance(xml, idref)
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

    open(args.out + ".yml", "w", encoding="utf-8").write("\n".join(L))

    # manual tracking file
    M = [f"# Manual / not auto-evaluated controls selected for this host (excluded from SCA)",
         f"# profile: {args.profile_id}", ""]
    for num, idref in in_manual:
        M.append(f"{num}\t{rule_title(xml, idref)}")
    open(args.out + ".manual.txt", "w", encoding="utf-8").write("\n".join(M) + "\n")

    print(f"[+] selected total : {len(sel)}")
    print(f"[+] manual excluded: {len(in_manual)}  -> {[n for n,_ in in_manual]}")
    print(f"[+] checks in policy: {len(in_policy)}  (id range 5001..{cid})")
    print(f"[+] family titles  : {len(families)}")
    print(f"[+] wrote {args.out}.yml and {args.out}.manual.txt")

if __name__ == "__main__":
    main()
