"""Benchmarks present on the manager -> OS library entries.

Every CIS benchmark dropped into the benchmarks folder (CIS_<Product>_Benchmark_v<version>-xccdf.xml)
becomes an OS of the bridge without editing os-library.json, one per product AND version (two
versions of the same benchmark are two entries, e.g. rhel9_v1_0_0 and rhel9_v2_0_0):

- an entry of os-library.json whose benchmark file is missing follows the newest version of the
  same product found in the folder;
- every other benchmark file gets an entry, derived from the file name and the benchmark's own
  profiles ("Level_1 - <Role>"), with the same Active Response commands as the configured OS of
  its family, and the group os-<key> until a group is chosen in the dashboard (ciscat-targets).
  Benchmarks without "Level_1 - <Role>" profiles (STIG SEVERITY_CAT_*, Level_1, Level_1_L1) get
  "base_profiles": see other_profile().

Entries in os-library.json keep their settings: set "active": false there to keep an OS out of apply
and runs. Choosing a group in the dashboard activates the OS again (the choice is explicit).
"""
import os
import re

# "_Benchmark" is missing from a few names (CIS_Microsoft_Windows_Server_2025_Stand-alone_v2.0.0)
BENCH_RE = re.compile(
    r"^CIS_(?P<product>.+?)(?:_Benchmark)?_v(?P<version>[0-9][0-9A-Za-z.]*)-xccdf\.xml$")
PROFILE_RE = re.compile(
    r'<xccdf:Profile\b[^>]*\bid="xccdf_org\.cisecurity\.benchmarks_profile_'
    r'(Level_1|Level_2|Next_Generation_Windows_Security)_-_([A-Za-z0-9_]+)"')
PROFILE_ID_RE = re.compile(
    r'<xccdf:Profile\b[^>]*\bid="xccdf_org\.cisecurity\.benchmarks_profile_([A-Za-z0-9_.-]+)"')
# other forms of the Level 1 profile, tried in this order when no "Level_1_-_<Role>" profile exists
LEVEL1_FORMS = (
    re.compile(r"^Level_1_?-_(?P<role>[A-Za-z0-9_]+)$"),  # Level_1-_MongoDB
    re.compile(r"^Level_1(_L1)?$"),                         # Level_1 (Apache), Level_1_L1 (Windows 11)
)
STIG_RE = re.compile(r"^(?:(?P<prefix>MS|DC)_)?SEVERITY_CAT_(?P<cat>I{1,3})$")
STIG_ROLES = {None: "STIG", "MS": "Member_Server_STIG", "DC": "Domain_Controller_STIG"}
OS_KEY_RE = re.compile(r"^[a-z0-9_]{1,64}$")

# preferred roles, first match wins; otherwise the first Level 1 role of the benchmark
ROLE_PREFERENCE = ("Server", "Member_Server", "Database_Engine")

DEFAULT_AR = {
    "linux": {"ar_bootstrap": "!ciscat-bootstrap-linux0", "ar_refresh": "!ciscat-refresh-linux0"},
    "windows": {"ar_bootstrap": "!ciscat-bootstrap0", "ar_assessment": "!ciscat-assessment0"},
}
WINDOWS_RESULTS = "C:\\Program Files (x86)\\ciscat\\results\\"
LINUX_RESULTS = "/var/lib/wazuh-ciscat/reports-cache/{0}/results.txt"


def parse_name(filename):
    """(product, version) of a CIS benchmark file name, or None."""
    m = BENCH_RE.match(filename)
    return (m.group("product"), m.group("version")) if m else None


def version_key(version):
    return tuple(int(p) if p.isdigit() else -1 for p in re.split(r"[.]", version))


def os_key_for(product):
    """Red_Hat_Enterprise_Linux_9 -> rhel9, Microsoft_Windows_Server_2022 -> windows_server_2022,
    Ubuntu_Linux_22.04_LTS -> ubuntu_linux_22_04_lts."""
    key = re.sub(r"[^a-z0-9]+", "_", product.lower()).strip("_")
    for prefix, new in (("red_hat_enterprise_linux_", "rhel"),
                        ("microsoft_windows_server_", "windows_server_"),
                        ("microsoft_windows_", "windows_"),
                        ("microsoft_", "")):
        if key.startswith(prefix):
            key = new + key[len(prefix):]
            break
    return key[:60].strip("_") or "os"


def family_for(product):
    return "windows" if product.startswith("Microsoft_") or "Windows" in product else "linux"


def profile_roles(path):
    """Level 1 roles of a benchmark, in document order (e.g. ['Server', 'Workstation'])."""
    roles = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for level, role in PROFILE_RE.findall(f.read()):
            if level == "Level_1" and role not in roles:
                roles.append(role)
    return roles


def profile_ids(path):
    """Ids of the benchmark's profiles without the common prefix, in document order."""
    with open(path, encoding="utf-8", errors="replace") as f:
        ids = PROFILE_ID_RE.findall(f.read())
    return [p for i, p in enumerate(ids) if p not in ids[:i] and "TAILORED" not in p]


def other_profile(ids):
    """(role, [base profiles]) for a benchmark without "Level_1_-_<Role>" profiles, or None.

    The tailored profile of the bridge is built from the base profiles (their union) and keeps the
    usual id, TAILORED_Level_1_-_<role>:
    - STIG benchmarks (SEVERITY_CAT_I/II/III, MS_/DC_ on Windows Server): every category together,
      role STIG (Member_Server_STIG preferred over Domain_Controller_STIG);
    - Level_1-_<Role>: that profile, role <Role>;
    - Level_1 or Level_1_L1 (benchmarks without roles): that profile, role Default.
    """
    stig = {}
    for p in ids:
        m = STIG_RE.match(p)
        if m:
            stig.setdefault(m.group("prefix"), []).append(p)
    for prefix in (None, "MS", "DC"):
        if prefix in stig:
            return STIG_ROLES[prefix], stig[prefix]
    for form in LEVEL1_FORMS:
        for p in ids:
            m = form.match(p)
            if m:
                return (m.groupdict().get("role") or "Default"), [p]
    return None


def present_benchmarks(bench_dir):
    """[(product, version, filename)] of every CIS benchmark in the folder, oldest version first."""
    try:
        names = sorted(os.listdir(bench_dir))
    except OSError:
        return []
    found = [parse_name(n) + (n,) for n in names if parse_name(n)]
    return sorted(found, key=lambda f: (f[0], version_key(f[1])))


def newest(present, product):
    """File name of the newest version of a product, or None."""
    files = [f for p, _, f in present if p == product]
    return files[-1] if files else None


def title_of(product, version):
    """Red_Hat_Enterprise_Linux_9, 2.0.0 -> 'Red Hat Enterprise Linux 9 v2.0.0'."""
    return "{0} v{1}".format(product.replace("_", " "), version)


def _new_entry(os_key, product, version, filename, role, family, ar, base_profiles=None):
    words = title_of(product, version)
    pkey = "l1_" + role.lower()
    entry = {
        "active": True,
        "discovered": True,
        "title": words,
        "family": family,
        "group": "os-" + os_key,
        "benchmark": filename,
        "role": role,
        "profiles": [[pkey, "L1"]],
        "policy_id": "cis_{0}_tailored_{1}".format(os_key, pkey),
        "policy_name": "CIS {0} - TAILORED Level_1 {1} (os-{2})".format(
            words, role.replace("_", " "), os_key),
    }
    if family == "linux":
        entry.update(base=os_key + "-custom", companion_prefix=filename[:-len("-xccdf.xml")],
                     flat_path=LINUX_RESULTS.format(pkey))
    else:
        entry.update(base="cis_{0}_tailored_{1}".format(os_key, pkey),
                     flat_path="{0}cis_{1}.ciscat-flat".format(WINDOWS_RESULTS, os_key))
    if base_profiles:
        entry["base_profiles"] = base_profiles
    entry.update(ar)
    return entry


def merge(library, bench_dir):
    """(library with the benchmarks present, [notes]) - the input is not modified."""
    present = present_benchmarks(bench_dir)
    lib = {k: dict(v) for k, v in library.items()}
    notes = []
    covered = set()
    for os_key, cfg in lib.items():
        parsed = parse_name(cfg.get("benchmark", ""))
        if not parsed:
            continue
        product, version = parsed
        latest = newest(present, product)
        if latest and not os.path.isfile(os.path.join(bench_dir, cfg["benchmark"])):
            notes.append("{0}: {1} missing, using {2}".format(os_key, cfg["benchmark"], latest))
            cfg["benchmark"] = latest
            version = parse_name(latest)[1]
            if cfg.get("family") == "linux":
                cfg["companion_prefix"] = latest[:-len("-xccdf.xml")]
        cfg.setdefault("title", title_of(product, version))
        covered.add(cfg["benchmark"])
    for product, version, filename in present:
        if filename in covered:
            continue
        family = family_for(product)
        key = base_key = "{0}_v{1}".format(os_key_for(product), re.sub(r"[^a-z0-9]+", "_",
                                                                      version.lower()))[:64]
        n = 2
        while key in lib:
            key = "{0}_{1}".format(base_key[:60], n)
            n += 1
        if not OS_KEY_RE.match(key):
            notes.append("{0}: no valid OS key, skipped".format(filename))
            continue
        path = os.path.join(bench_dir, filename)
        roles = profile_roles(path)
        base_profiles = None
        if roles:
            role = next((r for r in ROLE_PREFERENCE if r in roles), roles[0])
        else:
            other = other_profile(profile_ids(path))
            if not other:
                notes.append("{0}: no Level 1 or STIG profile, skipped".format(filename))
                continue
            role, base_profiles = other
        template = next((c for c in lib.values() if c.get("family") == family and
                         not c.get("discovered")), {})
        ar = {k: template[k] for k in DEFAULT_AR[family] if k in template} or DEFAULT_AR[family]
        lib[key] = _new_entry(key, product, version, filename, role, family, ar, base_profiles)
        notes.append("{0}: new OS from {1} (role {2}{3})".format(
            key, filename, role, ", profiles " + " + ".join(base_profiles) if base_profiles else ""))
    return lib, notes


def apply_targets(library, targets):
    """Groups chosen in the dashboard (ciscat-targets) replace the library groups and activate the OS."""
    lib = {k: dict(v) for k, v in library.items()}
    for os_key, rec in targets.items():
        if os_key in lib:
            lib[os_key]["group"] = rec["group"]
            lib[os_key]["group_source"] = "dashboard"
            lib[os_key]["active"] = True
    return lib
