"""Benchmarks present on the manager -> OS library entries.

Every CIS benchmark dropped into the benchmarks folder (CIS_<Product>_Benchmark_v<version>-xccdf.xml)
becomes an OS of the bridge without editing os-library.json:

- an entry of os-library.json whose benchmark file is missing follows the newest version of the
  same product found in the folder;
- a product with no entry gets one, derived from the file name and the benchmark's own profiles
  ("Level_1 - <Role>"), with the same Active Response commands as the configured OS of its family.

Entries in os-library.json always win: set "active": false there to keep an OS out of apply and runs.
"""
import os
import re

BENCH_RE = re.compile(r"^CIS_(?P<product>.+?)_Benchmark_v(?P<version>[0-9][0-9A-Za-z.]*)-xccdf\.xml$")
PROFILE_RE = re.compile(
    r'<xccdf:Profile\b[^>]*\bid="xccdf_org\.cisecurity\.benchmarks_profile_'
    r'(Level_1|Level_2|Next_Generation_Windows_Security)_-_([A-Za-z0-9_]+)"')
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


def present_benchmarks(bench_dir):
    """{product: (version, filename)} with the newest version of each product."""
    out = {}
    try:
        names = sorted(os.listdir(bench_dir))
    except OSError:
        return out
    for name in names:
        parsed = parse_name(name)
        if not parsed:
            continue
        product, version = parsed
        if product not in out or version_key(version) > version_key(out[product][0]):
            out[product] = (version, name)
    return out


def _new_entry(os_key, product, filename, role, family, ar):
    words = product.replace("_", " ")
    pkey = "l1_" + role.lower()
    entry = {
        "active": True,
        "discovered": True,
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
        product = parsed[0]
        covered.add(product)
        if product in present and not os.path.isfile(os.path.join(bench_dir, cfg["benchmark"])):
            filename = present[product][1]
            notes.append("{0}: {1} missing, using {2}".format(os_key, cfg["benchmark"], filename))
            cfg["benchmark"] = filename
            if cfg.get("family") == "linux":
                cfg["companion_prefix"] = filename[:-len("-xccdf.xml")]
    for product, (_, filename) in sorted(present.items()):
        if product in covered:
            continue
        family = family_for(product)
        key = base_key = os_key_for(product)
        n = 2
        while key in lib:
            key = "{0}_{1}".format(base_key, n)
            n += 1
        if not OS_KEY_RE.match(key):
            notes.append("{0}: no valid OS key, skipped".format(filename))
            continue
        roles = profile_roles(os.path.join(bench_dir, filename))
        if not roles:
            notes.append("{0}: no 'Level 1 - <role>' profile, skipped".format(filename))
            continue
        role = next((r for r in ROLE_PREFERENCE if r in roles), roles[0])
        template = next((c for c in lib.values() if c.get("family") == family and
                         not c.get("discovered")), {})
        ar = {k: template[k] for k in DEFAULT_AR[family] if k in template} or DEFAULT_AR[family]
        lib[key] = _new_entry(key, product, filename, role, family, ar)
        notes.append("{0}: new OS from {1} (role {2})".format(key, filename, role))
    return lib, notes
