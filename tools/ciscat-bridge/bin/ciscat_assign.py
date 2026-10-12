"""Agent operating system (as the Wazuh agent reports it) -> OS of the bridge.

Used by `ciscat-fleet.py assign`: every agent whose OS has a benchmark in the benchmarks folder is
put into the group of that OS, so a new agent, or a new benchmark, needs no manual step.

- the OS of an agent is its CIS product name, e.g. Red_Hat_Enterprise_Linux_9 or
  Microsoft_Windows_Server_2022, built from os.platform / os.name / os.major / os.minor;
- among the OSes of the library with that product, the newest benchmark version wins (an entry of
  os-library.json before a discovered one of the same version);
- only the standard benchmark of the product: STIG, Stand-alone (Windows outside a domain) and the
  application benchmarks (databases, web servers, browsers...) cannot be told from the agent's OS
  data and are given a group in the dashboard.
"""
import re

import ciscat_discover as discover

# os.platform of the Wazuh agent -> CIS product name ({major}, {minor} from the agent)
LINUX_PRODUCTS = {
    "rhel": "Red_Hat_Enterprise_Linux_{major}",
    "centos": "CentOS_Linux_{major}",
    "ol": "Oracle_Linux_{major}",
    "rocky": "Rocky_Linux_{major}",
    "almalinux": "AlmaLinux_OS_{major}",
    "ubuntu": "Ubuntu_Linux_{major}.{minor}_LTS",
    "debian": "Debian_Linux_{major}",
    "sles": "SUSE_Linux_Enterprise_{major}",
    "sled": "SUSE_Linux_Enterprise_{major}",
    "amzn": "Amazon_Linux_{major}",
    "linuxmint": "Linux_Mint_{major}",
}
# when os.platform is missing or unusual, the name tells the distribution
NAME_PLATFORMS = (
    (re.compile(r"red hat enterprise linux", re.I), "rhel"),
    (re.compile(r"oracle linux", re.I), "ol"),
    (re.compile(r"rocky linux", re.I), "rocky"),
    (re.compile(r"almalinux", re.I), "almalinux"),
    (re.compile(r"centos", re.I), "centos"),
    (re.compile(r"ubuntu", re.I), "ubuntu"),
    (re.compile(r"debian", re.I), "debian"),
    (re.compile(r"suse linux enterprise|sles", re.I), "sles"),
    (re.compile(r"amazon linux", re.I), "amzn"),
    (re.compile(r"linux mint", re.I), "linuxmint"),
)
# OS benchmarks (not applications), with their variants: STIG, Stand-alone (outside a domain)
OS_PRODUCT_RE = re.compile(
    r"^(?P<base>(Red_Hat_Enterprise_Linux|CentOS_Linux|Oracle_Linux|Rocky_Linux|AlmaLinux_OS|"
    r"Debian_Linux|SUSE_Linux_Enterprise|Amazon_Linux|Linux_Mint)_\d+|Ubuntu_Linux_\d+\.\d+_LTS|"
    r"Microsoft_Windows_Server_20\d\d(_R2|_\(non-R2\))?|Microsoft_Windows_1\d(_Enterprise)?)"
    r"(_STIG|_Stand-alone)?$")
WIN_SERVER_RE = re.compile(r"Windows Server (20\d\d)( R2)?", re.I)
WIN_CLIENT_RE = re.compile(r"Windows (1\d)\b", re.I)


def agent_product(os_info):
    """CIS product name of an agent's OS (the "os" object of GET /agents), or None."""
    os_info = os_info or {}
    platform = str(os_info.get("platform") or "").lower()
    name = str(os_info.get("name") or "")
    major = str(os_info.get("major") or "").strip()
    minor = str(os_info.get("minor") or "").strip()
    if platform == "windows" or name.lower().startswith("microsoft windows"):
        m = WIN_SERVER_RE.search(name)
        if m:
            year, r2 = m.group(1), m.group(2)
            if year == "2012":
                return "Microsoft_Windows_Server_2012_R2" if r2 else \
                    "Microsoft_Windows_Server_2012_(non-R2)"
            return "Microsoft_Windows_Server_" + year
        m = WIN_CLIENT_RE.search(name)
        if m:
            return "Microsoft_Windows_{0}_Enterprise".format(m.group(1))
        return None
    if platform not in LINUX_PRODUCTS:
        platform = next((p for rx, p in NAME_PLATFORMS if rx.search(name)), platform)
    template = LINUX_PRODUCTS.get(platform)
    if not template or not major.isdigit():
        return None
    if "{minor}" in template:
        if not minor.isdigit():
            return None
        minor = minor.zfill(2)
    return template.format(major=major, minor=minor)


def os_product(cfg):
    """Base OS product of a library entry (STIG and Stand-alone variants included), or None for an
    application benchmark."""
    parsed = discover.parse_name(cfg.get("benchmark", ""))
    m = OS_PRODUCT_RE.match(parsed[0]) if parsed else None
    if not m:
        return None
    base = m.group("base")
    # Windows 10/11: the Enterprise benchmark and the Stand-alone one are the same OS
    return re.sub(r"^(Microsoft_Windows_1\d)$", r"\1_Enterprise", base)


def choose(library, os_info):
    """(os key, None) of the OS an agent belongs to, or (None, reason)."""
    product = agent_product(os_info)
    if not product:
        name = (os_info or {}).get("name") or (os_info or {}).get("platform")
        return None, "OS {0}".format(name) if name else "OS not known yet"
    found = []
    for key, cfg in library.items():
        parsed = discover.parse_name(cfg.get("benchmark", ""))
        if parsed and parsed[0] == product:
            found.append((discover.version_key(parsed[1]), not cfg.get("discovered"), key))
    if not found:
        return None, "no benchmark for " + product
    key = max(found)[2]
    if not library[key].get("active"):
        return None, "{0} inactive in os-library.json".format(key)
    return key, None
