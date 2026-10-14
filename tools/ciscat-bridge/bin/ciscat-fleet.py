#!/usr/bin/env python3
"""ciscat-fleet.py - MANAGER side fleet orchestrator for the CIS-CAT / Wazuh SCA bridge.

Model:
  - os-<os> group: custom XCCDF (OS and global exclusions), benchmark companions and agent
    scripts. Every agent of the OS runs the Assessor with this custom.
  - ciscat-<os_key>-<combo> groups: the SCA policy. Agents with the same host/app_group
    exclusions share a combo; "base" is the combo without any. The policy keeps the same id
    and file name in every combo, so reports stay one policy with fewer checks where excluded.
  - Exclusions, schedules and requests come from the dashboard through Wazuh lists
    (etc/lists/ciscat-*, see CONTRACT.md); this script also publishes the benchmark sheets and
    OS list the dashboard reads.

Actions:
  sync      publish benchmark sheets + OS list for the dashboard (ciscat-bench-*, ciscat-oskeys)
  plan      dry-run of apply
  apply     regenerate custom XCCDF + policies, publish groups, assign agents to combos
  trigger   bootstrap + assessment in waves, on the agents of the target OSes, on chosen agents
            (--agents) or on the agents of chosen groups (--groups: OS or custom groups)
  history   coverage of the day per OS (ciscat-history), run daily by the scheduler
  assign    every agent into the group of its OS benchmark, from the OS the agent reports
            (dry-run; --apply assigns, then publishes; --auto: only with auto_assign=yes)
  baseline  groups owned by infrastructure code (Terraform): create them, write their agent.conf,
            add the listed agents (--file baseline.json)
  report    SCA scores per agent
  exclusions  the exclusion register as CSV (audit evidence), with who changed each and when
"""
import argparse
import base64
import csv
import fcntl
import grp
import hashlib
import io
import json
import os
import pwd
import re
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

BIN_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BIN_DIR)
import benchmark_to_sheet as sheet  # noqa: E402
import ciscat_assign as assign  # noqa: E402
import ciscat_discover as discover  # noqa: E402
import ciscat_store as store  # noqa: E402
import ciscat_xccdf as xccdf  # noqa: E402
import csv_to_custom_xccdf as tailor  # noqa: E402
import xccdf_to_sca_policy as gen  # noqa: E402

VERSION = "2.3.1"
ETC_DIR = os.environ.get("CISCAT_ETC_DIR", "/opt/ciscat/etc")
OS_LIBRARY_FILE = os.path.join(ETC_DIR, "os-library.json")
ORCH_CONF = os.path.join(ETC_DIR, "ciscat-orchestrator.conf")
COMBO_PREFIX = "ciscat-"
# files of one OS in a group it may share with other OSes
LINUX_CONF = "ciscat-refresh-{0}.conf"         # -> /var/lib/wazuh-ciscat/conf.d/<os>.conf
WINDOWS_PARAMS = "ciscat-params-{0}.txt"
OS_MANIFEST = "ciscat-manifest-{0}.csv"
# the manifests are signed (RSA, SHA-256): agents verify them with the public key their
# installer put in a root/Administrators-only place, so nobody who can only write the group
# folders (the wazuh user, here or on an agent) can make them run other files
SIGN_KEY = os.path.join(ETC_DIR, "manifest-signing.key")
SIGN_PUB = os.path.join(ETC_DIR, "ciscat-manifest.pub")
SIGN_PUB_XML = os.path.join(ETC_DIR, "ciscat-manifest.pub.xml")
WINDOWS_RUN = "C:\\CIS\\run\\"
# group-wide files read by agent scripts older than 2.3.0
LEGACY_MANIFEST = "ciscat-manifest.csv"
LEGACY_PARAMS = "ciscat-params.txt"
LEGACY_REFRESH_CONF = "refresh.conf"
AR_GAP = int(os.environ.get("CISCAT_AR_GAP", "15"))
# API tokens expire after 900 s by default: a new one is taken when the current one is older
TOKEN_MAX_AGE = int(os.environ.get("CISCAT_TOKEN_MAX_AGE", "600"))

# Seed for os-library.json (created by the installer only when missing, then edited on site).
DEFAULT_OS_LIBRARY = {
    "rhel7": {
        "active": True,
        "family": "linux",
        "group": "os-rhel7",
        "benchmark": "CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v4.0.0-xccdf.xml",
        "companion_prefix": "CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v4.0.0",
        "base": "rhel7-custom",
        "role": "Server",
        "profiles": [["l1_server", "L1"]],
        "policy_id": "cis_rhel7_tailored_l1_server",
        "policy_name": "CIS Red Hat Enterprise Linux 7 - TAILORED Level_1 Server (os-rhel7)",
        "flat_path": "/var/lib/wazuh-ciscat/reports-cache/l1_server/results.txt",
        "ar_bootstrap": "!ciscat-bootstrap-linux0",
        "ar_refresh": "!ciscat-refresh-linux0",
    },
    "windows_server_2025": {
        "active": True,
        "family": "windows",
        "group": "os-windows_server_2025",
        "benchmark": "CIS_Microsoft_Windows_Server_2025_Benchmark_v2.0.0-xccdf.xml",
        "base": "cis_win2025_tailored_l1_ms",
        "role": "Member_Server",
        "profiles": [["l1_ms", "L1"]],
        "policy_id": "cis_win2025_tailored_l1_ms",
        "policy_name": "CIS Microsoft Windows Server 2025 - TAILORED Level_1 Member Server (os-windows_server_2025)",
        "flat_path": "C:\\CIS\\results\\cis_win2025_v2.0.0.ciscat-flat",
        "ar_bootstrap": "!ciscat-bootstrap0",
        "ar_assessment": "!ciscat-assessment0",
    },
    "rhel8": {
        "active": False,
        "family": "linux",
        "group": "os-rhel8",
        "benchmark": "CIS_Red_Hat_Enterprise_Linux_8_Benchmark_v3.0.0-xccdf.xml",
        "companion_prefix": "CIS_Red_Hat_Enterprise_Linux_8_Benchmark_v3.0.0",
        "base": "rhel8-custom",
        "role": "Server",
        "profiles": [["l1_server", "L1"]],
        "policy_id": "cis_rhel8_tailored_l1_server",
        "policy_name": "CIS Red Hat Enterprise Linux 8 - TAILORED Level_1 Server (os-rhel8)",
        "flat_path": "/var/lib/wazuh-ciscat/reports-cache/l1_server/results.txt",
        "ar_bootstrap": "!ciscat-bootstrap-linux0",
        "ar_refresh": "!ciscat-refresh-linux0",
    },
    "debian12": {
        "active": False,
        "family": "linux",
        "group": "os-debian12",
        "benchmark": "CIS_Debian_Linux_12_Benchmark_v1.1.0-xccdf.xml",
        "companion_prefix": "CIS_Debian_Linux_12_Benchmark_v1.1.0",
        "base": "debian12-custom",
        "role": "Server",
        "profiles": [["l1_server", "L1"]],
        "policy_id": "cis_debian12_tailored_l1_server",
        "policy_name": "CIS Debian Linux 12 - TAILORED Level_1 Server (os-debian12)",
        "flat_path": "/var/lib/wazuh-ciscat/reports-cache/l1_server/results.txt",
        "ar_bootstrap": "!ciscat-bootstrap-linux0",
        "ar_refresh": "!ciscat-refresh-linux0",
    },
}

PATHS = {
    "exclusions_dir": "/opt/ciscat/tailoring/exclusions",
    "benchmarks_dir": "/opt/ciscat/benchmarks",
    "bin_dir": BIN_DIR,
    "shared_dir": "/var/ossec/etc/shared",
    "work_dir": "/opt/ciscat/work",
    "lists_dir": store.LISTS_DIR,
    "run_dir": "/opt/ciscat/run",
    # agent scripts the master publishes to the Windows agents (installed by the installer)
    "agent_dir": "/opt/ciscat/agent/active-response",
    # CIS-CAT Pro license: when present, every agent gets it through the signed manifest (renewal:
    # copy the new file here and apply)
    "license_file": "/opt/ciscat/license/license.xml",
}
# where the Windows agent installs what the manifest lists (C:\CIS: Assessor and bridge files)
WINDOWS_BENCH = "C:\\CIS\\Assessor\\benchmarks\\"
WINDOWS_BIN = "C:\\CIS\\bin\\"
WINDOWS_SCRIPTS = ("ciscat-assessment.ps1", "ciscat-csv-to-flat.ps1")
if os.environ.get("CISCAT_PATHS_JSON"):  # tests
    PATHS.update(json.loads(os.environ["CISCAT_PATHS_JSON"]))

API = {"url": os.environ.get("CISCAT_API_URL", "https://localhost:55000"), "user": "wazuh",
       "password": "", "ca": None}
_TOKEN = {"value": None, "at": 0.0}


def load_os_library():
    """(OS library, discovery notes): os-library.json (or the seed above), the benchmarks found
    in the benchmarks folder and the groups chosen in the dashboard."""
    if os.path.isfile(OS_LIBRARY_FILE):
        with open(OS_LIBRARY_FILE, encoding="utf-8") as f:
            lib = json.load(f)
    else:
        lib = DEFAULT_OS_LIBRARY
    for key, cfg in lib.items():
        if not store.OS_KEY_RE.match(key):
            sys.exit("os-library: invalid os key {0!r}".format(key))
        # joined into paths written as root: group names and plain file names only
        if not isinstance(cfg, dict) or not store.NAME_RE.match(str(cfg.get("group", ""))):
            sys.exit("os-library: {0}: invalid group {1!r}".format(key, cfg.get("group")))
        for field in ("base", "benchmark", "companion_prefix"):
            value = cfg.get(field)
            if value is not None and not re.match(r"^[A-Za-z0-9._()+-]{1,200}$", str(value)) \
                    or str(value or "").startswith("."):
                sys.exit("os-library: {0}: invalid {1} {2!r}".format(key, field, value))
    # every benchmark present in the benchmarks folder is an OS too (see ciscat_discover.py)
    lib, notes = discover.merge(lib, PATHS["benchmarks_dir"])
    # the group each OS applies to can be chosen in the dashboard
    records, _ = store.read_list(store.TARGETS, PATHS["lists_dir"])
    targets, errors = store.validate_targets(records)
    notes += ["ciscat-targets: " + e for e in errors]
    lib = discover.apply_targets(lib, targets)
    # Linux results are kept per OS on the agent (several benchmarks can apply to one agent):
    # the path is the bridge's, whatever an older os-library.json says
    for key, cfg in lib.items():
        if cfg.get("family") == "linux":
            cfg["flat_path"] = linux_results(key, cfg["profiles"][0][0])
        elif cfg.get("family") == "windows":
            # results in C:\CIS\results on every Windows agent, whatever an older library says
            name = cfg.get("flat_path", "").replace("/", "\\").split("\\")[-1] or \
                "cis_{0}.ciscat-flat".format(key)
            cfg["flat_path"] = discover.WINDOWS_RESULTS + name
    return lib, notes


def linux_results(os_key, profile_key):
    return discover.LINUX_RESULTS.format(os_key, profile_key)


# filled by main(): importing this module reads nothing
OS_LIBRARY, DISCOVERY_NOTES = {}, []
VERBOSE = False  # -v: one line per benchmark found and per OS without a group


# ----------------------------------------------------------------- helpers
def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def sh(cmd):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.decode()


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_atomic(path, data):
    """Writes a file through a hidden temporary file in the same folder (remoted skips hidden
    files), so agents and readers never see it half written. The temporary name is created
    exclusively (mkstemp): the group folders are writable by the wazuh user, and a name planted
    there in advance (a link) must not be followed by root."""
    folder = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".{0}.".format(os.path.basename(path)),
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "wb" if isinstance(data, bytes) else "w") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def copy_atomic(src, dst):
    with open(src, "rb") as f:
        write_atomic(dst, f.read())


# A Windows agent writes the group files it receives in text mode (UnmergeFiles with OS_TEXT):
# every LF becomes CRLF, and a CRLF in the source would shift the reading of the files after it.
# So Windows files are published with LF only, and their manifest lists the SHA-256 of the CRLF
# copy the agent ends up with, which is what ciscat-bootstrap.ps1 checks.
def copy_for_windows(src, dst):
    with open(src, "rb") as f:
        write_atomic(dst, f.read().replace(b"\r\n", b"\n"))


def windows_sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read().replace(b"\n", b"\r\n")).hexdigest()


LOOPBACK = ("localhost", "127.0.0.1", "::1")


def ssl_context(ca):
    """Verified TLS when the conf names a CA (api_ca); otherwise only the local manager API, with
    its default self-signed certificate: credentials never go unverified to another host."""
    if ca:
        return ssl.create_default_context(cafile=ca)
    host = urllib.parse.urlsplit(API["url"]).hostname or ""
    if host not in LOOPBACK:
        sys.exit("API {0}: not on this host, set api_ca in {1} (TLS is verified for a remote "
                 "API)".format(API["url"], ORCH_CONF))
    return ssl._create_unverified_context()


API_TRIES = 5
# The Wazuh API takes max_request_per_minute requests (300 by default) for ALL its users: past
# that it refuses every request, the dashboard's too, until the minute ends. The bridge keeps
# to a share of it (api_max_per_minute in ciscat-orchestrator.conf, 0 = no limit).
API_DEFAULT_PER_MINUTE = 100
_API_SENT = []


def api_pace():
    limit = API.get("per_minute", API_DEFAULT_PER_MINUTE)
    if not limit:
        return
    while True:
        now = time.monotonic()
        while _API_SENT and now - _API_SENT[0] >= 60:
            _API_SENT.pop(0)
        if len(_API_SENT) < limit:
            _API_SENT.append(now)
            return
        time.sleep(60 - (now - _API_SENT[0]) + 0.05)
API_WAIT = int(os.environ.get("CISCAT_API_WAIT", "15"))  # seconds, times the attempt number


def api_call(method, endpoint, token=None, body=None, raw=None):
    ctx = ssl_context(API["ca"])
    req = urllib.request.Request(API["url"] + endpoint, method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    else:
        cred = base64.b64encode((API["user"] + ":" + API["password"]).encode()).decode()
        req.add_header("Authorization", "Basic " + cred)
    if body is not None:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(body).encode()
    elif raw is not None:  # an agent.conf: the API only takes it as XML
        req.add_header("Content-Type", "application/xml")
        req.data = raw.encode()
    for attempt in range(1, API_TRIES + 1):
        api_pace()
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=120) as r:
                return r.read().decode()
        except urllib.error.HTTPError as e:
            # the Wazuh API takes a limited number of requests per minute
            # (max_request_per_minute of api.yaml): wait for the next minute and go on
            if e.code != 429 or attempt == API_TRIES:
                raise
            print("    API busy (429 Too Many Requests): waiting {0}s".format(API_WAIT * attempt))
            time.sleep(API_WAIT * attempt)


def api_json(method, endpoint, token, body=None, raw=None):
    data = json.loads(api_call(method, endpoint, token, body, raw))
    if data.get("error") not in (0, None):
        raise RuntimeError("API {0} {1}: {2}".format(method, endpoint, data.get("message")))
    return data.get("data", {})


def get_token():
    try:
        token = api_call("POST", "/security/user/authenticate?raw=true")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            sys.exit("Wazuh API authentication failed for user '{0}' (password from {1}). Update the "
                     "password file (chmod 600) or pass --password-file.".format(
                         API["user"], API.get("source") or "the default"))
        raise
    _TOKEN.update(value=token, at=time.monotonic())
    return token


def fresh_token():
    """The current token, or a new one when it is about to expire (long runs in waves)."""
    if _TOKEN["value"] is None or time.monotonic() - _TOKEN["at"] >= TOKEN_MAX_AGE:
        return get_token()
    return _TOKEN["value"]


AGENT_FIELDS = "id,name,status,group,os.platform"


def agent_record(a):
    return {"id": a["id"], "name": a.get("name", "?"), "status": a.get("status"),
            "groups": a.get("group") or [],
            "platform": str((a.get("os") or {}).get("platform") or "").lower()}


def paged(token, endpoint):
    """Every affected item of a GET endpoint (it has no limit/offset yet)."""
    out, offset = [], 0
    sep = "&" if "?" in endpoint else "?"
    while True:
        data = api_json("GET", "{0}{1}limit=500&offset={2}".format(endpoint, sep, offset), token)
        items = data.get("affected_items", [])
        out += items
        offset += len(items)
        if not items or offset >= data.get("total_affected_items", 0):
            return out


def group_agent_records(token, group):
    """Every agent of a group, the manager aside: [{id, name, status, groups, platform}]."""
    items = paged(token, "/groups/{0}/agents?select={1}".format(urllib.parse.quote(group),
                                                                 AGENT_FIELDS))
    return [agent_record(a) for a in items if a["id"] != "000"]


def agent_records(token, ids):
    """{id: record} of the given agents (unknown ids are left out)."""
    out = {}
    for i in range(0, len(ids), 250):
        items = paged(token, "/agents?agents_list={0}&select={1}".format(
            ",".join(ids[i:i + 250]), AGENT_FIELDS))
        out.update({a["id"]: agent_record(a) for a in items if a["id"] in ids})
    return out


def wrong_platform(cfg, platform):
    """True unless the agent is known to be of the benchmark's platform: a Windows benchmark
    never goes to a Linux or other Unix-like agent, nor the reverse (the assessment would fail,
    and the agent would get a policy of another OS). An agent that never connected has no
    platform yet: it gets nothing until it has one."""
    if not platform:
        return True
    return (platform == "windows") != (cfg.get("family") == "windows")


def group_agents(token, group, active_only=True, verbose=True):
    """[(id, name, [groups])] of a group."""
    out = []
    for a in group_agent_records(token, group):
        if active_only and a["status"] != "active":
            if verbose:
                print("  [skip] {0} {1}: status={2}".format(a["id"], a["name"], a["status"]))
            continue
        out.append((a["id"], a["name"], a["groups"]))
    return out


def existing_groups(token):
    return {g["name"] for g in api_json("GET", "/groups?limit=100000&select=name", token)
            .get("affected_items", [])}


def profile_name(os_key, level, role):
    # matches the naming produced by csv_to_custom_xccdf.py with --host <group>
    return "TAILORED {0} - {1} ({2})".format(level, role.replace("_", " "), OS_LIBRARY[os_key]["group"])


def profile_id(level, role):
    lvl = {"L1": "Level_1", "L2": "Level_2"}[level]
    return "xccdf_org.cisecurity.benchmarks_profile_TAILORED_{0}_-_{1}".format(lvl, role)


def combo_group(os_key, combo):
    return "{0}{1}-{2}".format(COMBO_PREFIX, os_key, combo)


def openssl(*args, data=None):
    r = subprocess.run(["openssl"] + list(args), input=data, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
    if r.returncode != 0:
        raise RuntimeError("openssl {0}: {1}".format(
            args[0], r.stderr.decode(errors="replace")[:300]))
    return r.stdout


def signing_key():
    """The manifest signing key, created once (RSA 3072, root only), with its public key as PEM
    (Linux agents) and as .NET RSAKeyValue XML (Windows agents) next to it."""
    os.makedirs(ETC_DIR, exist_ok=True)
    if not os.path.isfile(SIGN_KEY):
        old = os.umask(0o077)
        try:
            tmp = SIGN_KEY + ".new"
            openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072",
                    "-out", tmp)
            os.chmod(tmp, 0o600)
            os.replace(tmp, SIGN_KEY)
        finally:
            os.umask(old)
        print("manifest signing key created: {0}".format(SIGN_KEY))
    if not os.path.isfile(SIGN_PUB) or not os.path.isfile(SIGN_PUB_XML):
        pem = openssl("pkey", "-in", SIGN_KEY, "-pubout")
        text = openssl("pkey", "-in", SIGN_KEY, "-noout", "-text_pub").decode()
        mod = re.search(r"Modulus:\s*\n((?:\s+[0-9a-f:]+\n)+)", text)
        exp = re.search(r"Exponent:\s*(\d+)", text)
        if not mod or not exp:
            raise RuntimeError("cannot read the public key of " + SIGN_KEY)
        n = bytes.fromhex(re.sub(r"[\s:]", "", mod.group(1))).lstrip(b"\x00")
        e = int(exp.group(1))
        e = e.to_bytes((e.bit_length() + 7) // 8, "big")
        xml = "<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent></RSAKeyValue>\n".format(
            base64.b64encode(n).decode(), base64.b64encode(e).decode())
        write_atomic(SIGN_PUB, pem.decode())
        write_atomic(SIGN_PUB_XML, xml)
        for path in (SIGN_PUB, SIGN_PUB_XML):
            os.chmod(path, 0o644)
    return SIGN_KEY


def key_fingerprint():
    """SHA-256 of the public key (DER): what the agent installers print, to compare."""
    der = openssl("pkey", "-in", signing_key(), "-pubout", "-outform", "DER")
    return hashlib.sha256(der).hexdigest()


LICENSE_NAME = "ciscat-license.xml.b64"


def publish_license(gdir, windows):
    """The license as base64 text (byte-exact through the agents' text-mode copy), or None when
    the master has no license file. Returns the manifest line."""
    src = PATHS["license_file"]
    path = os.path.join(gdir, LICENSE_NAME)
    if not os.path.isfile(src):
        if os.path.isfile(path) and not os.path.islink(path):
            os.remove(path)  # the master's license was removed: the agents keep theirs
        return None
    with open(src, "rb") as f:
        data = base64.encodebytes(f.read()).decode()
    write_atomic(path, data)
    if windows:
        return "{0};{1};C:\\CIS\\Assessor\\license\\license.xml:b64".format(
            LICENSE_NAME, windows_sha256(path))
    return "{0};{1};/opt/ciscat/Assessor/license/license.xml:b64".format(LICENSE_NAME, sha256(path))


def publish_pubkey(gdir, windows):
    """The public key travels with the group files: an agent installed without it keeps the first
    one it gets (trust on first use) and ignores any other one later. Returns its file name."""
    signing_key()
    src, name = (SIGN_PUB_XML, "ciscat-manifest.pub.xml") if windows else \
        (SIGN_PUB, "ciscat-manifest.pub")
    (copy_for_windows if windows else copy_atomic)(src, os.path.join(gdir, name))
    return name


def sign_manifest(path):
    """<manifest>.sig: base64 of the RSA/SHA-256 signature of the manifest as written (LF)."""
    sig = openssl("dgst", "-sha256", "-sign", signing_key(), path)
    write_atomic(path + ".sig", base64.b64encode(sig).decode() + "\n")
    return os.path.basename(path) + ".sig"


def is_combo_group(os_key, group):
    """Only the groups this script names: ciscat-<os_key>-base or ciscat-<os_key>-<10 hex>."""
    return re.match(r"^{0}{1}-(base|[0-9a-f]{{10}})$".format(
        re.escape(COMBO_PREFIX), re.escape(os_key)), group) is not None


def own(path, mode=0o640):
    """wazuh:wazuh and mode on a file the bridge wrote. Never through a link: the group folders
    are writable by the wazuh user, so a link there could point root at any file (O_NOFOLLOW,
    then fchown/fchmod on what was opened)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    except OSError as e:
        print("    WARNING: ownership {0}: not changed ({1})".format(path, e.strerror))
        return
    try:
        os.fchown(fd, pwd.getpwnam("wazuh").pw_uid, grp.getgrnam("wazuh").gr_gid)
        os.fchmod(fd, mode)
    except Exception as e:
        print("    WARNING: ownership {0}: {1}".format(path, e))
    finally:
        os.close(fd)


def own_dir(gdir):
    for fn in os.listdir(gdir):
        path = os.path.join(gdir, fn)
        if not os.path.islink(path):
            own(path)


def ensure_agent_conf(gdir):
    """An OS group made outside the Wazuh API (a folder created or copied by hand) has no
    agent.conf, and the API then refuses to read the group (the dashboard cannot manage it):
    give it the empty one Wazuh writes for a new group. An existing agent.conf is never changed."""
    path = os.path.join(gdir, "agent.conf")
    if os.path.lexists(path):
        return
    write_atomic(path, "<agent_config>\n\n</agent_config>\n")
    own(path, 0o660)
    print("    created empty agent.conf (the group had none)")


def group_dir(group):
    """The shared folder of a group, created if missing; refused when it is a link or not a
    folder of the shared directory (the wazuh user can write there)."""
    if not store.NAME_RE.match(group) or group in (".", ".."):
        raise RuntimeError("invalid group name: {0!r}".format(group))
    gdir = os.path.join(PATHS["shared_dir"], group)
    if os.path.islink(gdir):
        raise RuntimeError("{0} is a link: refused".format(gdir))
    os.makedirs(gdir, exist_ok=True)
    if os.path.islink(gdir) or not os.path.isdir(gdir) or \
            os.path.dirname(os.path.realpath(gdir)) != os.path.realpath(PATHS["shared_dir"]):
        raise RuntimeError("{0} is not a folder of {1}: refused".format(gdir, PATHS["shared_dir"]))
    return gdir


# ----------------------------------------------------------------- status (shared with scheduler)
def update_status(key, record):
    store.update_records(store.STATUS, {key: record}, PATHS["lists_dir"], PATHS["run_dir"])


# ----------------------------------------------------------------- exclusions
def load_exclusions():
    """Exclusions from the dashboard list; before the first save, from the per-OS CSVs."""
    path = store.list_path(store.EXCLUSIONS, PATHS["lists_dir"])
    if os.path.exists(path):
        raw, errors = store.read_list(store.EXCLUSIONS, PATHS["lists_dir"])
        valid, verrors = store.validate_exclusions(raw)
        for e in errors + verrors:
            print("  [REJECTED exclusion] {0}".format(e), file=sys.stderr)
        return valid, "list", errors + verrors
    records, errors = {}, []
    for os_key in OS_LIBRARY:
        p = os.path.join(PATHS["exclusions_dir"], os_key + ".csv")
        if os.path.isfile(p):
            with open(p, newline="", encoding="utf-8-sig") as f:
                recs, errs = store.exclusions_from_csv_rows(list(csv.reader(f)), os_key)
            records.update(recs)
            errors += ["{0}: {1}".format(os.path.basename(p), e) for e in errs]
    return records, "csv", errors


EXCLUSION_FIELDS = ("os_key", "scope", "scope_value", "level", "role", "rule", "reason", "ticket",
                    "owner", "updated_by", "updated_at")


def act_exclusions():
    """The exclusion register, every OS, as CSV on stdout."""
    exclusions, _, errors = load_exclusions()
    out = csv.writer(sys.stdout, lineterminator="\n")
    out.writerow(EXCLUSION_FIELDS)
    for r in sorted(exclusions.values(), key=lambda r: (
            r["os_key"], r["scope"], r["scope_value"].lower(),
            [int(p) for p in r["rule"].split(".")])):
        # a text starting with = + - @ would run as a formula in a spreadsheet
        out.writerow(["'" + v if v[:1] in ("=", "+", "-", "@") else v
                      for v in (str(r.get(f, "")) for f in EXCLUSION_FIELDS)])
    return 1 if errors else 0


def write_exclusions_csv(exclusions, os_key):
    """CSV consumed by csv_to_custom_xccdf.py (and shipped to Windows agents as tailoring)."""
    os.makedirs(PATHS["exclusions_dir"], exist_ok=True)
    path = os.path.join(PATHS["exclusions_dir"], os_key + ".csv")
    buf = io.StringIO()
    buf.write("# generated by ciscat-fleet.py from etc/lists/ciscat-exclusions: edit in the dashboard\n")
    csv.writer(buf, lineterminator="\n").writerows(store.exclusions_to_csv_rows(exclusions, os_key))
    write_atomic(path, buf.getvalue())
    return path


def agent_combo_keys(exclusions, os_key, name, groups):
    """Keys of the host/app_group exclusions that apply to one agent."""
    lname, lgroups = name.lower(), {g.lower() for g in groups}
    keys = []
    for key, r in exclusions.items():
        if r["os_key"] != os_key:
            continue
        if r["scope"] == "host" and r["scope_value"].lower() == lname:
            keys.append(key)
        elif r["scope"] == "app_group" and r["scope_value"].lower() in lgroups:
            keys.append(key)
    return sorted(keys)


def combo_id(keys):
    if not keys:
        return "base"
    return hashlib.sha1("|".join(keys).encode()).hexdigest()[:10]


# ----------------------------------------------------------------- pipeline
def build(os_key, cfg, exc_csv, host, app_groups, out_dir):
    """Custom XCCDF + SCA policy for one host view (the OS group, or a combo representative)."""
    bench = os.path.join(PATHS["benchmarks_dir"], cfg["benchmark"])
    os.makedirs(out_dir, exist_ok=True)
    custom = os.path.join(out_dir, cfg["base"] + "-xccdf.xml")
    _, audit, rejected, _, _ = tailor.build_custom_xccdf(
        exc_csv, bench, host, os_key, cfg["role"], app_groups, custom,
        cfg.get("base_profiles", []))
    for _, why in rejected:
        print("    [REJECTED] {0}".format(why))
    _, level = cfg["profiles"][0]
    pol = os.path.join(out_dir, cfg["policy_id"])
    result = gen.generate(custom, profile_id(level, cfg["role"]), cfg["flat_path"],
                          cfg["policy_id"], cfg["policy_name"], pol)
    lines = tailor.audit_lines(audit)
    return {"custom": custom, "policy": pol + ".yml", "work": out_dir, "checks": result["checks"],
            "excluded": len(lines), "audit": lines}


def publish_linux(os_key, cfg, art):
    """Publishes the files, then the manifest that lists them. Returns the missing sources."""
    gdir = group_dir(cfg["group"])
    ensure_agent_conf(gdir)
    base, pfx = cfg["base"], cfg["companion_prefix"]
    bdir = PATHS["benchmarks_dir"]
    dest_bench = "/opt/ciscat/Assessor/benchmarks"
    entries = [
        (art["custom"], base + "-xccdf.xml", dest_bench + "/" + base + "-xccdf.xml"),
    ]
    # companions under BOTH names: prefix-derived (CPE) + original (href resolution)
    for suf in ("-oval.xml", "-cpe-oval.xml", "-cpe-dictionary.xml"):
        src = os.path.join(bdir, pfx + suf)
        entries.append((src, base + suf, dest_bench + "/" + base + suf))
        entries.append((src, pfx + suf, dest_bench + "/" + pfx + suf))
    entries.append((os.path.join(BIN_DIR, "ciscat-refresh.sh"), "ciscat-refresh.sh",
                    "/var/ossec/active-response/bin/ciscat-refresh.sh"))
    # the OS's refresh settings, one file per OS so several OSes can share an agent
    pkey, level = cfg["profiles"][0]
    rconf = os.path.join(art["work"], "refresh.conf")
    with open(rconf, "w") as f:
        f.write('BENCHMARK_FILE="{0}-xccdf.xml"\n'.format(base))
        f.write('PROFILE_LIST="{0}|{1}"\n'.format(pkey, profile_name(os_key, level, cfg["role"])))
        f.write('SPLAY_MAX_SEC="1800"\n')
    entries.append((rconf, LINUX_CONF.format(os_key),
                    "/var/lib/wazuh-ciscat/conf.d/{0}.conf".format(os_key)))

    lines = ["# ciscat-manifest ({0}, plain XML), generated {1}".format(
        os_key, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())), "# name;sha256;dest"]
    manifest = OS_MANIFEST.format(os_key)
    missing, names = [], [manifest]
    for src, name, dest in entries:
        if not os.path.isfile(src):
            print("    MISSING: {0}".format(src))
            missing.append(os.path.basename(src))
            continue
        copy_atomic(src, os.path.join(gdir, name))
        names.append(name)
        lines.append("{0};{1};{2}".format(name, sha256(os.path.join(gdir, name)), dest))
        print("    published: {0}".format(name))
    lic = publish_license(gdir, windows=False)
    if lic:
        lines.append(lic)
        names.append(LICENSE_NAME)
        print("    published: CIS-CAT license")
    write_atomic(os.path.join(gdir, manifest), "\n".join(lines) + "\n")
    names.append(sign_manifest(os.path.join(gdir, manifest)))
    names.append(publish_pubkey(gdir, windows=False))
    own_dir(gdir)
    return sorted(set(missing)), names


def publish_windows(os_key, cfg, art, exc_csv):
    """Publishes the files, then the manifest that lists them (name;sha256;dest). The agent's
    ciscat-bootstrap.ps1 installs those with a destination (benchmark files into the Assessor's
    benchmarks folder, the assessment and conversion scripts into C:\\CIS\\bin); the parameters
    and the tailoring are read from the shared folder. Returns the missing sources."""
    gdir = group_dir(cfg["group"])
    ensure_agent_conf(gdir)
    custom = cfg["base"] + "-custom.xml"
    copy_for_windows(art["custom"], os.path.join(gdir, custom))
    tailoring = "tailoring-{0}.csv".format(os_key)
    copy_for_windows(exc_csv, os.path.join(gdir, tailoring))
    # profile, custom benchmark and result name of this OS for ciscat-assessment.ps1 (one script
    # for every Windows OS)
    _, level = cfg["profiles"][0]
    flat = cfg["flat_path"].replace("/", "\\").split("\\")[-1]
    params = WINDOWS_PARAMS.format(os_key)
    write_atomic(os.path.join(gdir, params), "".join([
        "Profile={0}\n".format(profile_id(level, cfg["role"])),
        "FlatName={0}\n".format(flat[:-len(".ciscat-flat")] if flat.endswith(".ciscat-flat")
                                else flat),
        "CustomXccdf={0}\n".format(custom)]))
    # parameters and tailoring go to C:\CIS\run, so the assessment reads the verified copies
    entries = [(custom, WINDOWS_BENCH + custom), (tailoring, WINDOWS_RUN + tailoring),
               (params, WINDOWS_RUN + params)]
    # OVAL and CPE companions under their original names: the XCCDF checks reference them by href,
    # and the agent's CIS-CAT may not ship this benchmark (a newer version, a STIG)
    pfx = cfg["benchmark"][:-len("-xccdf.xml")]
    try:
        with open(art["custom"], encoding="utf-8", errors="replace") as f:
            xccdf = f.read()
    except OSError:
        xccdf = ""
    for suf in ("-oval.xml", "-cpe-oval.xml", "-cpe-dictionary.xml"):
        src = os.path.join(PATHS["benchmarks_dir"], pfx + suf)
        if os.path.isfile(src):
            copy_for_windows(src, os.path.join(gdir, pfx + suf))
            entries.append((pfx + suf, WINDOWS_BENCH + pfx + suf))
        elif pfx + suf in xccdf:
            # the agents' Assessor has no benchmarks folder of its own: only the master sends them
            print("    WARNING: the benchmark refers to {0}, not in {1}: copy it there".format(
                pfx + suf, PATHS["benchmarks_dir"]))
    missing = []
    for script in WINDOWS_SCRIPTS:
        src = os.path.join(PATHS["agent_dir"], script)
        if not os.path.isfile(src):
            print("    MISSING: {0}".format(src))
            missing.append(script)
            continue
        copy_for_windows(src, os.path.join(gdir, script))
        entries.append((script, WINDOWS_BIN + script))
    lines = ["# ciscat-manifest ({0}), generated {1}".format(
        os_key, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())), "# name;sha256;dest"]
    for name, dest in entries:
        lines.append("{0};{1};{2}".format(name, windows_sha256(os.path.join(gdir, name)), dest))
    lic = publish_license(gdir, windows=True)
    if lic:
        lines.append(lic)
    manifest = OS_MANIFEST.format(os_key)
    write_atomic(os.path.join(gdir, manifest), "\n".join(lines) + "\n")
    signature = sign_manifest(os.path.join(gdir, manifest))
    pubkey = publish_pubkey(gdir, windows=True)
    print("    published: custom + {0} + params + {1} companion(s) + {2} script(s) + manifest".format(
        tailoring, len(entries) - 3 - (len(WINDOWS_SCRIPTS) - len(missing)),
        len(WINDOWS_SCRIPTS) - len(missing)))
    own_dir(gdir)
    # a Windows benchmark may come without OVAL/CPE files (then it does not refer to them)
    return missing, [name for name, _ in entries] + [manifest, signature, pubkey] + (
        [LICENSE_NAME] if lic else [])


def policy_enabled(group, policy_file):
    """True when the group's agent.conf already loads the policy (set up by hand or by v1)."""
    try:
        with open(os.path.join(PATHS["shared_dir"], group, "agent.conf"), encoding="utf-8") as f:
            return policy_file in f.read()
    except OSError:
        return False


# How often the agents' SCA module reads the results again: an assessment's results reach the
# dashboard at the next scan. It is the interval of the agent's whole SCA module.
SCA_INTERVAL = os.environ.get("CISCAT_SCA_INTERVAL", "1h")
if not re.match(r"^[1-9][0-9]{0,4}[smhdw]$", SCA_INTERVAL):
    SCA_INTERVAL = "1h"


# Wazuh's own SCA policies (ruleset/sca) on the agents the bridge assesses: their scores would sit
# next to the CIS-CAT one in the dashboard, and on a newer OS they come from an older benchmark
# (Windows Server 2025 gets the 2022 policy). keep_default_sca=yes in the conf keeps them.
DEFAULT_SCA_RE = re.compile(r"^(cis|sca)_[a-z0-9_]{1,80}$")


DISABLED_SCA_RE = re.compile(r'<policy enabled="no">ruleset/sca/([a-z0-9_]{1,84})\.yml</policy>')


def default_sca_policies(token, agent_ids, groups=()):
    """Ids of the Wazuh SCA policies to switch off on the agents of an OS: those a few of its
    agents report, plus those already switched off in its combo groups (a switched-off policy
    is no longer reported, and must stay off at the next apply)."""
    if read_conf().get("keep_default_sca", "").lower() in ("yes", "true", "1"):
        return []
    ours = {c.get("policy_id") for c in OS_LIBRARY.values()}
    found = set()
    for g in groups:
        try:
            with open(os.path.join(PATHS["shared_dir"], g, "agent.conf"), encoding="utf-8") as f:
                found.update(p for p in DISABLED_SCA_RE.findall(f.read()) if p not in ours)
        except OSError:
            pass
    for aid in agent_ids[:5]:
        try:
            items = api_json("GET", "/sca/{0}?select=policy_id&limit=100".format(aid), token)
        except Exception:
            continue
        for p in items.get("affected_items", []):
            pid = str(p.get("policy_id", ""))
            if pid not in ours and "tailored" not in pid and DEFAULT_SCA_RE.match(pid):
                found.add(pid)
    return sorted(found)


def sca_agent_conf(cfg, policy_file, load_policy=True, disabled=()):
    """agent.conf of a combo group (owned by the bridge): the SCA scan interval, the SCA policy
    shipped with the group unless the OS group's own agent.conf already loads it, and Wazuh's own
    policies switched off."""
    path = ("shared/" if cfg["family"] == "windows" else "etc/shared/") + policy_file
    lines = ["      <policy>{0}</policy>\n".format(path)] if load_policy else []
    lines += ['      <policy enabled="no">ruleset/sca/{0}.yml</policy>\n'.format(p)
              for p in disabled]
    policies = "    <policies>\n{0}    </policies>\n".format("".join(lines)) if lines else ""
    return ("<!-- managed by the CIS-CAT bridge: SCA policy {0} -->\n"
            "<agent_config>\n  <sca>\n    <enabled>yes</enabled>\n"
            "    <scan_on_start>yes</scan_on_start>\n    <interval>{1}</interval>\n"
            "{2}  </sca>\n</agent_config>\n").format(cfg["policy_id"], SCA_INTERVAL, policies)


def apply_os(os_key, cfg, exclusions, token, apply_):
    """Plan or apply one OS. Returns a summary for ciscat-status."""
    bench = os.path.join(PATHS["benchmarks_dir"], cfg["benchmark"])
    if not os.path.isfile(bench):
        raise RuntimeError("benchmark missing in library: {0}".format(bench))
    n_exc = sum(1 for r in exclusions.values() if r["os_key"] == os_key)
    print("  exclusions: {0}  benchmark: {1}".format(n_exc, cfg["benchmark"]))

    agents, other = [], []
    for a in group_agent_records(token, cfg["group"]):
        if wrong_platform(cfg, a["platform"]):
            other.append(a)
        else:
            agents.append((a["id"], a["name"], a["groups"]))
    for a in other:
        print("  [skip] {0} {1}: platform {2}, not a {3} benchmark: no policy".format(
            a["id"], a["name"], a["platform"] or "not known yet", cfg.get("family")))
    combos = {}  # combo -> {"keys": [...], "agents": [(id, name, groups)]}
    for aid, name, groups in agents:
        keys = agent_combo_keys(exclusions, os_key, name, groups)
        combos.setdefault(combo_id(keys), {"keys": keys, "agents": []})["agents"].append(
            (aid, name, groups))
    combos.setdefault("base", {"keys": [], "agents": []})
    for cid in sorted(combos):
        c = combos[cid]
        print("  combo {0}: {1} agent(s), {2} host/app exclusion(s)".format(
            combo_group(os_key, cid), len(c["agents"]), len(c["keys"])))
    summary = {"agents": len(agents), "combos": len(combos), "exclusions": n_exc}
    if other:
        summary["wrong_platform"] = sorted(a["id"] for a in other)
    if not apply_:
        print("  [dry-run] would regenerate the custom XCCDF, {0} policy(ies) and group assignments"
              .format(len(combos)))
        return summary

    work = os.path.join(PATHS["work_dir"], os_key)
    exc_csv = write_exclusions_csv(exclusions, os_key)
    # 1. OS view: the custom every agent of the OS runs (OS and global exclusions)
    art = build(os_key, cfg, exc_csv, cfg["group"], [], work)
    for line in art["audit"]:
        print("    " + line)
    print("    [+] OS custom: {0} checks, {1} excluded".format(art["checks"], art["excluded"]))
    # 2. one policy per combo, from a representative agent of the combo
    built = {}
    for cid, c in combos.items():
        if cid == "base":
            built[cid] = art
            continue
        _, name, groups = c["agents"][0]
        built[cid] = build(os_key, cfg, exc_csv, name, groups, os.path.join(work, "combos", cid))
        print("    [+] combo {0}: {1} checks".format(cid, built[cid]["checks"]))
    summary["checks"] = {cid: b["checks"] for cid, b in built.items()}

    # 3. combo groups hold the policy (before it leaves the OS group, so agents never miss it)
    existing = existing_groups(token)
    policy_file = os.path.basename(art["policy"])
    # The combo groups load the policy, unless the OS group's agent.conf already does (an OS set up
    # by hand before the bridge), and always set the SCA interval: the results of a run are read
    # within the interval instead of at the next default scan (12 hours)
    defaults = default_sca_policies(token, [aid for c in combos.values() for aid, _, _ in c["agents"]],
                                    [combo_group(os_key, cid) for cid in combos])
    if defaults:
        print("    Wazuh SCA policies switched off on these agents: {0}".format(", ".join(defaults)))
    sca_conf = sca_agent_conf(cfg, policy_file,
                              load_policy=not policy_enabled(cfg["group"], policy_file),
                              disabled=defaults)
    for cid, b in built.items():
        g = combo_group(os_key, cid)
        if g not in existing:
            api_json("POST", "/groups", token, {"group_id": g})
            print("    created group {0}".format(g))
        gdir = group_dir(g)
        copy_atomic(b["policy"], os.path.join(gdir, policy_file))
        write_atomic(os.path.join(gdir, "agent.conf"), sca_conf)
        own_dir(gdir)
    # 4. assignments: add the right combo group, then drop the others of this OS
    moved = 0
    for cid, c in combos.items():
        target = combo_group(os_key, cid)
        for aid, name, groups in c["agents"]:
            if target not in groups:
                api_json("PUT", "/agents/{0}/group/{1}".format(aid, target), token)
                moved += 1
            for g in groups:
                if g != target and is_combo_group(os_key, g):
                    api_json("DELETE", "/agents/{0}/group/{1}".format(aid, g), token)
    summary["moved"] = moved
    # agents that left the OS group (or whose OS now applies to another group) leave its combos
    current = {aid for c in combos.values() for aid, _, _ in c["agents"]}
    for g in sorted(existing):
        if is_combo_group(os_key, g):
            for aid, _, _ in group_agents(token, g, active_only=False, verbose=False):
                if aid not in current:
                    api_json("DELETE", "/agents/{0}/group/{1}".format(aid, g), token)
    # 5. combo groups nobody uses any more
    stale = sorted(g for g in existing if is_combo_group(os_key, g)
                   and g not in {combo_group(os_key, cid) for cid in combos})
    if stale:
        api_json("DELETE", "/groups?groups_list=" + ",".join(stale), token)
        print("    removed unused groups: {0}".format(", ".join(stale)))
    # 6. OS group: custom + companions, no policy any more
    if cfg["family"] == "linux":
        summary["missing"], published = publish_linux(os_key, cfg, art)
    else:
        summary["missing"], published = publish_windows(os_key, cfg, art, exc_csv)
    summary["published"] = {"group": cfg["group"], "files": sorted(set(published))}
    old = os.path.join(PATHS["shared_dir"], cfg["group"], policy_file)
    if os.path.exists(old):
        os.remove(old)
        print("    policy moved from {0} to the combo groups".format(cfg["group"]))
    return summary


# ----------------------------------------------------------------- sync (dashboard data)
def act_sync():
    failed = False
    found = [n for n in DISCOVERY_NOTES if ": new OS from " in n]
    skipped = [n for n in DISCOVERY_NOTES if n.endswith(", skipped")]
    for note in DISCOVERY_NOTES:
        if VERBOSE or (note not in found and note not in skipped):
            print("[discovery] " + note)
    if not VERBOSE and (found or skipped):
        print("[discovery] {0} OS offered from the benchmarks folder, {1} benchmark(s) not usable "
              "by an agent (details: sync -v)".format(len(found), len(skipped)))
    oskeys = {}
    for os_key, cfg in OS_LIBRARY.items():
        bench = os.path.join(PATHS["benchmarks_dir"], cfg["benchmark"])
        entry = {"group": cfg["group"], "policy_id": cfg["policy_id"], "benchmark": cfg["benchmark"],
                 "active": bool(cfg["active"]), "role": cfg["role"], "available": os.path.isfile(bench),
                 "levels": sorted({lvl for _, lvl in cfg["profiles"]}),
                 "discovered": bool(cfg.get("discovered")), "title": cfg.get("title", os_key),
                 "group_source": cfg.get("group_source", "library")}
        if entry["available"]:
            try:
                bench_id, version, prof_keys, cols, profiles, titles, nums = sheet.extract(bench)
                manual = gen.manual_rule_numbers(xccdf.load(bench))
            except (OSError, xccdf.XccdfError) as e:
                print("[{0}] ERROR: benchmark not readable: {1}".format(os_key, e))
                entry["available"], failed = False, True
                oskeys[os_key] = entry
                continue
            col_of = dict(zip(prof_keys, cols))
            recs = {"_meta": {"os_key": os_key, "benchmark": bench_id, "version": version,
                              "profiles": cols, "file": cfg["benchmark"]}}
            for num in nums:
                recs[num] = {"t": titles.get(num, ""), "m": num in manual,
                             "p": [col_of[p] for p in profiles if num in profiles[p]]}
            name = store.bench_list_name(os_key)
            old, _ = store.read_list(name, PATHS["lists_dir"])
            if old != recs:
                store.write_list(name, recs, PATHS["lists_dir"])
                print("[{0}] benchmark sheet published: {1} rules".format(os_key, len(nums)))
            entry["version"] = version
        oskeys[os_key] = entry
    store.write_list(store.OSKEYS, oskeys, PATHS["lists_dir"])
    print("OS list published: {0}".format(", ".join(sorted(oskeys)) if VERBOSE else
                                          "{0} OS (names: sync -v)".format(len(oskeys))))
    return 1 if failed else 0


# ----------------------------------------------------------------- actions
def apply_lock():
    """Exclusive lock held for a whole apply: one started by the scheduler, the installer or by
    hand waits for the one running, so two never write the groups at the same time."""
    os.makedirs(PATHS["run_dir"], exist_ok=True)
    lock = open(os.path.join(PATHS["run_dir"], "apply.lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("another apply is running: waiting for it to finish", flush=True)
        fcntl.flock(lock, fcntl.LOCK_EX)
    return lock


def retire_combos(os_key, groups, token, apply_):
    """An OS that is not applied (inactive, or its group is gone) must not keep agents in its
    combo groups: they would go on receiving its policy. Removes the groups, and so the
    agents' membership."""
    combos = sorted(g for g in groups if is_combo_group(os_key, g))
    if not combos:
        return
    if not apply_:
        print("    [dry-run] would remove the groups {0}".format(", ".join(combos)))
        return
    for g in combos:
        for aid, _, _ in group_agents(token, g, active_only=False, verbose=False):
            api_json("DELETE", "/agents/{0}/group/{1}".format(aid, g), token)
    api_json("DELETE", "/groups?groups_list=" + ",".join(combos), token)
    print("    removed groups of an OS no longer applied: {0}".format(", ".join(combos)))


PUBLISHED_FILE = "published.json"


def read_published():
    """{os_key: {"group", "files"}}: what each OS last published in its group."""
    try:
        with open(os.path.join(PATHS["run_dir"], PUBLISHED_FILE), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def withdraw_published(published, applied):
    """Removes, from the group an OS published in before, the files of an OS that is not applied
    there any more (moved to another group, switched off, or in conflict). A file another OS
    still applied in that group also publishes stays: that OS rewrites it."""
    keep = {(rec["group"], f) for k, rec in published.items() if applied.get(k) == rec["group"]
            for f in rec["files"]}
    for os_key in sorted(published):
        rec = published[os_key]
        if applied.get(os_key) == rec["group"]:
            continue
        if not store.NAME_RE.match(rec.get("group", "")):
            del published[os_key]
            continue
        gdir = os.path.join(PATHS["shared_dir"], rec["group"])
        if os.path.islink(gdir):
            print("[withdraw] {0} is a link: left as it is".format(gdir))
            continue
        gone = []
        for name in rec["files"]:
            path = os.path.join(gdir, name)
            if os.path.basename(name) != name or (rec["group"], name) in keep:
                continue
            if os.path.isfile(path):
                os.remove(path)
                gone.append(name)
        if gone:
            print("[{0}] withdrawn from {1}: {2}".format(os_key, rec["group"], ", ".join(gone)))
        del published[os_key]


def write_group_legacy(published, groups_seen):
    """Group-wide files for agent scripts older than 2.3.0, which read one manifest and one set
    of Windows parameters per agent: the manifest lists the files of every OS of the group, and
    the parameters are written only when the group has a single Windows OS (with several, an
    old script could not tell them apart). Groups no OS publishes in any more lose them."""
    by_group = {}
    for os_key, rec in published.items():
        by_group.setdefault(rec["group"], []).append(os_key)
    for group in sorted(set(groups_seen) | set(by_group)):
        gdir = os.path.join(PATHS["shared_dir"], group)
        if os.path.islink(gdir) or not os.path.isdir(gdir):
            continue
        keys = sorted(by_group.get(group, []))
        legacy = {}
        lines = []
        for k in keys:
            try:
                with open(os.path.join(gdir, OS_MANIFEST.format(k)), encoding="utf-8") as f:
                    lines += [ln for ln in f.read().splitlines() if ln and not ln.startswith("#")]
            except OSError:
                pass
        if lines:
            legacy[LEGACY_MANIFEST] = "# ciscat-manifest ({0})\n# name;sha256;dest\n{1}\n".format(
                ", ".join(keys), "\n".join(lines))
        windows = [k for k in keys if OS_LIBRARY.get(k, {}).get("family") == "windows"]
        if len(windows) == 1:
            with open(os.path.join(gdir, WINDOWS_PARAMS.format(windows[0])), encoding="utf-8") as f:
                legacy[LEGACY_PARAMS] = f.read()
        for name in (LEGACY_MANIFEST, LEGACY_PARAMS, LEGACY_REFRESH_CONF):
            path = os.path.join(gdir, name)
            if name in legacy:
                write_atomic(path, legacy[name])
            elif os.path.isfile(path):
                os.remove(path)  # refresh.conf: the per-OS conf replaced it in 2.3.0
        own_dir(gdir)


def write_published(published):
    write_atomic(os.path.join(PATHS["run_dir"], PUBLISHED_FILE),
                 json.dumps(published, indent=1, sort_keys=True) + "\n")


def act_plan_apply(apply_, restart=False, request=None):
    lock = apply_lock() if apply_ else None
    try:
        return plan_apply(apply_, restart, request)
    finally:
        if lock:
            lock.close()


def plan_apply(apply_, restart, request):
    exclusions, source, errors = load_exclusions()
    print("exclusions source: {0} ({1} valid, {2} rejected)".format(source, len(exclusions), len(errors)))
    token = get_token()
    status = {"state": "running", "request": request or "", "started_at": now_iso(), "errors": [],
              "per_os": {}, "version": VERSION}
    failed = False
    if apply_:
        update_status("apply", status)
    groups = existing_groups(token)
    applied = {k: c["group"] for k, c in OS_LIBRARY.items() if c["active"] and c["group"] in groups}
    published = read_published()
    # groups whose bridge files may change: those of before and those of now
    groups_seen = {rec["group"] for rec in published.values()} | set(applied.values())
    if apply_:
        # files left in a group by an OS that is applied elsewhere now go first, so the OS that
        # stays in that group publishes its own on a clean folder
        withdraw_published(published, applied)
        write_published(published)
    no_group = []
    for os_key, cfg in OS_LIBRARY.items():
        if cfg["active"] and cfg["group"] not in groups and not VERBOSE:
            no_group.append(cfg["group"])
        else:
            print("[{0}] group={1} active={2}".format(os_key, cfg["group"], cfg["active"]))
        if not cfg["active"]:
            print("  [skip] inactive in library")
            retire_combos(os_key, groups, token, apply_)
            continue
        if cfg["group"] not in groups:
            # a benchmark nobody uses yet: create the group and add agents to it
            if VERBOSE:
                print("  [skip] group {0} does not exist".format(cfg["group"]))
            status["per_os"][os_key] = {"agents": 0, "skipped": "no group " + cfg["group"]}
            retire_combos(os_key, groups, token, apply_)
            continue
        sharing = sorted(k for k, g in applied.items() if g == cfg["group"] and k != os_key)
        if sharing:
            print("  note: group {0} also gets {1}; its agents run every benchmark of their "
                  "groups".format(cfg["group"], ", ".join(sharing)))
        try:
            status["per_os"][os_key] = summary = apply_os(os_key, cfg, exclusions, token, apply_)
        except Exception as e:
            print("  ERROR: {0}".format(e))
            status["errors"].append("{0}: {1}".format(os_key, e))
            failed = True
            continue
        if summary.get("published"):
            published[os_key] = summary.pop("published")
            write_published(published)
        if summary.get("wrong_platform"):
            status["errors"].append("{0}: {1} agent(s) of another platform in {2}, not assessed: "
                                    "{3}".format(os_key, len(summary["wrong_platform"]),
                                                 cfg["group"],
                                                 ", ".join(summary["wrong_platform"][:20])))
        if summary.get("missing"):
            status["errors"].append("{0}: benchmark files missing on the master, not published: "
                                    "{1}".format(os_key, ", ".join(summary["missing"])))
            failed = True
    if no_group:
        print("[skip] {0} OS without their group yet, nothing published (create the group to "
              "use one; list: plan -v): {1}".format(len(no_group), ", ".join(sorted(no_group)[:8]) +
                                                   (", ..." if len(no_group) > 8 else "")))
    if apply_:
        write_group_legacy(published, groups_seen)
    # rejected exclusion records are reported but do not fail the apply
    status["errors"] += errors[:50]
    status["state"] = "error" if failed else "ok"
    status["finished_at"] = now_iso()
    if apply_:
        update_status("apply", status)
        if restart:
            print(sh(["systemctl", "restart", "wazuh-manager"]))
        print("\nPublished. Agents sync at their next keepalive. Then: ciscat-fleet.py trigger")
    else:
        print("\n[dry-run] nothing written. Re-run with 'apply'.")
    return 0 if status["state"] == "ok" else 1


def ar_command(value):
    """The Active Response command to send: its name in ar.conf. A leading "!" (older OS libraries)
    is dropped: with it the agent runs active-response/bin/<name> as a file, bypassing ar.conf, so a
    missing or misnamed script fails on the agent without any error on the manager, and on Windows
    the <executable> of the master's ossec.conf (the .cmd launcher) is never used."""
    return (value or "").lstrip("!")


def configured_ar_commands():
    """Names of the Active Response commands the master distributes (shared/ar.conf)."""
    try:
        with open(os.path.join(PATHS["shared_dir"], "ar.conf"), encoding="utf-8") as f:
            return {line.split(" - ")[0].strip() for line in f if " - " in line}
    except OSError:
        return set()


def resolve_run(token, targets=None, agents=None, groups=None):
    """Who a run reaches: ({os_key: [agent ids]}, {agent id: reason not reached}, [notes]).

    targets: os keys (or "*"): the agents of their OS groups, as before.
    agents / groups: the chosen agents, or the agents of the chosen groups (an OS group or any
    custom one).
    An agent is reached once, with the commands of its platform: its script then runs every
    benchmark of its groups. Agents that are not connected, that are in no group of an active
    OS of their platform (a Windows benchmark never runs on a Linux or other Unix-like agent,
    nor the reverse) are not reached and are reported."""
    active = {k: c for k, c in OS_LIBRARY.items() if c["active"]}
    existing = existing_groups(token)
    os_of_group = {}
    for k, c in active.items():
        os_of_group.setdefault(c["group"], []).append(k)
    candidates, skipped, notes = [], {}, []
    if agents:
        found = agent_records(token, agents)
        for aid in agents:
            if aid in found:
                candidates.append((found[aid], None))
            else:
                skipped[aid] = "unknown agent"
    elif groups:
        for g in groups:
            if g not in existing:
                notes.append("group {0} does not exist".format(g))
                continue
            candidates += [(a, None) for a in group_agent_records(token, g)]
    else:
        for os_key in sorted(active):
            if targets and "*" not in targets and os_key not in targets:
                continue
            if active[os_key]["group"] in existing:
                candidates += [(a, os_key) for a in
                               group_agent_records(token, active[os_key]["group"])]
    plan, reached = {}, set()
    for a, os_key in candidates:
        aid = a["id"]
        if aid == "000" or aid in reached:
            continue
        if a["status"] != "active":
            skipped[aid] = "status " + str(a["status"])
            continue
        keys = [os_key] if os_key else sorted(
            {k for g in a["groups"] for k in os_of_group.get(g, [])})
        if not keys:
            skipped[aid] = "in no group of an active CIS-CAT OS"
            continue
        fitting = [k for k in keys if not wrong_platform(active[k], a["platform"])]
        if not fitting:
            skipped[aid] = "platform {0} does not match {1}".format(
                a["platform"] or "not known yet", ", ".join(keys))
            continue
        plan.setdefault(fitting[0], []).append(aid)
        reached.add(aid)
    # an agent skipped for one target OS and reached through another one is not reported
    return plan, {k: v for k, v in skipped.items() if k not in reached}, notes


def act_trigger(targets=None, wave_size=store.DEFAULT_WAVE_SIZE,
                wave_pause=store.DEFAULT_WAVE_PAUSE_S, job=None, agents=None, groups=None,
                label=None):
    started = now_iso()
    get_token()
    result = {"state": "running", "last_run": started, "sent": 0, "failed": 0, "skipped": [],
              "targets": targets or ([] if agents or groups else ["*"]),
              "agents": agents or [], "groups": groups or []}
    if label:
        result["label"] = label
    if job:
        update_status("job-" + job, result)
    plan, skipped, notes = resolve_run(fresh_token(), targets, agents, groups)
    for note in notes:
        print("  [skip] " + note)
    for aid in sorted(skipped):
        print("  [skip] {0}: {1}".format(aid, skipped[aid]))
    result["skipped"] = sorted(skipped)
    # the reasons of the first ones, so the dashboard can tell why an agent was not reached
    result["skipped_reasons"] = {k: skipped[k] for k in sorted(skipped)[:100]}
    if notes:
        result["notes"] = notes
    if not plan:
        print("no agent to reach")
    configured = configured_ar_commands()
    for os_key in sorted(plan):
        cfg, ids = OS_LIBRARY[os_key], plan[os_key]
        second = ar_command(cfg.get("ar_refresh") or cfg.get("ar_assessment"))
        # on Windows the assessment script copies the group files itself: no bootstrap
        bootstrap = None if cfg.get("family") == "windows" else ar_command(cfg.get("ar_bootstrap"))
        if (not bootstrap and cfg.get("family") != "windows") or not second:
            print("  ERROR [{0}]: no ar_bootstrap/ar_refresh/ar_assessment command in the OS "
                  "library".format(os_key))
            result["failed"] += len(ids)
            continue
        missing = [c for c in (bootstrap, second) if c and c not in configured]
        if missing:
            print("  ERROR [{0}]: Active Response command(s) {1} not in the master's ar.conf: add "
                  "their <command> and <active-response> blocks to ossec.conf (the installer prints "
                  "them) and restart wazuh-manager".format(os_key, ", ".join(missing)))
            result["failed"] += len(ids)
            result.setdefault("notes", []).append("{0}: Active Response command(s) {1} not "
                                                   "configured on the master".format(
                                                       os_key, ", ".join(missing)))
            continue
        waves = [ids[i:i + wave_size] for i in range(0, len(ids), wave_size)]
        print("[{0}] {1} agent(s) in {2} wave(s)".format(os_key, len(ids), len(waves)))
        for n, wave in enumerate(waves, 1):
            lst = ",".join(wave)
            try:
                if bootstrap:
                    api_json("PUT", "/active-response?agents_list=" + lst, fresh_token(),
                             {"command": bootstrap})
                    time.sleep(AR_GAP)  # let bootstrap install the package first
                r = api_json("PUT", "/active-response?agents_list=" + lst, fresh_token(),
                             {"command": second})
                result["sent"] += r.get("total_affected_items", 0)
                result["failed"] += r.get("total_failed_items", 0)
                print("  wave {0}: {1} -> affected {2}".format(n, second, r.get("total_affected_items")))
            except Exception as e:
                result["failed"] += len(wave)
                print("  ERROR wave {0} of {1}: {2}".format(n, os_key, e))
            if n < len(waves) and wave_pause:
                time.sleep(wave_pause)
    result["state"] = "ok" if not result["failed"] else "error"
    result["finished_at"] = now_iso()
    if job:
        update_status("job-" + job, result)
    print("\nThe assessments start on the agents now; the waves spread the load.")
    return 0 if result["state"] == "ok" else 1


def act_report():
    """SCA scores per agent. Exit code 1 when an agent's results could not be read."""
    token = get_token()
    errors = 0
    print("{0:<5} {1:<28} {2:<38} {3:>6} {4:>6} {5:>6} {6:>7} {7:>6}".format(
        "id", "agent", "policy", "checks", "pass", "fail", "invalid", "score"))
    print("-" * 110)
    groups = existing_groups(token)
    for os_key, cfg in OS_LIBRARY.items():
        if not cfg["active"] or cfg["group"] not in groups:
            continue
        for aid, aname, _ in group_agents(token, cfg["group"]):
            try:
                data = api_json("GET", "/sca/{0}?q=policy_id={1}".format(aid, cfg["policy_id"]), token)
                items = data["affected_items"]
                if not items:
                    print("{0:<5} {1:<28} {2:<38} {3}".format(aid, aname, cfg["policy_id"], "no results yet")); continue
                it = items[0]
                print("{0:<5} {1:<28} {2:<38} {3:>6} {4:>6} {5:>6} {6:>7} {7:>6}".format(
                    aid, aname[:28], cfg["policy_id"][:38], it["total_checks"], it["pass"],
                    it["fail"], it["invalid"], it["score"]))
            except Exception as e:
                print("{0:<5} {1:<28} ERROR: {2}".format(aid, aname, e))
                errors += 1
    return 1 if errors else 0


# ----------------------------------------------------------------- OS groups from the agents
def assign_plan(token):
    """([(agent id, name, os key, group)] to add, notes): every agent whose OS has a benchmark goes
    into the group of that OS. An agent already in the group of an OS benchmark (another version,
    STIG, Stand-alone: a choice made in the dashboard) is left as it is."""
    agents = [a for a in paged(token, "/agents?select=id,name,status,group,os.platform,os.name,"
                                      "os.major,os.minor")
              if a["id"] != "000"]
    os_groups = {}  # group -> base OS products of the library entries applied to it
    for key, cfg in OS_LIBRARY.items():
        product = assign.os_product(cfg)
        if product:
            os_groups.setdefault(cfg["group"], set()).add(product)
    adds, notes, ok, unmatched = [], [], 0, {}
    for a in sorted(agents, key=lambda x: x["id"]):
        key, reason = assign.choose(OS_LIBRARY, a.get("os"))
        if not key:
            unmatched.setdefault(reason, []).append(a["id"])
            continue
        target = OS_LIBRARY[key]["group"]
        groups = a.get("group") or []
        if target in groups:
            ok += 1
            continue
        product = assign.os_product(OS_LIBRARY[key])
        other = sorted(g for g in groups if g in os_groups)
        if any(product in os_groups[g] for g in other):
            ok += 1  # same OS, a benchmark chosen in the dashboard
            continue
        if other:
            notes.append("[!] {0} {1}: in {2}, but reports {3}: not moved (OS upgraded? move it "
                         "in the dashboard)".format(a["id"], a.get("name", "?"), ", ".join(other),
                                                    product))
            continue
        adds.append((a["id"], a.get("name", "?"), key, target))
    for reason, ids in sorted(unmatched.items()):
        notes.append("[-] {0}: {1} agent(s) {2}{3}".format(
            reason, len(ids), ", ".join(ids[:10]), ", ..." if len(ids) > 10 else ""))
    print("assign: {0} agent(s): {1} in their OS group, {2} to add, {3} without an OS "
          "benchmark".format(len(agents), ok, len(adds), sum(map(len, unmatched.values()))))
    return adds, notes


def act_assign(apply_, auto=False):
    if auto and read_conf().get("auto_assign", "").lower() not in ("yes", "true", "1"):
        print("assign: auto_assign is off in {0}".format(ORCH_CONF))
        return 0
    lock = apply_lock() if apply_ else None
    try:
        token = get_token()
        adds, notes = assign_plan(token)
        for line in notes:
            print("  " + line)
        groups = existing_groups(token)
        errors = 0
        for aid, name, key, group in adds:
            new = group not in groups
            if not apply_:
                print("  [+] {0} {1}: {2} -> {3}{4}".format(aid, name, key, group,
                                                          " (new group)" if new else ""))
                continue
            try:
                if new:
                    api_json("POST", "/groups", token, {"group_id": group})
                    groups.add(group)
                    print("  [+] group {0} created".format(group))
                api_json("PUT", "/agents/{0}/group/{1}".format(aid, urllib.parse.quote(group)),
                         token)
                print("  [+] {0} {1}: {2} -> {3}".format(aid, name, key, group))
            except Exception as e:
                print("  ERROR {0} {1} -> {2}: {3}".format(aid, name, group, e))
                errors += 1
        if not apply_:
            if adds:
                print("\n[dry-run] nothing changed. Re-run with 'assign --apply'.")
            return 0
        rc = 1 if errors else 0
        if len(adds) > errors:
            # the new members get the files of their OS at once
            print("\n== publish")
            rc = plan_apply(True, False, None) or rc
        return rc
    finally:
        if lock:
            lock.close()


# ----------------------------------------------------------------- baseline groups
GROUP_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def load_baseline(path):
    """{group: {"agent_conf": str, "agents": [names]}} from a baseline file, validated."""
    with open(path, encoding="utf-8") as f:
        spec = json.load(f)
    groups = spec.get("groups") if isinstance(spec, dict) else None
    if not isinstance(groups, dict):
        sys.exit("baseline: {0} needs a \"groups\" object".format(path))
    out = {}
    for name, g in sorted(groups.items()):
        if not GROUP_RE.match(name) or name in (".", "..", "default"):
            sys.exit("baseline: invalid group name {0!r}".format(name))
        conf = g.get("agent_conf") if isinstance(g, dict) else None
        agents = g.get("agents", []) if isinstance(g, dict) else None
        if not isinstance(conf, str) or "<agent_config" not in conf:
            sys.exit("baseline: group {0}: agent_conf must be an agent.conf text".format(name))
        if not isinstance(agents, list) or not all(isinstance(a, str) and a for a in agents):
            sys.exit("baseline: group {0}: agents must be a list of agent names".format(name))
        out[name] = {"agent_conf": conf, "agents": sorted(set(agents))}
    return out


def act_baseline(path):
    """Groups owned by infrastructure code: each is created when missing, its agent.conf written
    when it differs (the manager validates it), and the listed agents added to it. Nothing else is
    touched: groups and agents not in the file, and agents added by other means, stay as they are.
    Idempotent: a second run changes nothing."""
    groups = load_baseline(path)
    token = get_token()
    existing = existing_groups(token)
    agents = {a.get("name"): a for a in api_json(
        "GET", "/agents?limit=100000&select=id,name,group&q=id!=000", token).get("affected_items", [])}
    changes, errors = 0, 0
    for name, g in groups.items():
        quoted = urllib.parse.quote(name)
        if name not in existing:
            api_json("POST", "/groups", token, {"group_id": name})
            print("[{0}] group created".format(name)); changes += 1
            current = None
        else:
            current = api_call("GET", "/groups/{0}/files/agent.conf?raw=true".format(quoted), token)
        if current is None or current.strip() != g["agent_conf"].strip():
            try:
                api_json("PUT", "/groups/{0}/configuration".format(quoted), token,
                         raw=g["agent_conf"])
                print("[{0}] agent.conf written".format(name)); changes += 1
            except Exception as e:
                print("[{0}] ERROR agent.conf refused: {1}".format(name, e)); errors += 1
        for agent in g["agents"]:
            a = agents.get(agent)
            if not a:
                print("[{0}] WARNING agent {1} not found".format(name, agent)); continue
            if name in (a.get("group") or []):
                continue
            api_json("PUT", "/agents/{0}/group/{1}".format(a["id"], quoted), token)
            print("[{0}] agent {1} ({2}) added".format(name, agent, a["id"])); changes += 1
    print("baseline: {0} group(s), {1} change(s), {2} error(s)".format(len(groups), changes, errors))
    return 1 if errors else 0


# ----------------------------------------------------------------- coverage history
HISTORY_DAYS = 400
STALE_DAYS = 35  # an agent without a scan of its CIS-CAT policy for longer is not assessed


def parse_scan_time(value):
    try:
        t = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.astimezone()


def group_members(token, group):
    """[(id, status)] of every agent of a group, connected or not."""
    out, offset = [], 0
    while True:
        data = api_json("GET", "/groups/{0}/agents?limit=500&offset={1}&select=id,status".format(
            urllib.parse.quote(group), offset), token)
        items = data.get("affected_items", [])
        out += [(a["id"], a.get("status")) for a in items if a["id"] != "000"]
        offset += len(items)
        if not items or offset >= data.get("total_affected_items", 0):
            return out


def act_history(day=None):
    """Coverage of the day (ciscat-history): per OS, the agents of its group, those with a scan of
    its CIS-CAT policy in the last STALE_DAYS days, and the disconnected ones among the others."""
    token = get_token()
    now = datetime.now().astimezone()
    day = day or now.strftime("%Y-%m-%d")
    groups = existing_groups(token)
    per_os = {}
    for os_key, cfg in OS_LIBRARY.items():
        if not cfg["active"] or cfg["group"] not in groups:
            continue
        rec = {"group": cfg["group"], "expected": 0, "assessed": 0, "disconnected": 0}
        for aid, status in group_members(token, cfg["group"]):
            rec["expected"] += 1
            try:
                items = api_json("GET", "/sca/{0}?q=policy_id={1}&select=end_scan".format(
                    aid, cfg["policy_id"]), fresh_token()).get("affected_items", [])
            except Exception as e:  # an agent that never reported SCA is simply not assessed
                print("  [{0}] agent {1}: {2}".format(os_key, aid, e))
                items = []
            end = parse_scan_time(items[0].get("end_scan")) if items else None
            if end and (now - end).days < STALE_DAYS:
                rec["assessed"] += 1
            elif status != "active":
                rec["disconnected"] += 1
        per_os[os_key] = rec
        print("[{0}] {1}: {2}/{3} assessed in the last {4} days, {5} not assessed and "
              "disconnected".format(os_key, cfg["group"], rec["assessed"], rec["expected"],
                                    STALE_DAYS, rec["disconnected"]))
    old, _ = store.read_list(store.HISTORY, PATHS["lists_dir"])
    keep = sorted(k for k in old if k != day)[-(HISTORY_DAYS - 1):]
    store.update_records(store.HISTORY, {day: {"stale_days": STALE_DAYS, "os": per_os}},
                         PATHS["lists_dir"], PATHS["run_dir"],
                         remove=[k for k in old if k not in keep and k != day])
    print("coverage of {0} recorded for {1} OS(es)".format(day, len(per_os)))
    return 0


def read_conf():
    conf = {}
    if os.path.isfile(ORCH_CONF):
        with open(ORCH_CONF, encoding="utf-8") as f:
            for line in f:
                if "=" in line and not line.lstrip().startswith("#"):
                    k, v = line.rstrip("\n").split("=", 1)
                    conf[k.strip()] = v.strip()
    return conf


def load_api_credentials(args):
    """API credentials without putting the password on the command line (visible in ps).
    User: --user, else api_user in ciscat-orchestrator.conf (unless --password-file names
    another user's file), else wazuh. Password: $WAZUH_API_PASSWORD, --password-file,
    api_pass_file in the conf; --password is still read but deprecated.
    api_ca in the conf turns on TLS verification of the API with that CA file."""
    conf = read_conf()
    API["ca"] = conf.get("api_ca") or None
    per_minute = os.environ.get("CISCAT_API_MAX_PER_MINUTE") or conf.get("api_max_per_minute")
    if per_minute:
        try:
            API["per_minute"] = max(0, int(per_minute))
        except ValueError:
            sys.exit("api_max_per_minute must be a number of requests per minute (0: no limit)")
    if args.user:
        API["user"] = args.user
    elif conf.get("api_user") and not args.password_file:
        API["user"] = conf["api_user"]
    if args.password:
        print("WARNING: --password is visible in the process list and deprecated: use the "
              "password file (api_pass_file) or $WAZUH_API_PASSWORD", file=sys.stderr)
        API["password"], API["source"] = args.password, "--password"
        return
    if os.environ.get("WAZUH_API_PASSWORD"):
        API["password"], API["source"] = os.environ["WAZUH_API_PASSWORD"], "$WAZUH_API_PASSWORD"
        return
    pfile = args.password_file or conf.get("api_pass_file")
    if not pfile:
        return
    if not os.path.isfile(pfile):
        sys.exit("API password file not found: {0}".format(pfile))
    if os.stat(pfile).st_mode & 0o077:
        print("WARNING: {0} is readable by group/others; run: chmod 600 {0}".format(pfile),
              file=sys.stderr)
    with open(pfile, encoding="utf-8") as f:
        API["password"] = f.readline().rstrip("\r\n")
    API["source"] = pfile


def main():
    ap = argparse.ArgumentParser(description="CIS-CAT / Wazuh SCA fleet orchestrator")
    ap.add_argument("action", choices=["sync", "plan", "apply", "trigger", "history", "baseline",
                                       "assign", "key", "report", "exclusions", "version"])
    ap.add_argument("--password", help="deprecated, visible in ps: use the password file")
    ap.add_argument("--password-file", help="file with the API password (default: api_pass_file "
                    "in " + ORCH_CONF + ")")
    ap.add_argument("--user", help="Wazuh API user (default: api_user in the conf, else wazuh)")
    ap.add_argument("--restart", action="store_true", help="restart wazuh-manager after apply (testing only)")
    ap.add_argument("--targets", default="*", help="trigger: os keys, comma separated, or *")
    ap.add_argument("--agents", help="trigger: agent ids, comma separated (instead of --targets)")
    ap.add_argument("--groups", help="trigger: Wazuh groups, comma separated: OS groups or custom "
                    "ones (instead of --targets)")
    ap.add_argument("--wave-size", type=int, default=store.DEFAULT_WAVE_SIZE,
                    help="trigger: agents per wave (default %(default)s, as in the schedules)")
    ap.add_argument("--wave-pause", type=int, default=store.DEFAULT_WAVE_PAUSE_S,
                    help="trigger: seconds between waves (default %(default)s)")
    ap.add_argument("--job", help="trigger: schedule job key, for ciscat-status")
    ap.add_argument("--request", help="apply: request key, for ciscat-status")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="sync/plan/apply: one line per benchmark found and per OS without a group")
    ap.add_argument("--day", help="history: day of the snapshot (YYYY-MM-DD, default today)")
    ap.add_argument("--apply", action="store_true", help="assign: make the changes (default: "
                    "dry-run)")
    ap.add_argument("--auto", action="store_true", help="assign: only when auto_assign=yes in "
                    "the conf (scheduler)")
    ap.add_argument("--file", help="baseline: JSON file of the groups owned by infrastructure code")
    args = ap.parse_args()
    global VERBOSE
    VERBOSE = args.verbose
    if args.action == "version":
        print(VERSION)
        return 0
    if args.action == "key":
        # the manifest signing key (created when missing) and the public keys for the agents
        print("private key (master only): {0}".format(signing_key()))
        for path in (SIGN_PUB, SIGN_PUB_XML):
            print("public key for {0} agents: {1}  sha256 {2}".format(
                "Linux" if path == SIGN_PUB else "Windows", path, sha256(path)))
        print("key fingerprint: {0}".format(key_fingerprint()))
        return 0
    global OS_LIBRARY, DISCOVERY_NOTES
    OS_LIBRARY, DISCOVERY_NOTES = load_os_library()
    load_api_credentials(args)
    if args.action == "sync":
        return act_sync()
    if args.action == "plan":
        return act_plan_apply(False)
    if args.action == "apply":
        return act_plan_apply(True, restart=args.restart, request=args.request)
    if args.action == "trigger":
        if args.wave_size < 1 or args.wave_pause < 0:
            sys.exit("--wave-size must be >= 1 and --wave-pause >= 0")
        args.wave_size = min(args.wave_size, store.MAX_WAVE_SIZE)
        args.wave_pause = max(args.wave_pause, store.MIN_WAVE_PAUSE_S)
        split = lambda v: [t.strip() for t in (v or "").split(",") if t.strip()]  # noqa: E731
        scope = {"agents": split(args.agents), "groups": split(args.groups)}
        if not scope["agents"] and not scope["groups"]:
            scope["targets"] = split(args.targets)
        try:
            scope = store.validate_run_scope(scope)
        except store.StoreError as e:
            sys.exit("trigger: {0}".format(e))
        # a run from the command line is a job too, so the dashboard lists it with the others
        job, label = args.job, None
        if not job:
            job = "m" + time.strftime("%Y%m%d%H%M%S")
            label = "Command line ({0})".format(
                os.environ.get("SUDO_USER") or os.environ.get("USER") or "root")
        return act_trigger(scope["targets"], args.wave_size, args.wave_pause, job,
                           agents=scope["agents"], groups=scope["groups"], label=label)
    if args.action == "exclusions":
        return act_exclusions()
    if args.action == "assign":
        return act_assign(args.apply or args.auto, auto=args.auto)
    if args.action == "baseline":
        if not args.file:
            sys.exit("baseline needs --file")
        return act_baseline(args.file)
    if args.action == "history":
        if args.day:
            try:
                datetime.strptime(args.day, "%Y-%m-%d")
            except ValueError:
                sys.exit("--day must be YYYY-MM-DD")
        return act_history(args.day)
    return act_report()


if __name__ == "__main__":
    sys.exit(main())
