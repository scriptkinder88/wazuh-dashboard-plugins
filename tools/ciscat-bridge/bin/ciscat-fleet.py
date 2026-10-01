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
  trigger   bootstrap + assessment on the agents of the target OSes, in waves
  report    SCA scores per agent
"""
import argparse, csv, hashlib, io, json, os, shutil, ssl, subprocess, sys, time
import urllib.parse
import urllib.request
from datetime import datetime

BIN_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BIN_DIR)
import ciscat_store as store  # noqa: E402
import ciscat_discover as discover  # noqa: E402

VERSION = "2.2.0"
ETC_DIR = os.environ.get("CISCAT_ETC_DIR", "/opt/ciscat/etc")
OS_LIBRARY_FILE = os.path.join(ETC_DIR, "os-library.json")
ORCH_CONF = os.path.join(ETC_DIR, "ciscat-orchestrator.conf")
COMBO_PREFIX = "ciscat-"
AR_GAP = int(os.environ.get("CISCAT_AR_GAP", "15"))

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
        "flat_path": "C:\\Program Files (x86)\\ciscat\\results\\cis_win2025_v2.0.0.ciscat-flat",
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
}
if os.environ.get("CISCAT_PATHS_JSON"):  # tests
    PATHS.update(json.loads(os.environ["CISCAT_PATHS_JSON"]))

API = {"url": os.environ.get("CISCAT_API_URL", "https://localhost:55000"), "user": "wazuh",
       "password": ""}


def load_os_library():
    if os.path.isfile(OS_LIBRARY_FILE):
        with open(OS_LIBRARY_FILE, encoding="utf-8") as f:
            lib = json.load(f)
    else:
        lib = DEFAULT_OS_LIBRARY
    for key in lib:
        if not store.OS_KEY_RE.match(key):
            sys.exit("os-library: invalid os key {0!r}".format(key))
    # every benchmark present in the benchmarks folder is an OS too (see ciscat_discover.py)
    lib, notes = discover.merge(lib, PATHS["benchmarks_dir"])
    # the group each OS applies to can be chosen in the dashboard
    records, _ = store.read_list(store.TARGETS, PATHS["lists_dir"])
    targets, errors = store.validate_targets(records)
    notes += ["ciscat-targets: " + e for e in errors]
    return discover.apply_targets(lib, targets), notes


OS_LIBRARY, DISCOVERY_NOTES = load_os_library()


# ----------------------------------------------------------------- helpers
def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def sh(cmd):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.decode()


def run_checked(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = p.stdout.decode()
    if p.returncode != 0:
        raise RuntimeError("{0} failed ({1}): {2}".format(os.path.basename(cmd[1]), p.returncode,
                                                         out.strip().splitlines()[-1:] or ""))
    return out


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def api_call(method, endpoint, token=None, body=None):
    ctx = ssl._create_unverified_context()  # local manager API, self-signed certificate
    req = urllib.request.Request(API["url"] + endpoint, method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    else:
        import base64
        cred = base64.b64encode((API["user"] + ":" + API["password"]).encode()).decode()
        req.add_header("Authorization", "Basic " + cred)
    if body is not None:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(body).encode()
    with urllib.request.urlopen(req, context=ctx, timeout=120) as r:
        return r.read().decode()


def api_json(method, endpoint, token, body=None):
    data = json.loads(api_call(method, endpoint, token, body))
    if data.get("error") not in (0, None):
        raise RuntimeError("API {0} {1}: {2}".format(method, endpoint, data.get("message")))
    return data.get("data", {})


def get_token():
    import urllib.error
    try:
        return api_call("POST", "/security/user/authenticate?raw=true")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            sys.exit("Wazuh API authentication failed for user '{0}' (password from {1}). Update the "
                     "password file (chmod 600) or pass --password-file.".format(
                         API["user"], API.get("source") or "the default"))
        raise


def group_agents(token, group, active_only=True, verbose=True):
    """[(id, name, [groups])] of a group, paginated."""
    out, offset = [], 0
    while True:
        data = api_json("GET", "/groups/{0}/agents?limit=500&offset={1}&select=id,name,status,group"
                        .format(urllib.parse.quote(group), offset), token)
        items = data.get("affected_items", [])
        for a in items:
            if a["id"] == "000":
                continue
            if active_only and a.get("status") != "active":
                if verbose:
                    print("  [skip] {0} {1}: status={2}".format(a["id"], a.get("name", "?"),
                                                                a.get("status")))
                continue
            out.append((a["id"], a.get("name", "?"), a.get("group") or []))
        offset += len(items)
        if not items or offset >= data.get("total_affected_items", 0):
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


def is_combo_group(os_key, group):
    return group.startswith("{0}{1}-".format(COMBO_PREFIX, os_key))


def own(path, mode=0o640):
    try:
        import pwd, grp
        os.chown(path, pwd.getpwnam("wazuh").pw_uid, grp.getgrnam("wazuh").gr_gid)
        os.chmod(path, mode)
    except Exception as e:
        print("    WARNING: ownership {0}: {1}".format(path, e))


def own_dir(gdir):
    for fn in os.listdir(gdir):
        own(os.path.join(gdir, fn))


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
            print("  [REJECTED exclusion] {0}".format(e))
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


def write_exclusions_csv(exclusions, os_key):
    """CSV consumed by csv_to_custom_xccdf.py (and shipped to Windows agents as tailoring)."""
    os.makedirs(PATHS["exclusions_dir"], exist_ok=True)
    path = os.path.join(PATHS["exclusions_dir"], os_key + ".csv")
    buf = io.StringIO()
    buf.write("# generated by ciscat-fleet.py from etc/lists/ciscat-exclusions: edit in the dashboard\n")
    csv.writer(buf, lineterminator="\n").writerows(store.exclusions_to_csv_rows(exclusions, os_key))
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(buf.getvalue())
    os.replace(tmp, path)
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
    out = run_checked([sys.executable, os.path.join(BIN_DIR, "csv_to_custom_xccdf.py"),
                       "--csv", exc_csv, "--benchmark", bench, "--host", host,
                       "--os-key", os_key, "--role", cfg["role"],
                       "--app-groups", ",".join(app_groups), "--out", custom])
    audit = [l.strip() for l in out.splitlines() if l.strip().startswith("[L")]
    pkey, level = cfg["profiles"][0]
    pol = os.path.join(out_dir, cfg["policy_id"])
    out = run_checked([sys.executable, os.path.join(BIN_DIR, "xccdf_to_sca_policy.py"),
                       "--xccdf", custom, "--profile-id", profile_id(level, cfg["role"]),
                       "--flat-path", cfg["flat_path"], "--policy-id", cfg["policy_id"],
                       "--policy-name", cfg["policy_name"], "--out", pol])
    checks = 0
    for line in out.splitlines():
        if "checks in policy:" in line:
            checks = int(line.split(":")[1].split()[0])
    return {"custom": custom, "policy": pol + ".yml", "work": out_dir, "checks": checks,
            "excluded": len(audit), "audit": audit}


def publish_linux(os_key, cfg, art):
    gdir = os.path.join(PATHS["shared_dir"], cfg["group"])
    os.makedirs(gdir, exist_ok=True)
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
    # per-OS refresh.conf generated on the fly (group-generic profile name)
    pkey, level = cfg["profiles"][0]
    rconf = os.path.join(art["work"], "refresh.conf")
    with open(rconf, "w") as f:
        f.write('BENCHMARK_FILE="{0}-xccdf.xml"\n'.format(base))
        f.write('PROFILE_LIST="{0}|{1}"\n'.format(pkey, profile_name(os_key, level, cfg["role"])))
        f.write('SPLAY_MAX_SEC="1800"\n')
    entries.append((rconf, "refresh.conf", "/var/lib/wazuh-ciscat/refresh.conf"))

    man = os.path.join(gdir, "ciscat-manifest.csv")
    with open(man, "w") as f:
        f.write("# ciscat-manifest ({0}, plain XML), generated {1}\n".format(
            os_key, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
        f.write("# name;sha256;dest\n")
        for src, name, dest in entries:
            if not os.path.isfile(src):
                print("    MISSING: {0}".format(src)); continue
            shutil.copyfile(src, os.path.join(gdir, name))
            f.write("{0};{1};{2}\n".format(name, sha256(os.path.join(gdir, name)), dest))
            print("    published: {0}".format(name))
    own_dir(gdir)


def publish_windows(os_key, cfg, art, exc_csv):
    gdir = os.path.join(PATHS["shared_dir"], cfg["group"])
    os.makedirs(gdir, exist_ok=True)
    shutil.copyfile(art["custom"], os.path.join(gdir, cfg["base"] + "-custom.xml"))
    tailoring = "tailoring-{0}.csv".format(os_key)
    shutil.copyfile(exc_csv, os.path.join(gdir, tailoring))
    # profile and result name of this OS for ciscat-assessment.ps1 (one script for every Windows OS)
    _, level = cfg["profiles"][0]
    flat = cfg["flat_path"].replace("/", "\\").split("\\")[-1]
    with open(os.path.join(gdir, "ciscat-params.txt"), "w") as f:
        f.write("Profile={0}\n".format(profile_id(level, cfg["role"])))
        f.write("FlatName={0}\n".format(flat[:-len(".ciscat-flat")] if flat.endswith(".ciscat-flat")
                                          else flat))
    with open(os.path.join(gdir, "ciscat-manifest.csv"), "w") as f:
        f.write("# ciscat-manifest: name;sha256 (generated on the manager)\n")
        for name in (tailoring, "ciscat-params.txt"):
            f.write("{0};{1}\n".format(name, sha256(os.path.join(gdir, name))))
    print("    published: custom + {0} + params + manifest".format(tailoring))
    own_dir(gdir)


def policy_enabled(group, policy_file):
    """True when the group's agent.conf already loads the policy (set up by hand or by v1)."""
    try:
        with open(os.path.join(PATHS["shared_dir"], group, "agent.conf"), encoding="utf-8") as f:
            return policy_file in f.read()
    except OSError:
        return False


def sca_agent_conf(cfg, policy_file):
    """agent.conf of a combo group (owned by the bridge): load the SCA policy shipped with it."""
    path = ("shared/" if cfg["family"] == "windows" else "etc/shared/") + policy_file
    return ("<!-- managed by the CIS-CAT bridge: SCA policy {0} -->\n"
            "<agent_config>\n  <sca>\n    <enabled>yes</enabled>\n"
            "    <scan_on_start>yes</scan_on_start>\n    <policies>\n"
            "      <policy>{1}</policy>\n    </policies>\n  </sca>\n</agent_config>\n"
            ).format(cfg["policy_id"], path)


def apply_os(os_key, cfg, exclusions, token, apply_):
    """Plan or apply one OS. Returns a summary for ciscat-status."""
    bench = os.path.join(PATHS["benchmarks_dir"], cfg["benchmark"])
    if not os.path.isfile(bench):
        raise RuntimeError("benchmark missing in library: {0}".format(bench))
    n_exc = sum(1 for r in exclusions.values() if r["os_key"] == os_key)
    print("  exclusions: {0}  benchmark: {1}".format(n_exc, cfg["benchmark"]))

    agents = group_agents(token, cfg["group"], active_only=False, verbose=False)
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
    # OSes set up by hand keep loading the policy as they always did; a discovered OS, or one moved
    # to another group from the dashboard, gets the policy loaded by its combo groups
    sca_conf = None
    if (cfg.get("discovered") or cfg.get("group_source") == "dashboard") and \
            not policy_enabled(cfg["group"], policy_file):
        sca_conf = sca_agent_conf(cfg, policy_file)
    for cid, b in built.items():
        g = combo_group(os_key, cid)
        if g not in existing:
            api_json("POST", "/groups", token, {"group_id": g})
            print("    created group {0}".format(g))
        gdir = os.path.join(PATHS["shared_dir"], g)
        os.makedirs(gdir, exist_ok=True)
        shutil.copyfile(b["policy"], os.path.join(gdir, policy_file))
        if sca_conf:
            with open(os.path.join(gdir, "agent.conf"), "w") as f:
                f.write(sca_conf)
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
        publish_linux(os_key, cfg, art)
    else:
        publish_windows(os_key, cfg, art, exc_csv)
    old = os.path.join(PATHS["shared_dir"], cfg["group"], policy_file)
    if os.path.exists(old):
        os.remove(old)
        print("    policy moved from {0} to the combo groups".format(cfg["group"]))
    return summary


# ----------------------------------------------------------------- sync (dashboard data)
def act_sync():
    import benchmark_to_sheet as sheet
    import xccdf_to_sca_policy as gen
    for note in DISCOVERY_NOTES:
        print("[discovery] " + note)
    oskeys = {}
    for os_key, cfg in OS_LIBRARY.items():
        bench = os.path.join(PATHS["benchmarks_dir"], cfg["benchmark"])
        entry = {"group": cfg["group"], "policy_id": cfg["policy_id"], "benchmark": cfg["benchmark"],
                 "active": bool(cfg["active"]), "role": cfg["role"], "available": os.path.isfile(bench),
                 "levels": sorted({lvl for _, lvl in cfg["profiles"]}),
                 "discovered": bool(cfg.get("discovered")), "title": cfg.get("title", os_key),
                 "group_source": cfg.get("group_source", "library")}
        if entry["available"]:
            bench_id, version, prof_keys, cols, profiles, titles, nums = sheet.extract(bench)
            with open(bench, encoding="utf-8", errors="replace") as f:
                manual = gen.manual_rule_numbers(f.read())
            col_of = dict(zip(prof_keys, cols))
            recs = {"_meta": {"os_key": os_key, "benchmark": bench_id, "version": version,
                              "profiles": cols, "file": cfg["benchmark"]}}
            for num in nums:
                recs[num] = {"t": titles.get(num, ""), "m": num in manual,
                             "p": [col_of[p] for p in profiles if num in profiles[p]]}
            name = store.bench_list_name(os_key)
            old, _ = store.read_list(name, PATHS["lists_dir"])
            if old.get("_meta", {}).get("benchmark") != bench_id or len(old) != len(recs) or \
                    old.get("_meta", {}).get("version") != version:
                store.write_list(name, recs, PATHS["lists_dir"])
                print("[{0}] benchmark sheet published: {1} rules".format(os_key, len(nums)))
            entry["version"] = version
        oskeys[os_key] = entry
    store.write_list(store.OSKEYS, oskeys, PATHS["lists_dir"])
    print("OS list published: {0}".format(", ".join(sorted(oskeys))))


# ----------------------------------------------------------------- actions
def act_plan_apply(apply_, restart=False, request=None):
    exclusions, source, errors = load_exclusions()
    print("exclusions source: {0} ({1} valid, {2} rejected)".format(source, len(exclusions), len(errors)))
    token = get_token()
    status = {"state": "running", "request": request or "", "started_at": now_iso(), "errors": [],
              "per_os": {}, "version": VERSION}
    failed = False
    if apply_:
        update_status("apply", status)
    groups = existing_groups(token)
    for os_key, cfg in OS_LIBRARY.items():
        print("[{0}] group={1} active={2}".format(os_key, cfg["group"], cfg["active"]))
        if not cfg["active"]:
            print("  [skip] inactive in library"); continue
        if cfg["group"] not in groups:
            # a benchmark nobody uses yet: create the group and add agents to it
            print("  [skip] group {0} does not exist".format(cfg["group"]))
            status["per_os"][os_key] = {"agents": 0, "skipped": "no group " + cfg["group"]}
            continue
        try:
            status["per_os"][os_key] = apply_os(os_key, cfg, exclusions, token, apply_)
        except Exception as e:
            print("  ERROR: {0}".format(e))
            status["errors"].append("{0}: {1}".format(os_key, e))
            failed = True
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


def act_trigger(targets=None, wave_size=100000, wave_pause=0, job=None):
    started = now_iso()
    token = get_token()
    result = {"state": "running", "last_run": started, "sent": 0, "failed": 0, "skipped": [],
              "targets": targets or ["*"]}
    if job:
        update_status("job-" + job, result)
    groups = existing_groups(token)
    for os_key, cfg in OS_LIBRARY.items():
        if not cfg["active"] or (targets and "*" not in targets and os_key not in targets):
            continue
        if cfg["group"] not in groups:
            continue
        agents = []
        for aid, name, _ in group_agents(token, cfg["group"], active_only=False, verbose=False):
            agents.append(aid)
        active = {a for a, _, _ in group_agents(token, cfg["group"])}
        result["skipped"] += sorted(set(agents) - active)
        ids = [a for a in agents if a in active]
        if not ids:
            print("[{0}] no active agents in {1}".format(os_key, cfg["group"])); continue
        second = cfg.get("ar_refresh") or cfg.get("ar_assessment")
        waves = [ids[i:i + wave_size] for i in range(0, len(ids), wave_size)]
        print("[{0}] {1} agent(s) in {2} wave(s)".format(os_key, len(ids), len(waves)))
        for n, wave in enumerate(waves, 1):
            lst = ",".join(wave)
            try:
                api_json("PUT", "/active-response?agents_list=" + lst, token, {"command": cfg["ar_bootstrap"]})
                time.sleep(AR_GAP)  # let bootstrap install the package first
                r = api_json("PUT", "/active-response?agents_list=" + lst, token, {"command": second})
                result["sent"] += r.get("total_affected_items", 0)
                result["failed"] += r.get("total_failed_items", 0)
                print("  wave {0}: {1} -> affected {2}".format(n, second, r.get("total_affected_items")))
            except Exception as e:
                result["failed"] += len(wave)
                print("  ERROR wave {0} of {1}: {2}".format(n, os_key, e))
            if n < len(waves) and wave_pause:
                time.sleep(wave_pause)
                token = get_token()  # tokens last 15 minutes
    result["state"] = "ok" if not result["failed"] else "error"
    result["finished_at"] = now_iso()
    if job:
        update_status("job-" + job, result)
    print("\nAssessments run with splay (up to 30 min) on Linux; Windows runs immediately.")
    return 0 if result["state"] == "ok" else 1


def act_report():
    token = get_token()
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


def load_api_credentials(args):
    """API credentials without putting the password on the command line (visible in ps).
    Order: --password, $WAZUH_API_PASSWORD, --password-file, api_pass_file/api_user in
    ciscat-orchestrator.conf."""
    if args.user:
        API["user"] = args.user
    if args.password:
        API["password"], API["source"] = args.password, "--password"
        return
    if os.environ.get("WAZUH_API_PASSWORD"):
        API["password"], API["source"] = os.environ["WAZUH_API_PASSWORD"], "$WAZUH_API_PASSWORD"
        return
    conf = {}
    if os.path.isfile(ORCH_CONF):
        with open(ORCH_CONF, encoding="utf-8") as f:
            for line in f:
                if "=" in line and not line.lstrip().startswith("#"):
                    k, v = line.rstrip("\n").split("=", 1)
                    conf[k.strip()] = v.strip()
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
    if not args.user and not args.password_file and conf.get("api_user"):
        API["user"] = conf["api_user"]


def main():
    ap = argparse.ArgumentParser(description="CIS-CAT / Wazuh SCA fleet orchestrator")
    ap.add_argument("action", choices=["sync", "plan", "apply", "trigger", "report", "version"])
    ap.add_argument("--password", help="Wazuh API password (visible in ps: prefer the file)")
    ap.add_argument("--password-file", help="file with the API password (default: api_pass_file "
                    "in " + ORCH_CONF + ")")
    ap.add_argument("--user", help="Wazuh API user (default: api_user in the conf, else wazuh)")
    ap.add_argument("--restart", action="store_true", help="restart wazuh-manager after apply (testing only)")
    ap.add_argument("--targets", default="*", help="trigger: os keys, comma separated, or *")
    ap.add_argument("--wave-size", type=int, default=100000, help="trigger: agents per wave")
    ap.add_argument("--wave-pause", type=int, default=0, help="trigger: seconds between waves")
    ap.add_argument("--job", help="trigger: schedule job key, for ciscat-status")
    ap.add_argument("--request", help="apply: request key, for ciscat-status")
    args = ap.parse_args()
    if args.action == "version":
        print(VERSION); return 0
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
        targets = [t.strip() for t in args.targets.split(",") if t.strip()]
        return act_trigger(targets, args.wave_size, args.wave_pause, args.job)
    return act_report()


if __name__ == "__main__":
    sys.exit(main() or 0)
