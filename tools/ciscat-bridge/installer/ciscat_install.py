#!/usr/bin/env python3
"""Installs or updates the CIS-CAT bridge on a Wazuh master and/or dashboard host.

Run by the self-contained ciscat-bridge-install-<version>.sh (see build.py) from the directory
the payload was extracted to. Idempotent: running the same version twice changes nothing more.

Master role (Wazuh manager, cluster master or standalone):
  - backup of everything it touches, restorable with --rollback
  - scripts into /opt/ciscat/bin, agent scripts into /opt/ciscat/agent/active-response
  - /opt/ciscat/etc/os-library.json created from the OS table of the ciscat-fleet.py in place
    (only when missing: later updates keep the site's active flags)
  - manager rule etc/rules/ciscat_rules.xml (refused when its rule id is already used)
  - exclusions migrated once from /opt/ciscat/tailoring/exclusions/*.csv to the dashboard list
  - cron: the scheduler replaces ciscat-orchestrator.sh entries (commented out, not deleted)
  - ciscat-fleet.py sync + plan; apply only with --apply
Wazuh 5.0 master (/var/wazuh-manager, see bin/ciscat_platform.py), same steps except:
  - no CDB lists and no XML rules: the indexer configuration (/opt/ciscat/etc/indexer.json,
    --indexer-*) is required, the dashboard store index is created when missing, and the Sigma
    rule rules/ciscat-not-found.sigma.yml is left in /opt/ciscat/rules for import
  - the Active Response channels and Alerting monitors of the runs are created or updated
    (matched by name)
Dashboard role (wazuh-dashboard installed):
  - with --plugin-url/--plugin-file and --plugin-sha256: verified install of the main plugin
"""
import argparse
import ast
import csv
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.environ.get("CISCAT_INSTALL_ROOT", "/")  # tests install into a fake root
# the payload's bin/ (the installer runs from the extracted payload; in the source tree, ../bin)
for _bin in (os.path.join(HERE, "bin"), os.path.join(os.path.dirname(HERE), "bin")):
    if os.path.isfile(os.path.join(_bin, "ciscat_platform.py")):
        sys.path.insert(0, _bin)
        break
import ciscat_platform as platform  # noqa: E402

PLATFORM = 4  # set by main()
# CIS-CAT alert rule: the first id of this range not used by another rule file
RULE_IDS = range(100950, 101000)
PLUGIN_TOOL = "/usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin"

MANAGED_BIN = [
    "ciscat-fleet.py", "ciscat-scheduler.py", "ciscat_store.py", "ciscat_schedule.py",
    "ciscat_discover.py", "csv_to_custom_xccdf.py", "xccdf_to_sca_policy.py", "benchmark_to_sheet.py",
    "ciscat_platform.py", "ciscat_indexer.py",
    "ciscat-refresh.sh", "ciscat-bootstrap.sh", "maps/ciscat-profiles.json",
    "maps/os-benchmark-map.json",
]
MANAGED_AGENT = ["ciscat-assessment.ps1", "ciscat-assessment.cmd"]
SIGMA_RULE = "ciscat-not-found.sigma.yml"
RULES_DIR = "/opt/ciscat/rules"  # Wazuh 5.0: the Sigma rule, to import through the content manager
INDEXER_CONF = "/opt/ciscat/etc/indexer.json"
INDEXER_PASS = "/opt/ciscat/etc/indexer.pass"
CRON_FILE = "/etc/cron.d/ciscat-scheduler"
CRON_LINE = ("*/5 * * * * root /usr/bin/python3 /opt/ciscat/bin/ciscat-scheduler.py "
             ">>/opt/ciscat/log/ciscat-scheduler.log 2>&1\n")
OLD_CRON_MARK = "ciscat-orchestrator.sh"


def P(path):
    return os.path.join(ROOT, path.lstrip("/"))


def say(msg):
    print(msg, flush=True)


def step(msg):
    say("\n== " + msg)


def die(msg):
    say("ERROR: " + msg)
    sys.exit(1)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def own_wazuh(path, mode):
    os.chmod(path, mode)
    if os.geteuid() == 0:
        try:
            import grp
            import pwd
            user, group = platform.owner(PLATFORM)
            os.chown(path, pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid)
        except KeyError:
            pass


def run(cmd, check=False, **kw):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kw)
    out = p.stdout.decode(errors="replace")
    if check and p.returncode != 0:
        die("{0} failed ({1}):\n{2}".format(" ".join(cmd), p.returncode, out))
    return p.returncode, out


# ----------------------------------------------------------------------------- roles
def is_master():
    if PLATFORM == 5:
        # every 5.0 manager is a cluster node: master unless node_type says worker
        conf = P(platform.manager_conf(5))
        if os.path.exists(conf):
            with open(conf, encoding="utf-8", errors="replace") as f:
                if platform.is_worker(f.read(), 5):
                    die("this is a Wazuh cluster WORKER: run the command on the master node")
        return True
    if not os.path.exists(P("/var/ossec/bin/wazuh-analysisd")):
        return False
    conf = P("/var/ossec/etc/ossec.conf")
    if os.path.exists(conf):
        with open(conf, encoding="utf-8", errors="replace") as f:
            text = f.read()
        cluster = re.search(r"<cluster>(.*?)</cluster>", text, re.S)
        if cluster and re.search(r"<disabled>\s*no\s*</disabled>", cluster.group(1)) and \
                re.search(r"<node_type>\s*worker\s*</node_type>", cluster.group(1)):
            die("this is a Wazuh cluster WORKER: run the command on the master node")
    return True


def is_dashboard():
    return os.path.exists(P(PLUGIN_TOOL))


# ----------------------------------------------------------------------------- backup
def backup_targets():
    if PLATFORM == 5:  # the lists live in the indexer, the rule is a Sigma file
        paths = [P("/opt/ciscat/bin"), P("/opt/ciscat/agent"), P("/opt/ciscat/etc"),
                 P("/opt/ciscat/tailoring/exclusions"), P(CRON_FILE),
                 P("/etc/cron.d/ciscat-orchestrator"), P(RULES_DIR)]
        return [p for p in paths if os.path.exists(p)]
    paths = [P("/opt/ciscat/bin"), P("/opt/ciscat/agent"), P("/opt/ciscat/etc"),
             P("/opt/ciscat/tailoring/exclusions"), P(CRON_FILE),
             P("/etc/cron.d/ciscat-orchestrator"), P("/var/ossec/etc/rules/ciscat_rules.xml")]
    paths += glob.glob(P("/var/ossec/etc/lists/ciscat-*"))
    return [p for p in paths if os.path.exists(p)]


def make_backup(crontab_text):
    bdir = P("/opt/ciscat/backup")
    os.makedirs(bdir, exist_ok=True)
    os.chmod(bdir, 0o700)
    stamp, n = time.strftime("%Y%m%d-%H%M%S"), 0
    while True:  # never overwrite an earlier backup
        path = os.path.join(bdir, "ciscat-bridge-{0}{1}.tgz".format(stamp, "-{0}".format(n) if n else ""))
        try:
            os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            break
        except FileExistsError:
            n += 1
    with tarfile.open(path, "w:gz") as tar:
        for p in backup_targets():
            tar.add(p, arcname=os.path.relpath(p, ROOT))
        if crontab_text is not None:
            data = crontab_text.encode()
            info = tarfile.TarInfo("crontab-root.txt")
            info.size = len(data)
            import io
            tar.addfile(info, io.BytesIO(data))
    os.chmod(path, 0o600)
    return path


def rollback(path):
    if not os.path.isfile(path):
        die("backup not found: " + path)
    step("Rollback from " + path)
    for p in (P("/opt/ciscat/bin"), P("/opt/ciscat/agent")) + ((P(RULES_DIR),) if PLATFORM == 5 else ()):
        if os.path.isdir(p):
            shutil.rmtree(p)
    for p in (P(CRON_FILE), P("/var/ossec/etc/rules/ciscat_rules.xml")):
        if os.path.exists(p):
            os.remove(p)
    with tarfile.open(path) as tar:
        members = [m for m in tar.getmembers() if m.name != "crontab-root.txt"]
        for m in members:
            if m.name.startswith("/") or ".." in m.name.split("/"):
                die("unsafe path in backup: " + m.name)
        tar.extractall(ROOT, members=members)
        if "crontab-root.txt" in tar.getnames():
            write_crontab(tar.extractfile("crontab-root.txt").read().decode())
    if PLATFORM == 5:
        say("restored. The indexer store, the Active Response channels and the monitors are left "
            "as they are.")
    else:
        say("restored. Restart wazuh-manager if the rule file changed.")


# ----------------------------------------------------------------------------- crontab
def read_crontab():
    fake = os.environ.get("CISCAT_CRONTAB_FILE")
    if fake:
        return open(fake).read() if os.path.exists(fake) else ""
    if not shutil.which("crontab"):
        return None
    rc, out = run(["crontab", "-l"])
    return out if rc == 0 else ""


def write_crontab(text):
    fake = os.environ.get("CISCAT_CRONTAB_FILE")
    if fake:
        with open(fake, "w") as f:
            f.write(text)
        return
    p = subprocess.run(["crontab", "-"], input=text.encode())
    if p.returncode != 0:
        die("crontab update failed")


def disable_old_cron(crontab_text):
    changed = []
    if crontab_text:
        lines = crontab_text.splitlines(True)
        new = ["# disabled by ciscat-bridge (replaced by ciscat-scheduler): " + l
               if OLD_CRON_MARK in l and not l.lstrip().startswith("#") else l for l in lines]
        if new != lines:
            write_crontab("".join(new))
            changed.append("root crontab")
    old = P("/etc/cron.d/ciscat-orchestrator")
    if os.path.exists(old):
        with open(old) as f:
            lines = f.readlines()
        new = ["# disabled by ciscat-bridge (replaced by ciscat-scheduler): " + l
               if OLD_CRON_MARK in l and not l.lstrip().startswith("#") else l for l in lines]
        if new != lines:
            with open(old, "w") as f:
                f.writelines(new)
            changed.append("/etc/cron.d/ciscat-orchestrator")
    return changed


# ----------------------------------------------------------------------------- steps
def literal_assignment(path, name):
    """Literal value assigned to `name` at module level in a Python file, or None."""
    try:
        with open(path, encoding="utf-8") as f:
            tree = ast.parse(f.read())
    except (OSError, SyntaxError):
        return None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == name for t in node.targets):
            try:
                return json.loads(json.dumps(ast.literal_eval(node.value)))  # tuples -> lists
            except ValueError:
                return None  # not a literal (v2 fleet loads os-library.json)
    return None


def os_library_from_fleet(path):
    """OS table of an existing v1 ciscat-fleet.py, or None."""
    return literal_assignment(path, "OS_LIBRARY")


def install_files(payload):
    installed = []
    for rel in MANAGED_BIN:
        src, dst = os.path.join(payload, "bin", rel), P("/opt/ciscat/bin/" + rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if not os.path.exists(dst) or sha256(dst) != sha256(src):
            shutil.copyfile(src, dst)
            installed.append(rel)
        os.chmod(dst, 0o750 if rel.endswith((".py", ".sh")) else 0o640)
    for rel in MANAGED_AGENT:
        src, dst = (os.path.join(payload, "agent", "active-response", rel),
                    P("/opt/ciscat/agent/active-response/" + rel))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if not os.path.exists(dst) or sha256(dst) != sha256(src):
            shutil.copyfile(src, dst)
            installed.append("agent/" + rel)
        os.chmod(dst, 0o750)
    if PLATFORM == 5:
        src, dst = os.path.join(payload, "rules", SIGMA_RULE), P(RULES_DIR + "/" + SIGMA_RULE)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if not os.path.exists(dst) or sha256(dst) != sha256(src):
            shutil.copyfile(src, dst)
            installed.append("rules/" + SIGMA_RULE)
        os.chmod(dst, 0o644)
    for d in ("/opt/ciscat/log", "/opt/ciscat/run", "/opt/ciscat/etc"):
        os.makedirs(P(d), exist_ok=True)
    return installed


def install_rule(payload):
    """Installs the rule with a free id. Returns the id when the file changed, else None."""
    dst = P("/var/ossec/etc/rules/ciscat_rules.xml")
    others = [f for f in glob.glob(P("/var/ossec/etc/rules/*.xml")) + glob.glob(P("/var/ossec/ruleset/rules/*.xml"))
              if os.path.abspath(f) != os.path.abspath(dst)]
    used = set()
    for f in others:
        with open(f, encoding="utf-8", errors="replace") as fh:
            used.update(int(i) for i in re.findall(r'<rule\s[^>]*\bid="(\d+)"', fh.read()))
    current = None
    if os.path.exists(dst):
        with open(dst, encoding="utf-8") as fh:
            m = re.search(r'<rule\s[^>]*\bid="(\d+)"', fh.read())
            current = int(m.group(1)) if m else None
    free = [i for i in RULE_IDS if i not in used]
    if not free:
        say("WARNING: no free rule id in {0}-{1}: CIS-CAT rule NOT installed".format(
            RULE_IDS[0], RULE_IDS[-1]))
        return None
    rule_id = current if current in free else free[0]  # keep the id already in place
    with open(os.path.join(payload, "rules", "ciscat_rules.xml"), encoding="utf-8") as fh:
        content = re.sub(r'(<rule\s[^>]*\bid=")\d+(")', r"\g<1>{0}\2".format(rule_id), fh.read(), count=1)
    if os.path.exists(dst) and open(dst, encoding="utf-8").read() == content:
        return None
    previous = open(dst, "rb").read() if os.path.exists(dst) else None
    with open(dst, "w", encoding="utf-8") as fh:
        fh.write(content)
    own_wazuh(dst, 0o660)
    test = P("/var/ossec/bin/wazuh-analysisd")
    if ROOT == "/" and os.access(test, os.X_OK):
        rc, out = run([test, "-t"])
        if rc != 0:
            if previous is None:
                os.remove(dst)
            else:
                with open(dst, "wb") as f:
                    f.write(previous)
            say("WARNING: ruleset test failed, CIS-CAT rule not installed:\n" + out[-2000:])
            return None
    return rule_id


def migrate_exclusions():
    sys.path.insert(0, P("/opt/ciscat/bin"))
    import ciscat_store as store
    lists_dir = P("/var/ossec/etc/lists")
    if store.list_exists(store.EXCLUSIONS, lists_dir):
        return "list already present, CSVs not imported"
    records, report = {}, []
    for path in sorted(glob.glob(P("/opt/ciscat/tailoring/exclusions/*.csv"))):
        os_key = os.path.basename(path)[:-4]
        if not store.OS_KEY_RE.match(os_key):
            continue
        with open(path, newline="", encoding="utf-8-sig") as f:
            recs, errs = store.exclusions_from_csv_rows(list(csv.reader(f)), os_key,
                                                        updated_at=time.strftime("%Y-%m-%dT%H:%M:%S"))
        records.update(recs)
        report.append("{0}: {1} imported{2}".format(os.path.basename(path), len(recs),
                                                    "".join("\n    REJECTED " + e for e in errs)))
    if not records and not report:
        return "no exclusions CSV found"
    if PLATFORM != 5:
        os.makedirs(lists_dir, exist_ok=True)
    store.write_list(store.EXCLUSIONS, records or {"_empty": {"v": 1}}, lists_dir)
    return "\n  ".join(report)


def install_cron():
    path = P(CRON_FILE)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    content = "# CIS-CAT bridge scheduler (tools/ciscat-bridge)\n" + CRON_LINE
    if os.path.exists(path) and open(path).read() == content:
        return False
    with open(path, "w") as f:
        f.write(content)
    os.chmod(path, 0o644)
    return True


def fleet(*args):
    if os.environ.get("CISCAT_INSTALL_SKIP_FLEET"):
        return 0
    rc, out = run([sys.executable, P("/opt/ciscat/bin/ciscat-fleet.py")] + list(args))
    for line in out.rstrip().splitlines():
        say("  | " + line)
    return rc


def indexer_settings(args):
    """Wazuh 5.0: the indexer configuration from the --indexer-* options and the one in place,
    checked (and the indexer reached with it) before anything changes on the host."""
    import ciscat_indexer
    conf_file = P(INDEXER_CONF)
    conf = {}
    if os.path.exists(conf_file):
        with open(conf_file, encoding="utf-8") as f:
            conf = json.load(f)
    new = dict(conf)
    if args.indexer_url:
        if not re.match(r"^https?://[^\s/]+(:[0-9]+)?/?$", args.indexer_url):
            die("--indexer-url: https://<host>:<port> expected")
        new["url"] = args.indexer_url.rstrip("/")
    if args.indexer_user:
        new["user"] = args.indexer_user
    if args.indexer_ca:
        if not os.path.isfile(args.indexer_ca):
            die("--indexer-ca: file not found: " + args.indexer_ca)
        new["ca"] = os.path.abspath(args.indexer_ca)
    password = None
    if args.indexer_password_file:
        if not os.path.isfile(args.indexer_password_file):
            die("--indexer-password-file: file not found: " + args.indexer_password_file)
        with open(args.indexer_password_file, encoding="utf-8") as f:
            password = f.readline().rstrip("\r\n")
        if not password:
            die("--indexer-password-file: the first line (the password) is empty")
        new["password_file"] = P(INDEXER_PASS)
    elif new.get("password_file") and os.path.isfile(new["password_file"]):
        with open(new["password_file"], encoding="utf-8") as f:
            password = f.readline().rstrip("\r\n")
    missing = [k for k in ("url", "user", "password_file") if not new.get(k)]
    if missing or password is None:
        die("Wazuh 5.0: the bridge keeps its data in the Wazuh indexer. Pass --indexer-url "
            "https://<indexer>:9200 --indexer-user <user> --indexer-password-file <file> "
            "[--indexer-ca <root-ca.pem>] (missing: {0})".format(", ".join(missing) or "password"))
    try:  # reach the indexer with these settings before changing anything
        ciscat_indexer.Indexer(new["url"], new["user"], password, new.get("ca")).exists(
            ciscat_indexer.STORE_INDEX)
    except (ciscat_indexer.IndexerError, OSError, ValueError) as e:
        die("Wazuh indexer: {0}".format(e))
    return {"file": conf_file, "old": conf, "new": new, "password": password}


def write_indexer_config(settings):
    """/opt/ciscat/etc/indexer.json and indexer.pass (mode 600)."""
    conf_file, new = settings["file"], settings["new"]
    os.makedirs(os.path.dirname(conf_file), exist_ok=True)
    dst = new["password_file"]
    if dst == P(INDEXER_PASS):
        old = None
        if os.path.exists(dst):
            with open(dst, encoding="utf-8") as f:
                old = f.readline().rstrip("\r\n")
        if old != settings["password"]:
            fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(settings["password"] + "\n")
            say("indexer password stored in " + INDEXER_PASS)
        os.chmod(dst, 0o600)
    if new != settings["old"]:
        fd = os.open(conf_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(new, f, indent=2, sort_keys=True)
            f.write("\n")
        say("indexer configuration written: {0} ({1}, user {2})".format(
            INDEXER_CONF, new["url"], new["user"]))
    else:
        say("indexer configuration kept: {0} ({1})".format(INDEXER_CONF, new["url"]))
    os.chmod(conf_file, 0o600)
    return conf_file


def indexer_setup(args, settings):
    """Wazuh 5.0: store index and the Active Response channels and monitors of the runs."""
    import ciscat_indexer
    conf_file = write_indexer_config(settings)
    os.environ["CISCAT_INDEXER_CONF"] = conf_file  # for the store and the fleet runs below
    try:
        ix = ciscat_indexer.Indexer.from_config(conf_file)
        created = ix.ensure_store_index()
        say("dashboard store index {0}: {1}".format(ciscat_indexer.STORE_INDEX,
                                                   "created" if created else "present"))
        actions = dict(platform.AR_ACTIONS)
        if args.windows_bootstrap_executable:
            actions["ciscat-bootstrap-windows"] = args.windows_bootstrap_executable
        for line in ciscat_indexer.ensure_active_response(ix, actions, platform.TRIGGER_PATTERN):
            say("active response: " + line)
    except (ciscat_indexer.IndexerError, OSError, ValueError) as e:
        die("Wazuh indexer: {0}".format(e))


def master(payload, args, version):
    step("Master: CIS-CAT bridge {0}{1}".format(version, " (Wazuh 5.0)" if PLATFORM == 5 else ""))
    settings = indexer_settings(args) if PLATFORM == 5 else None
    crontab_text = read_crontab()
    b = make_backup(crontab_text)
    say("backup: {0}  (restore: --rollback {0})".format(b))

    lib_file = P("/opt/ciscat/etc/os-library.json")
    if not os.path.exists(lib_file):
        lib = os_library_from_fleet(P("/opt/ciscat/bin/ciscat-fleet.py"))
        source = "current ciscat-fleet.py"
        if lib is None:  # no v1 fleet in place: the seed shipped with the bridge
            lib = literal_assignment(os.path.join(payload, "bin", "ciscat-fleet.py"),
                                     "DEFAULT_OS_LIBRARY") or {}
            source = "bridge defaults"
        os.makedirs(os.path.dirname(lib_file), exist_ok=True)
        with open(lib_file, "w", encoding="utf-8") as f:
            json.dump(lib, f, indent=2, sort_keys=True)
            f.write("\n")
        os.chmod(lib_file, 0o640)
        say("os-library.json created from the {0}: {1}".format(
            source, ", ".join("{0}{1}".format(k, "" if v.get("active") else " (inactive)")
                              for k, v in sorted(lib.items()))))
    else:
        say("os-library.json kept (site configuration)")

    changed = install_files(payload)
    say("files updated: {0}".format(", ".join(changed) if changed else "none (already current)"))
    with open(P("/opt/ciscat/VERSION"), "w") as f:
        f.write(version + "\n")

    if PLATFORM == 5:
        step("Wazuh indexer")
        indexer_setup(args, settings)
        say("rule: Wazuh 5.0 has no XML rules. Import {0}/{1} as a custom Sigma rule through the "
            "indexer content manager (README.md).".format(RULES_DIR, SIGMA_RULE))
        rule_id = None
    else:
        rule_id = install_rule(payload)
    if rule_id:
        say("manager rule {0} installed: restart wazuh-manager to load it{1}".format(
            rule_id, " (doing it now)" if args.restart_manager else " (--restart-manager)"))
        if args.restart_manager and ROOT == "/":
            run(["systemctl", "restart", "wazuh-manager"], check=True)

    say("exclusions: " + migrate_exclusions())
    disabled = disable_old_cron(crontab_text)
    if disabled:
        say("old orchestrator cron disabled in: " + ", ".join(disabled))
    if install_cron():
        say("scheduler cron installed: " + CRON_FILE)

    pfile = P("/opt/ciscat/etc/.ciscat_api_pass")
    if not os.path.exists(P("/opt/ciscat/etc/ciscat-orchestrator.conf")) or not os.path.exists(pfile):
        say("WARNING: API credentials missing: create /opt/ciscat/etc/ciscat-orchestrator.conf "
            "(api_user, api_pass_file) and the password file (chmod 600)")
    elif os.stat(pfile).st_mode & 0o077:
        os.chmod(pfile, 0o600)
        say("password file permissions tightened to 600")

    step("Benchmark sheets for the dashboard (sync)")
    fleet("sync")
    step("Plan")
    rc = fleet("plan")
    if args.apply:
        step("Apply")
        rc = fleet("apply")
    else:
        say("\nNothing applied to the agents. Re-run with --apply, or use Apply in the dashboard.")
    return rc


def unwrap_plugin_zip(path):
    """The plugin zip itself, also when it arrives inside the zip GitHub wraps artifacts in."""
    import zipfile
    for _ in range(2):
        try:
            with zipfile.ZipFile(path) as z:
                names = z.namelist()
                if any(n.startswith("opensearch-dashboards/") for n in names):
                    return path
                inner = [n for n in names if n.endswith(".zip") and "/" not in n.strip("/")]
                if len(names) != 1 or len(inner) != 1:
                    die("not an OpenSearch Dashboards plugin zip (no opensearch-dashboards/ folder): " + path)
                out = os.path.join(os.path.dirname(path), "inner-" + os.path.basename(inner[0]))
                with z.open(inner[0]) as src, open(out, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                os.chmod(out, 0o644)
                say("plugin zip taken from the wrapper archive: " + inner[0])
                path = out
        except zipfile.BadZipFile:
            die("not a zip file: " + path)
    die("plugin zip nested too deep: " + path)


def dashboard(args):
    step("Dashboard: Wazuh plugin")
    if not (args.plugin_url or args.plugin_file):
        say("no --plugin-url/--plugin-file: plugin left as it is")
        return 0
    if not re.match(r"^[0-9a-f]{64}$", args.plugin_sha256 or ""):
        die("--plugin-sha256 (64 hex characters) is required to install the plugin")
    # a private dir the service user can read: the zip may sit in a home dir it cannot reach
    tmp = tempfile.mkdtemp(prefix="ciscat-plugin-")
    os.chmod(tmp, 0o755)
    staged = os.path.join(tmp, "wazuh-plugin.zip")
    if args.plugin_url:
        run(["curl", "-fsSL", "--proto", "=https", "-o", staged, args.plugin_url], check=True)
    else:
        shutil.copyfile(args.plugin_file, staged)
    os.chmod(staged, 0o644)
    if sha256(staged) != args.plugin_sha256:
        die("plugin checksum mismatch: refusing to install " + (args.plugin_url or args.plugin_file))
    staged = unwrap_plugin_zip(staged)
    tool = P(PLUGIN_TOOL)
    # the plugin tool must run as the dashboard service user, not root
    user = ["runuser", "-u", "wazuh-dashboard", "--"] if ROOT == "/" and os.geteuid() == 0 else []
    plugins = P("/usr/share/wazuh-dashboard/plugins")
    current = os.path.join(plugins, "wazuh")
    saved = None
    if os.path.isdir(current):
        saved = os.path.join(P("/opt/ciscat/backup"), "wazuh-plugin-{0}.tgz".format(time.strftime("%Y%m%d-%H%M%S")))
        os.makedirs(os.path.dirname(saved), exist_ok=True)
        with tarfile.open(saved, "w:gz") as tar:
            tar.add(current, arcname="wazuh")
        say("current plugin saved: " + saved)
    run(user + [tool, "remove", "wazuh"])
    rc, out = run(user + [tool, "install", "file://" + staged])
    shutil.rmtree(tmp, ignore_errors=True)
    if rc != 0:
        if saved:  # never leave the dashboard without its plugin
            if os.path.isdir(current):
                shutil.rmtree(current)
            with tarfile.open(saved) as tar:
                tar.extractall(plugins)
            if ROOT == "/":
                run(["chown", "-R", "wazuh-dashboard:wazuh-dashboard", current])
            die("plugin install failed, previous plugin restored:\n" + out[-2000:])
        die("plugin install failed:\n" + out[-2000:])
    say("plugin installed")
    if args.restart_dashboard:
        run(["systemctl", "restart", "wazuh-dashboard"], check=True)
        say("wazuh-dashboard restarted")
    else:
        say("restart wazuh-dashboard to load it (--restart-dashboard)")
    return 0


def main():
    ap = argparse.ArgumentParser(description="CIS-CAT bridge installer")
    ap.add_argument("--apply", action="store_true", help="master: also apply the policies to the agents")
    ap.add_argument("--restart-manager", action="store_true", help="master: restart to load the rule")
    ap.add_argument("--rollback", metavar="BACKUP", help="master: restore a backup made by this installer")
    ap.add_argument("--plugin-url", help="dashboard: HTTPS URL of the plugin zip in the internal repository")
    ap.add_argument("--plugin-file", help="dashboard: local plugin zip")
    ap.add_argument("--plugin-sha256", help="dashboard: expected SHA-256 of the plugin zip")
    ap.add_argument("--restart-dashboard", action="store_true")
    ap.add_argument("--indexer-url", help="Wazuh 5.0 master: indexer URL, e.g. https://127.0.0.1:9200")
    ap.add_argument("--indexer-user", help="Wazuh 5.0 master: indexer user of the bridge")
    ap.add_argument("--indexer-password-file", help="Wazuh 5.0 master: file with the indexer password "
                    "(copied to " + INDEXER_PASS + ", mode 600)")
    ap.add_argument("--indexer-ca", help="Wazuh 5.0 master: CA certificate of the indexer (PEM)")
    ap.add_argument("--windows-bootstrap-executable",
                    help="Wazuh 5.0 master: executable of the ciscat-bootstrap-windows Active Response "
                    "(default ciscat-bootstrap.cmd)")
    ap.add_argument("--version-file", default=os.path.join(HERE, "VERSION"))
    args = ap.parse_args()
    if ROOT == "/" and os.geteuid() != 0:
        die("run as root")
    if sys.version_info < (3, 6):
        die("python 3.6+ required")
    payload = HERE
    version = open(args.version_file).read().strip()
    global PLATFORM
    try:
        PLATFORM = platform.detect(ROOT)
    except ValueError as e:
        die(str(e))
    os.environ["CISCAT_PLATFORM"] = str(PLATFORM)  # the fleet runs below see the same platform
    os.environ["CISCAT_INDEXER_CONF"] = P(INDEXER_CONF)  # store backend: written on 5.0 only
    if args.rollback:
        rollback(args.rollback)
        return 0
    master_role, dash_role = is_master(), is_dashboard()
    if not master_role and not dash_role:
        die("neither a Wazuh manager nor a Wazuh dashboard was found on this host")
    rc = 0
    if master_role:
        rc = master(payload, args, version) or rc
    if dash_role:
        rc = dashboard(args) or rc
    step("Done (exit {0})".format(rc))
    return rc


if __name__ == "__main__":
    sys.exit(main())
