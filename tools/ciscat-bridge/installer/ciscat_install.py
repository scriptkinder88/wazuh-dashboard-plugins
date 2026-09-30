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
RULE_ID = "100950"
PLUGIN_TOOL = "/usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin"

MANAGED_BIN = [
    "ciscat-fleet.py", "ciscat-scheduler.py", "ciscat_store.py", "ciscat_schedule.py",
    "csv_to_custom_xccdf.py", "xccdf_to_sca_policy.py", "benchmark_to_sheet.py",
    "ciscat-refresh.sh", "ciscat-bootstrap.sh", "maps/ciscat-profiles.json",
    "maps/os-benchmark-map.json",
]
MANAGED_AGENT = ["ciscat-assessment.ps1", "ciscat-assessment.cmd"]
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
            os.chown(path, pwd.getpwnam("wazuh").pw_uid, grp.getgrnam("wazuh").gr_gid)
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
    for p in (P("/opt/ciscat/bin"), P("/opt/ciscat/agent")):
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
    for d in ("/opt/ciscat/log", "/opt/ciscat/run", "/opt/ciscat/etc"):
        os.makedirs(P(d), exist_ok=True)
    return installed


def install_rule(payload):
    dst = P("/var/ossec/etc/rules/ciscat_rules.xml")
    others = [f for f in glob.glob(P("/var/ossec/etc/rules/*.xml")) + glob.glob(P("/var/ossec/ruleset/rules/*.xml"))
              if os.path.abspath(f) != os.path.abspath(dst)]
    for f in others:
        with open(f, encoding="utf-8", errors="replace") as fh:
            if re.search(r'<rule\s+id="{0}"'.format(RULE_ID), fh.read()):
                say("WARNING: rule id {0} already used in {1}: CIS-CAT rule NOT installed".format(RULE_ID, f))
                return False
    src = os.path.join(payload, "rules", "ciscat_rules.xml")
    if os.path.exists(dst) and sha256(dst) == sha256(src):
        return False
    previous = open(dst, "rb").read() if os.path.exists(dst) else None
    shutil.copyfile(src, dst)
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
            return False
    return True


def migrate_exclusions():
    sys.path.insert(0, P("/opt/ciscat/bin"))
    import ciscat_store as store
    lists_dir = P("/var/ossec/etc/lists")
    if os.path.exists(os.path.join(lists_dir, store.EXCLUSIONS)):
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


def master(payload, args, version):
    step("Master: CIS-CAT bridge {0}".format(version))
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

    if install_rule(payload):
        say("manager rule {0} installed: restart wazuh-manager to load it{1}".format(
            RULE_ID, " (doing it now)" if args.restart_manager else " (--restart-manager)"))
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


def dashboard(args):
    step("Dashboard: Wazuh plugin")
    if not (args.plugin_url or args.plugin_file):
        say("no --plugin-url/--plugin-file: plugin left as it is")
        return 0
    if not re.match(r"^[0-9a-f]{64}$", args.plugin_sha256 or ""):
        die("--plugin-sha256 (64 hex characters) is required to install the plugin")
    tmp = tempfile.mkdtemp()
    zip_path = args.plugin_file
    if args.plugin_url:
        zip_path = os.path.join(tmp, "wazuh-plugin.zip")
        run(["curl", "-fsSL", "--proto", "=https", "-o", zip_path, args.plugin_url], check=True)
    if sha256(zip_path) != args.plugin_sha256:
        die("plugin checksum mismatch: refusing to install " + zip_path)
    tool = P(PLUGIN_TOOL)
    # the plugin tool must run as the dashboard service user, not root
    user = ["runuser", "-u", "wazuh-dashboard", "--"] if ROOT == "/" and os.geteuid() == 0 else []
    run(user + [tool, "remove", "wazuh"])
    run(user + [tool, "install", "file://" + os.path.abspath(zip_path)], check=True)
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
    ap.add_argument("--version-file", default=os.path.join(HERE, "VERSION"))
    args = ap.parse_args()
    if ROOT == "/" and os.geteuid() != 0:
        die("run as root")
    if sys.version_info < (3, 6):
        die("python 3.6+ required")
    payload = HERE
    version = open(args.version_file).read().strip()
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
