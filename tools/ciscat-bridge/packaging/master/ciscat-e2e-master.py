#!/usr/bin/env python3
"""End-to-end check of the CIS-CAT bridge, master side. Run as root on the Wazuh master.

  python3 ciscat-e2e-master.py pre  <agent> [<agent> ...]   # before the run: is everything in place?
  python3 ciscat-e2e-master.py run  <agent> [<agent> ...]   # start the assessment on those agents
  python3 ciscat-e2e-master.py post <agent> [<agent> ...]   # after the run: did SCA read the results?

<agent> is an agent id (003) or name. Read-only except "run", which only sends the same Active
Response the dashboard "Run now" sends. Prints EXPECT / GOT and PASS, FAIL or WAIT per check.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

# the defaults are the master's; the environment overrides them only to test this script
FLEET_PATH = os.environ.get("E2E_FLEET", "/opt/ciscat/bin/ciscat-fleet.py")
OSSEC = os.environ.get("E2E_OSSEC", "/var/ossec")
SHARED = os.environ.get("E2E_SHARED", OSSEC + "/etc/shared")
STATE = os.environ.get("E2E_STATE", "/opt/ciscat/run/e2e-last.json")
VERSION_FILE = os.environ.get("E2E_VERSION_FILE", "/opt/ciscat/VERSION")
EXPECTED_VERSION = "2.3.0"
AR_EXPECTED = {
    "ciscat-assessment0": "ciscat-assessment.cmd",
    "ciscat-bootstrap-linux0": "ciscat-bootstrap.sh",
    "ciscat-refresh-linux0": "ciscat-refresh.sh",
}
RESULTS = {"PASS": 0, "FAIL": 0, "WAIT": 0, "INFO": 0}


def check(code, title, expect, got, ok, wait=False):
    state = "PASS" if ok else ("WAIT" if wait else "FAIL")
    RESULTS[state] += 1
    print("[{0}] {1} {2}\n        EXPECT: {3}\n        GOT:    {4}".format(state, code, title, expect, got))
    return ok


def info(code, text):
    RESULTS["INFO"] += 1
    print("[INFO] {0} {1}".format(code, text))


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_fleet():
    spec = importlib.util.spec_from_file_location("fleet", FLEET_PATH)
    fleet = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fleet)
    fleet.OS_LIBRARY, _ = fleet.load_os_library()
    fleet.load_api_credentials(argparse.Namespace(password=None, password_file=None, user=None))
    return fleet


def resolve(fleet, token, names):
    """{id: agent record} of the agents given by id or name."""
    items = fleet.paged(token, "/agents?select={0},version,lastKeepAlive".format(fleet.AGENT_FIELDS))
    by_id = {a["id"]: a for a in items}
    by_name = {a.get("name", "").lower(): a for a in items}
    out = {}
    for n in names:
        a = by_id.get(n) or by_name.get(n.lower())
        if not a:
            check("M0", "agent {0} known to the manager".format(n), "an agent with this id or name",
                  "not found", False)
            continue
        out[a["id"]] = a
    return out


def oses_of(fleet, agent):
    rec = fleet.agent_record(agent)
    keys = sorted(k for k, c in fleet.OS_LIBRARY.items()
                  if c["active"] and c["group"] in rec["groups"])
    return rec, [k for k in keys if not fleet.wrong_platform(fleet.OS_LIBRARY[k], rec["platform"])], \
        [k for k in keys if fleet.wrong_platform(fleet.OS_LIBRARY[k], rec["platform"])]


def sca_state(fleet, token, aid, policy_id):
    data = fleet.api_json("GET", "/sca/{0}?q=policy_id={1}".format(aid, policy_id), token)
    items = data.get("affected_items", [])
    return items[0] if items else None


def ar_conf_lines():
    try:
        with open(SHARED + "/ar.conf") as f:
            return f.read()
    except OSError:
        return ""


def policy_flat_path(path):
    """The f:<file> the policy reads its results from."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = re.search(r"'f:([^']+?)(?: ->|')", line)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return ""


def signature_ok(manifest, pub):
    """'valid', or why not: the .sig is the base64 RSA/SHA-256 signature of the manifest."""
    import base64
    import tempfile
    try:
        with open(manifest + ".sig") as f:
            sig = base64.b64decode(f.read())
    except (OSError, ValueError) as e:
        return "no signature ({0})".format(e)
    with tempfile.NamedTemporaryFile() as t:
        t.write(sig)
        t.flush()
        r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", pub, "-signature", t.name,
                            manifest], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return "valid" if r.returncode == 0 else "not valid: " + r.stdout.strip()[:120]


def manifest_ok(gdir, name, digest=None):
    """(entries, problems) of a manifest: every file listed must be in the group with its sha256
    (for Windows, the sha256 of the CRLF copy the agent stores: digest=fleet.windows_sha256)."""
    digest = digest or sha256
    entries, problems = 0, []
    with open(os.path.join(gdir, name), encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(";")
            if not line.strip() or line.startswith("#") or len(parts) < 2:
                continue
            entries += 1
            path = os.path.join(gdir, parts[0])
            if not os.path.isfile(path):
                problems.append(parts[0] + " missing")
            elif digest(path) != parts[1]:
                problems.append(parts[0] + " sha256 differs")
    return entries, problems


def pre(fleet, token, agents):
    print("== M1 bridge on the master")
    try:
        with open(VERSION_FILE) as f:
            version = f.read().strip()
    except OSError:
        version = "none"
    check("M1", "bridge version", EXPECTED_VERSION, version, version == EXPECTED_VERSION)

    print("\n== M2 Active Response commands distributed to the agents (shared/ar.conf)")
    ar = ar_conf_lines()
    for name, exe in AR_EXPECTED.items():
        line = next((ln for ln in ar.splitlines() if ln.startswith(name + " ")), "")
        check("M2", name, "{0} - {1}".format(name, exe), line or "missing",
              "- {0} -".format(exe) in line)

    for aid, agent in agents.items():
        rec, keys, wrong = oses_of(fleet, agent)
        print("\n== agent {0} {1}".format(aid, rec["name"]))
        check("M3", "agent connected", "active", rec["status"], rec["status"] == "active")
        info("M3", "platform={0} version={1} groups={2}".format(
            rec["platform"] or "?", agent.get("version", "?"), ", ".join(rec["groups"])))
        check("M4", "CIS-CAT benchmarks for this agent",
              "at least one active OS whose group the agent is in, of its platform",
              ", ".join(keys) or "none", bool(keys))
        if wrong:
            info("M4", "groups of OSes of another platform (never run here, by design): " +
                 ", ".join(wrong))
        try:
            out = subprocess.run([OSSEC + "/bin/agent_groups", "-S", "-i", aid],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 universal_newlines=True).stdout
        except OSError as e:
            out = str(e)
        synced = [ln.strip() for ln in out.splitlines() if "sync" in ln.lower()]
        check("M5", "group files synchronized to the agent", "synchronized (not 'not synchronized')",
              (synced or [out.strip()[-120:] or "no answer"])[-1],
              any("sync" in ln.lower() and "not" not in ln.lower() for ln in synced))
        for k in keys:
            cfg = fleet.OS_LIBRARY[k]
            gdir = os.path.join(SHARED, cfg["group"])
            print("  -- benchmark {0} (group {1}, family {2})".format(k, cfg["group"], cfg["family"]))
            if cfg["family"] == "windows":
                own = [cfg["base"] + "-custom.xml", "ciscat-params-{0}.txt".format(k),
                       "tailoring-{0}.csv".format(k), "ciscat-manifest-{0}.csv".format(k)]
            else:
                own = [cfg["base"] + "-xccdf.xml", "ciscat-refresh-{0}.conf".format(k),
                       "ciscat-manifest-{0}.csv".format(k), "ciscat-refresh.sh"]
            missing = [f for f in own if not os.path.isfile(os.path.join(gdir, f))]
            check("M6", "files of {0} in {1}".format(k, cfg["group"]), ", ".join(own),
                  "missing: " + ", ".join(missing) if missing else "all present", not missing)
            if os.path.isfile(os.path.join(gdir, "ciscat-manifest-{0}.csv".format(k))):
                n, problems = manifest_ok(gdir, "ciscat-manifest-{0}.csv".format(k),
                                          fleet.windows_sha256 if cfg.get("family") == "windows" else None)
                check("M7", "manifest of {0} matches the files".format(k), "every sha256 equal",
                      "; ".join(problems) or "{0} files ok".format(n), not problems)
                mpath = os.path.join(gdir, "ciscat-manifest-{0}.csv".format(k))
                check("M7", "manifest of {0} signed with the master's key".format(k),
                      "signature valid", signature_ok(mpath, fleet.SIGN_PUB), signature_ok(mpath, fleet.SIGN_PUB) == "valid")
            combos = [g for g in rec["groups"] if fleet.is_combo_group(k, g)]
            check("M8", "agent in one policy group of {0}".format(k), "ciscat-{0}-base or -<hash>".format(k),
                  ", ".join(combos) or "none", len(combos) == 1)
            for g in combos:
                ypath = os.path.join(SHARED, g, cfg["policy_id"] + ".yml")
                check("M9", "SCA policy {0} in {1}".format(cfg["policy_id"], g), ypath,
                      "present" if os.path.isfile(ypath) else "missing", os.path.isfile(ypath))
                flat = policy_flat_path(ypath)
                check("M10", "policy reads the results file of {0}".format(k), cfg["flat_path"],
                      flat or "?", flat == cfg["flat_path"])
            st = sca_state(fleet, token, aid, cfg["policy_id"])
            info("M11", "SCA {0} now: {1}".format(cfg["policy_id"], "no scan yet" if not st else
                 "end_scan={0} score={1}% pass={2} fail={3} total={4}".format(
                     st.get("end_scan"), st.get("score"), st.get("pass"), st.get("fail"),
                     st.get("total_checks"))))


def run(fleet, token, agents):
    ids = sorted(agents)
    before = {}
    for aid, agent in agents.items():
        _, keys, _ = oses_of(fleet, agent)
        for k in keys:
            st = sca_state(fleet, token, aid, fleet.OS_LIBRARY[k]["policy_id"])
            before["{0}/{1}".format(aid, k)] = (st or {}).get("end_scan", "")
    job = "e2e" + datetime.now().strftime("%Y%m%d%H%M%S")
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print("== trigger {0} on {1} (job {2}, {3} UTC)".format(FLEET_PATH, ",".join(ids), job, started))
    p = subprocess.run([sys.executable, FLEET_PATH, "trigger", "--agents", ",".join(ids),
                        "--wave-pause", "0", "--job", job], stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, universal_newlines=True)
    print(p.stdout)
    status, _ = fleet.store.read_list(fleet.store.STATUS, fleet.PATHS["lists_dir"])
    st = status.get("job-" + job, {})
    check("R1", "Active Response sent", "state ok, sent = number of agents, skipped none",
          "state={0} sent={1} failed={2} skipped={3}".format(st.get("state"), st.get("sent"),
                                                            st.get("failed"), st.get("skipped_reasons") or "none"),
          st.get("state") == "ok" and st.get("sent") == len(ids) and not st.get("skipped"))
    with open(STATE, "w") as f:
        json.dump({"job": job, "started": started, "agents": ids, "before": before}, f)
    print("\nNow on each agent: the agent script 'watch', then 'post'. Then here: 'post'.")


def post(fleet, token, agents):
    try:
        with open(STATE) as f:
            last = json.load(f)
    except OSError:
        sys.exit("no run recorded: run 'run' first")
    print("== run {0} started {1} UTC".format(last["job"], last["started"]))
    for aid, agent in agents.items():
        rec, keys, _ = oses_of(fleet, agent)
        for k in keys:
            cfg = fleet.OS_LIBRARY[k]
            st = sca_state(fleet, token, aid, cfg["policy_id"]) or {}
            end = st.get("end_scan", "")
            t_end = fleet.parse_scan_time(end) if end else None
            t_run = fleet.parse_scan_time(last["started"])
            newer = bool(t_end and t_run and t_end > t_run)
            check("P1", "agent {0} {1}: SCA read the new results of {2}".format(aid, rec["name"], k),
                  "end_scan after {0}".format(last["started"]),
                  "end_scan={0} score={1}% pass={2} fail={3} invalid={4} total={5}".format(
                      end or "none", st.get("score"), st.get("pass"), st.get("fail"),
                      st.get("invalid"), st.get("total_checks")),
                  newer, wait=not newer)
            if not newer:
                print("        SCA reads the results every hour (interval set by the bridge) and "
                      "when the agent starts: once the agent script says the results file is new, "
                      "wait for the next scan or restart the agent, and run 'post' again.")
            elif st.get("total_checks") and st.get("invalid") == st.get("total_checks"):
                check("P2", "results understood by the policy", "invalid < total",
                      "every check invalid: the results file is missing or empty", False)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("step", choices=["pre", "run", "post"])
    ap.add_argument("agents", nargs="+")
    args = ap.parse_args()
    if os.geteuid() != 0 and not os.environ.get("E2E_FLEET"):
        sys.exit("run as root")
    fleet = load_fleet()
    token = fleet.get_token()
    agents = resolve(fleet, token, args.agents)
    if agents:
        {"pre": pre, "run": run, "post": post}[args.step](fleet, token, agents)
    print("\nSUMMARY: PASS={PASS} FAIL={FAIL} WAIT={WAIT}".format(**RESULTS))
    return 1 if RESULTS["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
