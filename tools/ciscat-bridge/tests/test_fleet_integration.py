"""End-to-end fleet test against a fake Wazuh API and real CIS XCCDF benchmarks.

CIS benchmark files are licensed and not part of this repository. Point CISCAT_TEST_BENCHMARKS
at a folder that holds:
  CIS_Ubuntu_Linux_20.04_LTS_Benchmark_v2.0.1-xccdf.xml   (stands in for a Linux OS)
  CIS_Microsoft_Windows_Server_2025_Benchmark_v1.0.0-xccdf.xml
The test is skipped without it.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "bin")
sys.path.insert(0, BIN)
sys.path.insert(0, HERE)
import ciscat_store as store  # noqa: E402
from fake_wazuh_api import FakeWazuh  # noqa: E402

BENCH_DIR = os.environ.get("CISCAT_TEST_BENCHMARKS", "")
LINUX = "CIS_Ubuntu_Linux_20.04_LTS_Benchmark_v2.0.1-xccdf.xml"
WIN = "CIS_Microsoft_Windows_Server_2025_Benchmark_v1.0.0-xccdf.xml"


def excl(**kw):
    rec = store.validate_exclusion(dict({"level": "L1", "reason": "test"}, **kw))
    return store.exclusion_key(rec), rec


@unittest.skipUnless(BENCH_DIR and os.path.isfile(os.path.join(BENCH_DIR, LINUX))
                     and os.path.isfile(os.path.join(BENCH_DIR, WIN)),
                     "CISCAT_TEST_BENCHMARKS not set")
class FleetIntegration(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        p = {k: os.path.join(self.root, k) for k in
             ("exclusions_dir", "benchmarks_dir", "shared_dir", "work_dir", "lists_dir", "run_dir")}
        for d in p.values():
            os.makedirs(d)
        self.paths = p
        for f in (LINUX, WIN):
            os.symlink(os.path.join(BENCH_DIR, f), os.path.join(p["benchmarks_dir"], f))
        etc = os.path.join(self.root, "etc")
        os.makedirs(etc)
        lib = {
            "rhel7": {"active": True, "family": "linux", "group": "os-rhel7", "benchmark": LINUX,
                      "companion_prefix": LINUX[:-10], "base": "rhel7-custom", "role": "Server",
                      "profiles": [["l1_server", "L1"]], "policy_id": "cis_rhel7_tailored_l1_server",
                      "policy_name": "Test Linux", "flat_path": "/var/lib/x/results.txt",
                      "ar_bootstrap": "!ciscat-bootstrap-linux0", "ar_refresh": "!ciscat-refresh-linux0"},
            "windows_server_2025": {"active": True, "family": "windows", "group": "os-windows_server_2025",
                                    "benchmark": WIN, "base": "cis_win2025_tailored_l1_ms",
                                    "role": "Member_Server", "profiles": [["l1_ms", "L1"]],
                                    "policy_id": "cis_win2025_tailored_l1_ms", "policy_name": "Test Win",
                                    "flat_path": "C:\\x.flat", "ar_bootstrap": "!ciscat-bootstrap0",
                                    "ar_assessment": "!ciscat-assessment0"},
        }
        with open(os.path.join(etc, "os-library.json"), "w") as f:
            json.dump(lib, f)
        self.fake = FakeWazuh(p["shared_dir"], {
            "001": {"name": "web-01", "status": "active", "group": ["os-rhel7", "app-sap"]},
            "002": {"name": "web-02", "status": "active", "group": ["os-rhel7"]},
            "003": {"name": "db-01", "status": "disconnected", "group": ["os-rhel7", "app-sap"]},
            "004": {"name": "win-01", "status": "active", "group": ["os-windows_server_2025"]},
        })
        self.env = dict(os.environ, CISCAT_ETC_DIR=etc, CISCAT_PATHS_JSON=json.dumps(p),
                        CISCAT_API_URL=self.fake.serve(), WAZUH_API_PASSWORD="x", CISCAT_AR_GAP="0")

    def tearDown(self):
        self.fake.server.shutdown()

    def fleet(self, *args):
        r = subprocess.run([sys.executable, os.path.join(BIN, "ciscat-fleet.py")] + list(args),
                           env=self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)
        return r.stdout

    def policy_rules(self, group, policy_id):
        with open(os.path.join(self.paths["shared_dir"], group, policy_id + ".yml")) as f:
            return set(re.findall(r"r:\^([0-9\\.]+):pass", f.read()))

    def test_sync_apply_combos_and_trigger(self):
        out = self.fleet("sync")
        bench, errors = store.read_list("ciscat-bench-rhel7", self.paths["lists_dir"])
        self.assertEqual(errors, [])
        self.assertIn("L1_Server", bench["_meta"]["profiles"])
        self.assertIn("L1_Server", bench["1.1.1.1"]["p"])
        oskeys, _ = store.read_list(store.OSKEYS, self.paths["lists_dir"])
        self.assertTrue(oskeys["windows_server_2025"]["available"], out)

        recs = dict([excl(os_key="rhel7", scope="os", rule="1.1.1.1"),
                     excl(os_key="rhel7", scope="app_group", scope_value="app-sap", rule="1.1.1.2"),
                     excl(os_key="rhel7", scope="host", scope_value="WEB-02", rule="1.1.1.3"),
                     excl(os_key="windows_server_2025", scope="os", rule="1.1.1")])
        store.write_list(store.EXCLUSIONS, recs, self.paths["lists_dir"])
        plan = self.fleet("plan")
        self.assertIn("[dry-run]", plan)
        self.assertEqual([c for c in self.fake.calls if c[0] != "GET" and "authenticate" not in c[1]], [])

        self.fleet("apply", "--request", "r1")
        a = self.fake.agents
        combo = {aid: [g for g in a[aid]["group"] if g.startswith("ciscat-")] for aid in a}
        self.assertEqual(len(combo["001"]), 1)
        self.assertEqual(combo["001"], combo["003"])  # same app group -> same combo
        self.assertNotEqual(combo["001"], combo["002"])
        self.assertEqual(combo["004"], ["ciscat-windows_server_2025-base"])
        pid = "cis_rhel7_tailored_l1_server"
        base = self.policy_rules("ciscat-rhel7-base", pid)
        sap = self.policy_rules(combo["001"][0], pid)
        host = self.policy_rules(combo["002"][0], pid)
        self.assertNotIn(r"1\.1\.1\.1", base | sap | host)       # OS exclusion everywhere
        self.assertEqual(base - sap, {r"1\.1\.1\.2"})            # app group only
        self.assertEqual(base - host, {r"1\.1\.1\.3"})           # host only, case-insensitive
        self.assertNotIn(r"1\.1\.1", self.policy_rules("ciscat-windows_server_2025-base",
                                                       "cis_win2025_tailored_l1_ms"))
        for g in ("os-rhel7", "os-windows_server_2025"):   # the policy left the OS groups
            self.assertFalse([f for f in os.listdir(os.path.join(self.paths["shared_dir"], g))
                              if f.endswith(".yml")])
        with open(os.path.join(self.paths["exclusions_dir"], "rhel7.csv")) as f:
            self.assertIn("app_group,app-sap,l1", f.read())
        status, _ = store.read_list(store.STATUS, self.paths["lists_dir"])
        self.assertEqual((status["apply"]["state"], status["apply"]["request"]), ("ok", "r1"))
        self.assertEqual(status["apply"]["per_os"]["rhel7"]["combos"], 3)

        # dropping the host exclusion moves web-02 back to base and removes its combo group
        stale = combo["002"][0]
        del recs[excl(os_key="rhel7", scope="host", scope_value="web-02", rule="1.1.1.3")[0]]
        store.write_list(store.EXCLUSIONS, recs, self.paths["lists_dir"])
        self.fleet("apply")
        self.assertIn("ciscat-rhel7-base", a["002"]["group"])
        self.assertNotIn(stale, self.fake.groups)

        out = self.fleet("trigger", "--targets", "rhel7", "--wave-size", "1", "--job", "j1")
        cmds = [c for c, _ in self.fake.ar]
        self.assertEqual(cmds.count("!ciscat-refresh-linux0"), 2, out)  # 001 and 002, one per wave
        self.assertNotIn("!ciscat-assessment0", cmds)
        status, _ = store.read_list(store.STATUS, self.paths["lists_dir"])
        self.assertEqual((status["job-j1"]["sent"], status["job-j1"]["skipped"]), (2, ["003"]))


if __name__ == "__main__":
    unittest.main()
