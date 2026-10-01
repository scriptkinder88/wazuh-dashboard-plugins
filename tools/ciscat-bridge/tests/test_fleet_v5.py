"""Wazuh 5.0 runs and report: trigger documents instead of PUT /active-response, SCA results from
the indexer instead of /sca (fake Wazuh API + fake indexer, no benchmark needed)."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "bin")
sys.path.insert(0, BIN)
sys.path.insert(0, HERE)
import ciscat_store as store  # noqa: E402
from fake_indexer import FakeIndexer  # noqa: E402
from fake_wazuh_api import FakeWazuh  # noqa: E402
from test_indexer_store import write_conf  # noqa: E402

LIBRARY = {
    "rhel7": {"active": True, "family": "linux", "group": "os-rhel7",
              "benchmark": "CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v4.0.0-xccdf.xml",
              "role": "Server", "profiles": [["l1_server", "L1"]],
              "policy_id": "cis_rhel7_tailored_l1_server", "policy_name": "x", "flat_path": "/x",
              "ar_bootstrap": "!ciscat-bootstrap-linux0", "ar_refresh": "!ciscat-refresh-linux0"},
    "windows_server_2025": {"active": True, "family": "windows", "group": "os-windows_server_2025",
                            "benchmark": "CIS_Microsoft_Windows_Server_2025_Benchmark_v2.0.0-xccdf.xml",
                            "role": "Member_Server", "profiles": [["l1_ms", "L1"]],
                            "policy_id": "cis_win2025_tailored_l1_ms", "policy_name": "y",
                            "flat_path": "C:\\x", "ar_bootstrap": "!ciscat-bootstrap0",
                            "ar_assessment": "site-assessment"},
}


class FleetV5(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        p = {k: os.path.join(self.d, k) for k in
             ("exclusions_dir", "benchmarks_dir", "shared_dir", "work_dir", "lists_dir", "run_dir")}
        for path in p.values():
            os.makedirs(path)
        etc = os.path.join(self.d, "etc")
        os.makedirs(etc)
        with open(os.path.join(etc, "os-library.json"), "w") as f:
            json.dump(LIBRARY, f)
        self.api = FakeWazuh(p["shared_dir"], {
            "001": {"name": "web-01", "status": "active", "group": ["os-rhel7"]},
            "002": {"name": "web-02", "status": "active", "group": ["os-rhel7"]},
            "003": {"name": "db-01", "status": "disconnected", "group": ["os-rhel7"]},
            "004": {"name": "win-01", "status": "active", "group": ["os-windows_server_2025"]},
        })
        self.ix = FakeIndexer()
        self.addCleanup(self.ix.stop)
        self.conf = write_conf(self.d, self.ix.serve())
        self.env = dict(os.environ, CISCAT_ETC_DIR=etc, CISCAT_PATHS_JSON=json.dumps(p),
                        CISCAT_API_URL=self.api.serve(), WAZUH_API_PASSWORD="x",
                        CISCAT_AR_GAP="0", CISCAT_PLATFORM="5", CISCAT_INDEXER_CONF=self.conf)
        self.addCleanup(self.api.server.server_close)
        self.addCleanup(self.api.server.shutdown)

    def fleet(self, *args, rc=0):
        r = subprocess.run([sys.executable, os.path.join(BIN, "ciscat-fleet.py")] + list(args),
                           env=self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.assertEqual(r.returncode, rc, r.stdout)
        return r.stdout

    def triggers(self):
        return self.ix.streams.get("wazuh-findings-v5-ciscat", [])

    def status(self):
        os.environ["CISCAT_INDEXER_CONF"] = self.conf
        try:
            store._INDEXERS.clear()
            return store.read_list(store.STATUS)[0]
        finally:
            os.environ.pop("CISCAT_INDEXER_CONF")
            store._INDEXERS.clear()

    def test_trigger_writes_one_document_per_agent_and_action(self):
        out = self.fleet("trigger", "--wave-size", "1", "--job", "j1")
        self.assertEqual(self.api.ar, [])  # no PUT /active-response on 5.0
        docs = self.triggers()
        got = [(d["event"]["action"], d["wazuh"]["agent"]["id"]) for d in docs]
        self.assertEqual(got, [  # wave by wave: bootstrap, then the assessment
            ("ciscat-bootstrap-linux", "001"), ("ciscat-refresh-linux", "001"),
            ("ciscat-bootstrap-linux", "002"), ("ciscat-refresh-linux", "002"),
            ("ciscat-bootstrap-windows", "004"), ("site-assessment", "004")])
        d = docs[1]
        self.assertEqual(d["event"], {"kind": "event", "module": "ciscat", "dataset": "ciscat.run",
                                      "action": "ciscat-refresh-linux"})
        self.assertEqual(d["rule"], {"name": "CIS-CAT run requested"})
        self.assertEqual(d["wazuh"], {"agent": {"id": "001", "name": "web-01"},
                                      "integration": {"name": "ciscat-bridge"}})
        self.assertRegex(d["@timestamp"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}[+-]\d\d:\d\d$")
        bulks = [c for c in self.ix.calls if c[1].endswith("/_bulk")]
        self.assertEqual(len(bulks), 6)
        self.assertTrue(all(c[1] == "/wazuh-findings-v5-ciscat/_bulk" for c in bulks))
        st = self.status()["job-j1"]
        self.assertEqual((st["state"], st["sent"], st["failed"], st["skipped"]),
                         ("ok", 3, 0, ["003"]))
        self.assertIn("Alerting monitors", out)

    def test_rejected_documents_are_counted_as_failed(self):
        self.ix.reject_bulk = {"002"}
        self.fleet("trigger", "--targets", "rhel7", "--job", "j2", rc=1)
        st = self.status()["job-j2"]
        self.assertEqual((st["state"], st["sent"], st["failed"]), ("error", 1, 1))

    def test_gap_is_90_seconds_on_5_unless_overridden(self):
        code = ("import importlib.util,sys;sys.argv=['x'];"
                "s=importlib.util.spec_from_file_location('f',{0!r});m=importlib.util.module_from_spec(s);"
                "s.loader.exec_module(m);print(m.AR_GAP, m.PLATFORM)").format(
                    os.path.join(BIN, "ciscat-fleet.py"))
        env = dict(self.env)
        del env["CISCAT_AR_GAP"]
        for platform, gap, expected in (("5", None, "90 5"), ("4", None, "15 4"), ("5", "7", "7 5")):
            env["CISCAT_PLATFORM"] = platform
            if gap:
                env["CISCAT_AR_GAP"] = gap
            r = subprocess.run([sys.executable, "-c", code], env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True)
            self.assertEqual(r.stdout.strip(), expected, r.stdout)

    def test_trigger_without_indexer_config_stops(self):
        self.env["CISCAT_INDEXER_CONF"] = os.path.join(self.d, "missing.json")
        out = self.fleet("trigger", rc=1)
        self.assertIn("needs the indexer configuration", out)
        self.assertEqual(self.api.ar, [])

    def test_report_from_the_sca_states(self):
        pid = "cis_rhel7_tailored_l1_server"
        self.ix.sca_states = ([("001", pid, "Passed")] * 3 + [("001", pid, "Failed")] +
                              [("001", pid, "Not applicable")] * 2 + [("001", "other", "Failed")] +
                              [("002", pid, "Failed")] * 2)
        out = self.fleet("report")
        rows = {line.split()[0]: line.split() for line in out.splitlines()[2:] if line.strip()}
        self.assertEqual(rows["001"][1:], ["web-01", pid, "6", "3", "1", "2", "75"])
        self.assertEqual(rows["002"][3:], ["2", "0", "2", "0", "0"])
        self.assertIn("no results yet", " ".join(rows["004"]))
        self.assertNotIn("/sca/", " ".join(c[1] for c in self.api.calls))


if __name__ == "__main__":
    unittest.main()
