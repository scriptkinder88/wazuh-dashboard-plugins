"""Daily coverage snapshot (ciscat-fleet.py history) against the fake Wazuh API."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "bin")
sys.path.insert(0, BIN)
sys.path.insert(0, HERE)
import ciscat_store as store  # noqa: E402
from fake_wazuh_api import FakeWazuh  # noqa: E402


def entry(group, policy, family="linux", active=True):
    return {"active": active, "family": family, "group": group, "benchmark": "none-xccdf.xml",
            "base": policy, "role": "Server", "profiles": [["l1_server", "L1"]],
            "policy_id": policy, "policy_name": policy, "flat_path": "/x",
            "ar_bootstrap": "!b", "ar_refresh": "!r", "ar_assessment": "!a"}


def ago(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


class History(unittest.TestCase):
    def setUp(self):
        root = tempfile.mkdtemp()
        self.paths = {k: os.path.join(root, k) for k in
                      ("exclusions_dir", "benchmarks_dir", "shared_dir", "work_dir", "lists_dir",
                       "run_dir")}
        for d in self.paths.values():
            os.makedirs(d)
        etc = os.path.join(root, "etc")
        os.makedirs(etc)
        with open(os.path.join(etc, "os-library.json"), "w") as f:
            json.dump({"rhel7": entry("os-rhel7", "cis_rhel7"),
                       "win": entry("os-win", "cis_win", "windows"),
                       "debian12": entry("os-debian12", "cis_debian12", active=False),
                       "rhel8": entry("os-rhel8", "cis_rhel8")}, f)
        self.fake = FakeWazuh(self.paths["shared_dir"], {
            "001": {"name": "web-01", "status": "active", "group": ["os-rhel7"]},
            "002": {"name": "web-02", "status": "disconnected", "group": ["os-rhel7"]},
            "003": {"name": "web-03", "status": "active", "group": ["os-rhel7"]},
            "004": {"name": "win-01", "status": "active", "group": ["os-win"]},
            "005": {"name": "deb-01", "status": "active", "group": ["os-debian12"]},
        })
        self.fake.sca = {"001": {"cis_rhel7": ago(2)}, "002": {"cis_rhel7": ago(50)},
                         "004": {"cis_win": ago(40), "other": ago(1)}}
        self.env = dict(os.environ, CISCAT_ETC_DIR=etc, CISCAT_PATHS_JSON=json.dumps(self.paths),
                        CISCAT_API_URL=self.fake.serve(), WAZUH_API_PASSWORD="x")

    def tearDown(self):
        self.fake.server.shutdown()

    def history(self, *args):
        r = subprocess.run([sys.executable, os.path.join(BIN, "ciscat-fleet.py"), "history"] +
                           list(args), env=self.env, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)
        return r.stdout

    def test_coverage_of_the_day(self):
        out = self.history("--day", "2026-10-02")
        self.assertIn("[rhel7] os-rhel7: 1/3 assessed in the last 35 days, 1 not assessed and "
                      "disconnected", out)
        records, errors = store.read_list(store.HISTORY, self.paths["lists_dir"])
        self.assertEqual(errors, [])
        self.assertEqual(records["2026-10-02"], {
            "v": 1, "stale_days": 35, "os": {
                "rhel7": {"group": "os-rhel7", "expected": 3, "assessed": 1, "disconnected": 1},
                "win": {"group": "os-win", "expected": 1, "assessed": 0, "disconnected": 0},
            }})  # inactive OSes and OSes without a group are left out

    def test_keeps_400_days(self):
        start = datetime(2025, 1, 1)
        old = {(start + timedelta(days=i)).strftime("%Y-%m-%d"): {"v": 1, "os": {}}
               for i in range(405)}
        store.write_list(store.HISTORY, old, self.paths["lists_dir"])
        self.history("--day", "2026-10-02")
        records, _ = store.read_list(store.HISTORY, self.paths["lists_dir"])
        self.assertEqual(len(records), 400)
        self.assertIn("2026-10-02", records)
        self.assertEqual(min(records), (start + timedelta(days=6)).strftime("%Y-%m-%d"))

    def test_rejects_a_bad_day(self):
        r = subprocess.run([sys.executable, os.path.join(BIN, "ciscat-fleet.py"), "history",
                            "--day", "02/10/2026"], env=self.env, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--day must be YYYY-MM-DD", r.stdout)


if __name__ == "__main__":
    unittest.main()
