"""Groups owned by infrastructure code (ciscat-fleet.py baseline), against the fake Wazuh API."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "bin")
sys.path.insert(0, HERE)
from fake_wazuh_api import FakeWazuh  # noqa: E402

CONF = """<agent_config os="Linux">
  <syscheck>
    <!-- wz-fim eyJyZWFzb24iOiJiYXNlbGluZSJ9 -->
    <directories whodata="yes">/etc</directories>
  </syscheck>
</agent_config>
"""


class Baseline(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        paths = {k: os.path.join(self.root, k) for k in
                 ("exclusions_dir", "benchmarks_dir", "shared_dir", "work_dir", "lists_dir", "run_dir")}
        for d in paths.values():
            os.makedirs(d)
        etc = os.path.join(self.root, "etc")
        os.makedirs(etc)
        with open(os.path.join(etc, "os-library.json"), "w") as f:
            json.dump({}, f)
        self.fake = FakeWazuh(paths["shared_dir"], {
            "001": {"name": "web-01", "status": "active", "group": ["default"]},
            "002": {"name": "web-02", "status": "active", "group": ["default"]},
        })
        self.env = dict(os.environ, CISCAT_ETC_DIR=etc, CISCAT_PATHS_JSON=json.dumps(paths),
                        CISCAT_API_URL=self.fake.serve(), WAZUH_API_PASSWORD="x")

    def tearDown(self):
        self.fake.server.shutdown()

    def run_baseline(self, spec, rc=0):
        path = os.path.join(self.root, "baseline.json")
        with open(path, "w") as f:
            json.dump(spec, f)
        r = subprocess.run([sys.executable, os.path.join(BIN, "ciscat-fleet.py"), "baseline",
                            "--file", path], env=self.env, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
        self.assertEqual(r.returncode, rc, r.stdout)
        return r.stdout

    def test_creates_writes_and_assigns_once(self):
        spec = {"groups": {"baseline-linux": {"agent_conf": CONF, "agents": ["web-01", "ghost"]}}}
        out = self.run_baseline(spec)
        self.assertIn("[baseline-linux] group created", out)
        self.assertIn("[baseline-linux] agent.conf written", out)
        self.assertIn("[baseline-linux] agent web-01 (001) added", out)
        self.assertIn("WARNING agent ghost not found", out)
        self.assertEqual(self.fake.confs["baseline-linux"], CONF)
        self.assertEqual(self.fake.agents["001"]["group"], ["default", "baseline-linux"])
        self.assertEqual(self.fake.agents["002"]["group"], ["default"])
        # idempotent
        self.assertIn("1 group(s), 0 change(s), 0 error(s)", self.run_baseline(spec))
        # a change made elsewhere is put back
        self.fake.confs["baseline-linux"] = "<agent_config>\n</agent_config>\n"
        self.assertIn("agent.conf written", self.run_baseline(spec))

    def test_refused_configuration_fails_the_run(self):
        bad = {"groups": {"baseline-x": {"agent_conf": "<agent_config><syscheck>", "agents": []}}}
        out = self.run_baseline(bad, rc=1)
        self.assertIn("[baseline-x] ERROR agent.conf refused", out)

    def test_invalid_files_are_refused_before_any_call(self):
        for spec in ({"groups": {"bad name": {"agent_conf": CONF}}},
                     {"groups": {"default": {"agent_conf": CONF}}},
                     {"groups": {"g": {"agent_conf": "no xml"}}},
                     {"groups": {"g": {"agent_conf": CONF, "agents": "web-01"}}},
                     {"nogroups": {}}):
            out = self.run_baseline(spec, rc=1)
            self.assertIn("baseline:", out)
        self.assertEqual(self.fake.calls, [])


if __name__ == "__main__":
    unittest.main()
