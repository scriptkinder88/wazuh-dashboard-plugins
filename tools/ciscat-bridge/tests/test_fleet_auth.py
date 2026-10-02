"""A wrong API password gives an actionable message, not a traceback."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fake_wazuh_api import FakeWazuh  # noqa: E402


class FleetAuth(unittest.TestCase):
    def test_wrong_password_names_its_source(self):
        d = tempfile.mkdtemp()
        fake = FakeWazuh(os.path.join(d, "shared"), {})
        fake.reject_auth = True
        url = fake.serve()
        try:
            etc = os.path.join(d, "etc")
            os.makedirs(etc)
            pw = os.path.join(etc, ".pass")
            with open(pw, "w") as f:
                f.write("wrong\n")
            os.chmod(pw, 0o600)
            with open(os.path.join(etc, "ciscat-orchestrator.conf"), "w") as f:
                f.write("api_user=wazuh\napi_pass_file={0}\n".format(pw))
            with open(os.path.join(etc, "os-library.json"), "w") as f:
                json.dump({}, f)
            env = dict(os.environ, CISCAT_ETC_DIR=etc, CISCAT_API_URL=url,
                       CISCAT_PATHS_JSON=json.dumps({"lists_dir": d, "run_dir": d}))
            env.pop("WAZUH_API_PASSWORD", None)
            r = subprocess.run([sys.executable, os.path.join(HERE, "..", "bin", "ciscat-fleet.py"), "plan"],
                               env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        finally:
            fake.server.shutdown()
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("Traceback", r.stdout)
        self.assertIn("authentication failed for user 'wazuh' (password from {0})".format(pw), r.stdout)


if __name__ == "__main__":
    unittest.main()
