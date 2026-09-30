"""ciscat-refresh.sh stops when CIS-CAT Pro is not installed on the agent."""
import os
import re
import socket
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "bin", "ciscat-refresh.sh")
RULES = os.path.join(HERE, "..", "rules", "ciscat_rules.xml")


class RefreshWithoutAssessor(unittest.TestCase):
    def test_stops_with_message_and_withdraws_previous_results(self):
        d = tempfile.mkdtemp()
        data = os.path.join(d, "data")
        cache = os.path.join(data, "reports-cache", "l1_server")
        os.makedirs(cache)
        with open(os.path.join(data, "refresh.conf"), "w") as f:
            f.write('BENCHMARK_FILE="x-xccdf.xml"\nPROFILE_LIST="l1_server|P"\nSPLAY_MAX_SEC="1800"\n')
        with open(os.path.join(cache, "results.txt"), "w") as f:
            f.write("1.1.1:pass\n")
        ar_log = os.path.join(d, "active-responses.log")
        env = dict(os.environ, CISCAT_PATH=os.path.join(d, "no-assessor"),
                   CISCAT_DATA_DIR=data, CISCAT_AR_LOG=ar_log)
        r = subprocess.run(["sh", SCRIPT], env=env, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=30)
        self.assertEqual(r.returncode, 1)
        with open(ar_log) as f:
            log = f.read()
        self.assertIn("CIS-CAT Pro not found on {}:".format(socket.gethostname()), log)
        self.assertNotIn("splay", log)  # stops before sleeping
        self.assertEqual(sorted(os.listdir(cache)), ["results.txt.stale"])
        # the manager rule matches the logged line
        with open(RULES) as f:
            match = re.search(r"<match>([^<]+)</match>", f.read()).group(1)
        self.assertIn(match, log)


if __name__ == "__main__":
    unittest.main()
