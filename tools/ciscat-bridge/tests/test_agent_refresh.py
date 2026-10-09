"""ciscat-refresh.sh on a fake Assessor: configuration, lock, flatten of the ARF report, and the
stop when CIS-CAT Pro is not installed on the agent."""
import fcntl
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "bin", "ciscat-refresh.sh")
RULES = os.path.join(HERE, "..", "rules", "ciscat_rules.xml")
CONF = 'BENCHMARK_FILE="x-xccdf.xml"\nPROFILE_LIST="l1_server|P"\nSPLAY_MAX_SEC="0"\n'
FAKE_ASSESSOR = """#!/bin/sh
mkdir -p reports
cp "$FAKE_ARF" reports/host-ARF.xml
"""


def rule_result(num, result, attrs=""):
    return ('<xccdf:rule-result {0}idref="xccdf_org.cisecurity.benchmarks_rule_{1}_Title"'
            ' time="t">\n  <xccdf:result>{2}</xccdf:result>\n</xccdf:rule-result>\n'
            .format(attrs, num, result))


def arf(*results):
    return "<arf>\n<xccdf:TestResult>\n" + "".join(results) + "</xccdf:TestResult>\n</arf>\n"


class Refresh(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.data = os.path.join(self.d, "data")
        self.cache = os.path.join(self.data, "reports-cache", "l1_server")
        os.makedirs(self.cache)
        self.assessor = os.path.join(self.d, "Assessor")
        os.makedirs(os.path.join(self.assessor, "benchmarks"))
        with open(os.path.join(self.assessor, "benchmarks", "x-xccdf.xml"), "w") as f:
            f.write("<x/>")
        cli = os.path.join(self.assessor, "Assessor-CLI.sh")
        with open(cli, "w") as f:
            f.write(FAKE_ASSESSOR)
        os.chmod(cli, 0o755)
        os.makedirs(os.path.join(self.assessor, "license"))
        with open(os.path.join(self.assessor, "license", "license.xml"), "w") as f:
            f.write("<license/>")
        self.arf = os.path.join(self.d, "report.xml")
        self.ar_log = os.path.join(self.d, "active-responses.log")
        self.env = dict(os.environ, CISCAT_PATH=self.assessor, CISCAT_DATA_DIR=self.data,
                        CISCAT_AR_LOG=self.ar_log, FAKE_ARF=self.arf)
        self.conf(CONF)

    def conf(self, text):
        with open(os.path.join(self.data, "refresh.conf"), "w") as f:
            f.write(text)

    def run_refresh(self, report=None):
        if report is not None:
            with open(self.arf, "w") as f:
                f.write(report)
        r = subprocess.run(["sh", SCRIPT, "--foreground"], env=self.env, cwd=self.d,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        with open(self.ar_log) as f:
            return r.returncode, f.read()

    def results(self):
        with open(os.path.join(self.cache, "results.txt")) as f:
            return f.read()

    def benchmarks(self, *keys, sent=None):
        """conf.d settings of the given OSes; `sent`: those whose group still sends them."""
        self.shared = os.path.join(self.d, "shared")
        os.makedirs(self.shared, exist_ok=True)
        os.makedirs(os.path.join(self.data, "conf.d"), exist_ok=True)
        self.env["CISCAT_AGENT_SHARED"] = self.shared
        for k in keys:
            with open(os.path.join(self.data, "conf.d", k + ".conf"), "w") as f:
                f.write(CONF)
        for k in (keys if sent is None else sent):
            open(os.path.join(self.shared, "ciscat-refresh-{0}.conf".format(k)), "w").close()

    def test_every_benchmark_of_the_agent_runs_with_its_own_results(self):
        self.benchmarks("rhel7", "aks")
        rc, log = self.run_refresh(arf(rule_result("1.1", "pass")))
        self.assertEqual(rc, 0, log)
        for k in ("aks", "rhel7"):
            self.assertIn("benchmark: " + k, log)
            with open(os.path.join(self.data, "reports-cache", k, "l1_server", "results.txt")) as f:
                self.assertEqual(f.read(), "1.1:pass\n")
        # the single refresh.conf of an older manager is not used next to conf.d
        self.assertFalse(os.path.exists(os.path.join(self.cache, "results.txt")))

    def test_a_benchmark_the_agent_left_is_removed_and_its_results_withdrawn(self):
        self.benchmarks("rhel7", "aks", sent=["rhel7"])
        old = os.path.join(self.data, "reports-cache", "aks", "l1_server")
        os.makedirs(old)
        with open(os.path.join(old, "results.txt"), "w") as f:
            f.write("1.1:pass\n")
        rc, log = self.run_refresh(arf(rule_result("1.1", "pass")))
        self.assertEqual(rc, 0, log)
        self.assertIn("benchmark aks no longer applies to this agent", log)
        self.assertEqual(os.listdir(os.path.join(self.data, "conf.d")), ["rhel7.conf"])
        self.assertEqual(os.listdir(old), ["results.txt.stale"])

    def test_under_execd_the_assessment_runs_detached_and_execd_is_released(self):
        # execd writes one JSON line on stdin, keeps the pipe open and waits for the script to
        # exit and close its stdout: the script must return at once, the assessment goes on
        with open(self.arf, "w") as f:
            f.write(arf(rule_result("1.1", "pass")))
        cli = os.path.join(self.assessor, "Assessor-CLI.sh")
        with open(cli, "w") as f:
            f.write("#!/bin/sh\nsleep 2\n" + FAKE_ASSESSOR.split("\n", 1)[1])
        p = subprocess.Popen(["sh", SCRIPT], env=self.env, cwd=self.d, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        p.stdin.write(b'{"command":"add","parameters":{}}\n')
        p.stdin.flush()
        start = time.monotonic()
        out = p.stdout.read()  # EOF only when no process holds the pipe any more
        p.wait(timeout=10)
        self.assertLess(time.monotonic() - start, 1.5, "execd would wait for the assessment")
        self.assertEqual((p.returncode, out), (0, b""))
        p.stdin.close()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not os.path.exists(os.path.join(self.cache, "results.txt")):
            time.sleep(0.2)
        self.assertEqual(self.results(), "1.1:pass\n")

    def test_without_license_it_stops_and_withdraws_the_results(self):
        with open(os.path.join(self.cache, "results.txt"), "w") as f:
            f.write("1.1:pass\n")
        os.remove(os.path.join(self.assessor, "license", "license.xml"))
        rc, log = self.run_refresh(arf(rule_result("1.1", "pass")))
        self.assertEqual(rc, 1)
        self.assertIn("no license", log)
        self.assertEqual(os.listdir(self.cache), ["results.txt.stale"])
        with open(RULES) as f:
            self.assertIn(re.search(r"<match>([^<]+)</match>", f.read()).group(1), log)
        # a license file named in the Assessor settings is found there
        os.makedirs(os.path.join(self.assessor, "config"))
        lic = os.path.join(self.d, "elsewhere.xml")
        with open(lic, "w") as f:
            f.write("<license/>")
        with open(os.path.join(self.assessor, "config", "assessor-cli.properties"), "w") as f:
            f.write("ciscat.license.filepath={0}\n".format(lic))
        rc, log = self.run_refresh()
        self.assertEqual(rc, 0, log)

    def test_flatten_pairs_each_rule_with_its_result(self):
        rc, log = self.run_refresh(arf(rule_result("1.1.2", "PASS"),
                                       rule_result("1.1.10", "fail", attrs='role="full" '),
                                       rule_result("2.1", "notapplicable")))
        self.assertEqual(rc, 0, log)
        self.assertEqual(self.results(), "1.1.10:fail\n1.1.2:pass\n2.1:notapplicable\n")

    def test_report_with_a_rule_result_without_result_is_refused(self):
        with open(os.path.join(self.cache, "results.txt"), "w") as f:
            f.write("9.9:pass\n")
        broken = rule_result("1.1", "pass").replace("<xccdf:result>pass</xccdf:result>", "")
        rc, log = self.run_refresh(arf(broken, rule_result("1.2", "fail")))
        self.assertEqual(rc, 1)
        self.assertIn("ARF report not understood", log)
        self.assertEqual(self.results(), "9.9:pass\n")  # previous results kept

    def test_report_without_results_does_not_publish_an_empty_file(self):
        rc, log = self.run_refresh(arf())
        self.assertEqual(rc, 1)
        self.assertIn("flatten produced 0 lines", log)
        self.assertFalse(os.path.exists(os.path.join(self.cache, "results.txt")))
        self.assertEqual([f for f in os.listdir(self.cache) if f.startswith(".")], [])

    def test_configuration_is_read_as_data(self):
        marker = os.path.join(self.d, "ran")
        for bad in ('SPLAY_MAX_SEC=$(touch {0})\n', 'PROFILE_LIST="a|b"; touch {0}\n',
                    'BENCHMARK_FILE="../../{0}"\n', 'SPLAY_MAX_SEC="`touch {0}`"\n'):
            self.conf(CONF + bad.format(marker))
            rc, log = self.run_refresh(arf(rule_result("1.1", "pass")))
            self.assertEqual(rc, 1, bad)
            self.assertIn("refresh.conf:", log)
            self.assertFalse(os.path.exists(marker), bad)
        self.conf(CONF + 'NEW_SETTING="1"\n')
        rc, log = self.run_refresh(arf(rule_result("1.1", "pass")))
        self.assertEqual(rc, 0, log)
        self.assertIn("unknown key ignored: NEW_SETTING", log)

    def test_only_the_newest_run_logs_are_kept(self):
        logs = os.path.join(self.data, "logs")
        os.makedirs(logs)
        for n in range(40):
            p = os.path.join(logs, "refresh_20260101_0000{0:02d}.log".format(n))
            with open(p, "w") as f:
                f.write("old\n")
            os.utime(p, (1767225600 + n, 1767225600 + n))
        rc, log = self.run_refresh(arf(rule_result("1.1", "pass")))
        self.assertEqual(rc, 0, log)
        left = sorted(os.listdir(logs))
        self.assertEqual(len(left), 30)
        self.assertNotIn("refresh_20260101_000010.log", left)  # the oldest went
        self.assertIn("refresh_20260101_000039.log", left)

    @unittest.skipUnless(shutil.which("flock"), "flock(1) not installed")
    def test_one_assessment_at_a_time(self):
        with open(os.path.join(self.data, "refresh.lock"), "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            rc, log = self.run_refresh(arf(rule_result("1.1", "pass")))
        self.assertEqual(rc, 1)
        self.assertIn("another CIS-CAT assessment is running", log)
        self.assertFalse(os.path.exists(os.path.join(self.cache, "results.txt")))


class RefreshWithoutAssessor(unittest.TestCase):
    def test_stops_with_message_and_withdraws_previous_results(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
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
        # the assessment as the detached run started under execd does it
        r = subprocess.run(["sh", SCRIPT, "--foreground"], env=env, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, timeout=30)
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
