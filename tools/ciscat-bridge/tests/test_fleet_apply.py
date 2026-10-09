"""ciscat-fleet.py apply and trigger against the fake Wazuh API, with a small synthetic benchmark:
the combo groups it owns, the apply lock, missing benchmark files, API tokens and credentials."""
import fcntl
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "bin")
FLEET = os.path.join(BIN, "ciscat-fleet.py")
sys.path.insert(0, BIN)
sys.path.insert(0, HERE)
import ciscat_store as store  # noqa: E402
from fake_wazuh_api import FakeWazuh  # noqa: E402

PREFIX = "CIS_Test_Linux_Benchmark_v1.0.0"
BENCH = """<?xml version="1.0" encoding="UTF-8"?>
<xccdf:Benchmark xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2"
    id="xccdf_org.cisecurity.benchmarks_benchmark_Test">
  <xccdf:version>1.0.0</xccdf:version>
  <xccdf:Profile id="xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Server">
    <xccdf:title>Level 1 - Server</xccdf:title>
    <xccdf:select idref="xccdf_org.cisecurity.benchmarks_rule_1.1_One" selected="true"/>
    <xccdf:select idref="xccdf_org.cisecurity.benchmarks_rule_1.2_Two" selected="true"/>
  </xccdf:Profile>
  <xccdf:Group id="xccdf_org.cisecurity.benchmarks_group_1_Setup">
    <xccdf:title>Setup</xccdf:title>
    <xccdf:Rule id="xccdf_org.cisecurity.benchmarks_rule_1.1_One">
      <xccdf:title>One</xccdf:title><check system="oval"/>
    </xccdf:Rule>
    <xccdf:Rule id="xccdf_org.cisecurity.benchmarks_rule_1.2_Two">
      <xccdf:title>Two</xccdf:title><xccdf:check system="oval"/>
    </xccdf:Rule>
  </xccdf:Group>
</xccdf:Benchmark>
"""
COMPANIONS = ("-oval.xml", "-cpe-oval.xml", "-cpe-dictionary.xml")


def entry(**kw):
    e = {"active": True, "family": "linux", "group": "os-rhel7", "benchmark": PREFIX + "-xccdf.xml",
         "companion_prefix": PREFIX, "base": "rhel7-custom", "role": "Server",
         "profiles": [["l1_server", "L1"]], "policy_id": "cis_rhel7_tailored_l1_server",
         "policy_name": "Test", "flat_path": "/var/lib/x/results.txt",
         "ar_bootstrap": "!ciscat-bootstrap-linux0", "ar_refresh": "!ciscat-refresh-linux0"}
    e.update(kw)
    return e


class FleetApply(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.paths = {k: os.path.join(self.root, k) for k in
                      ("exclusions_dir", "benchmarks_dir", "shared_dir", "work_dir", "lists_dir",
                       "run_dir")}
        for d in self.paths.values():
            os.makedirs(d)
        with open(os.path.join(self.paths["benchmarks_dir"], PREFIX + "-xccdf.xml"), "w") as f:
            f.write(BENCH)
        self.etc = os.path.join(self.root, "etc")
        os.makedirs(self.etc)
        self.library({"rhel7": entry()})
        self.fake = FakeWazuh(self.paths["shared_dir"], {
            "001": {"name": "web-01", "status": "active", "group": ["os-rhel7"]},
            "002": {"name": "web-02", "status": "active", "group": ["os-rhel7",
                                                                     "ciscat-rhel7-handmade"]},
            "003": {"name": "web-03", "status": "disconnected", "group": ["os-rhel7"]},
        })
        self.addCleanup(lambda: self.fake.server.shutdown())
        self.env = dict(os.environ, CISCAT_ETC_DIR=self.etc,
                        CISCAT_PATHS_JSON=json.dumps(self.paths), CISCAT_API_URL=self.fake.serve(),
                        WAZUH_API_PASSWORD="x", CISCAT_AR_GAP="0")

    def library(self, lib):
        with open(os.path.join(self.etc, "os-library.json"), "w") as f:
            json.dump(lib, f)

    def companions(self):
        for suf in COMPANIONS:
            with open(os.path.join(self.paths["benchmarks_dir"], PREFIX + suf), "w") as f:
                f.write("<x/>")

    def fleet(self, *args, rc=0):
        r = subprocess.run([sys.executable, FLEET] + list(args), env=self.env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if rc is not None:
            self.assertEqual(r.returncode, rc, r.stdout)
        return r.stdout

    def status(self):
        return store.read_list(store.STATUS, self.paths["lists_dir"])[0]

    def test_sync_reports_an_unreadable_benchmark(self):
        with open(os.path.join(self.paths["benchmarks_dir"], PREFIX + "-xccdf.xml"), "w") as f:
            f.write("<xccdf:Benchmark")
        out = self.fleet("sync", rc=1)
        self.assertIn("[rhel7] ERROR: benchmark not readable", out)
        oskeys, _ = store.read_list(store.OSKEYS, self.paths["lists_dir"])
        self.assertFalse(oskeys["rhel7"]["available"])

    def test_sync_publishes_the_sheet_and_republishes_it_when_it_changes(self):
        self.fleet("sync")
        sheet, _ = store.read_list("ciscat-bench-rhel7", self.paths["lists_dir"])
        self.assertEqual((sheet["1.1"]["t"], sheet["1.1"]["m"], sheet["1.2"]["m"]), ("One", False, False))
        with open(os.path.join(self.paths["benchmarks_dir"], PREFIX + "-xccdf.xml"), "w") as f:
            f.write(BENCH.replace("<xccdf:title>One</xccdf:title>", "<xccdf:title>One &amp; more</xccdf:title>"))
        self.fleet("sync")
        sheet, _ = store.read_list("ciscat-bench-rhel7", self.paths["lists_dir"])
        self.assertEqual(sheet["1.1"]["t"], "One & more")

    def test_an_os_no_longer_applied_releases_its_combo_groups(self):
        # agent 004 was left in the combo groups of two OSes that are not applied any more:
        # one whose os- group is gone, one switched off in the library
        self.companions()
        self.library({"rhel7": entry(),
                      "aks": entry(group="os-aks", base="aks-custom", policy_id="cis_aks_l1"),
                      "win": entry(group="os-win", active=False, base="win-custom",
                                   policy_id="cis_win_l1")})
        self.fake.agents["004"] = {"name": "win-01", "status": "active",
                                   "group": ["ciscat-aks-base", "ciscat-win-0123456789",
                                             "ciscat-aks-handmade"]}
        self.fake.groups |= {"ciscat-aks-base", "ciscat-win-0123456789", "ciscat-aks-handmade"}
        out = self.fleet("plan")
        self.assertIn("would remove the groups ciscat-aks-base", out)
        self.assertIn("ciscat-aks-base", self.fake.agents["004"]["group"])
        self.fleet("apply")
        self.assertEqual(self.fake.agents["004"]["group"], ["ciscat-aks-handmade"])
        self.assertNotIn("ciscat-aks-base", self.fake.groups)
        self.assertNotIn("ciscat-win-0123456789", self.fake.groups)
        self.assertIn("ciscat-aks-handmade", self.fake.groups)
        self.assertIn("ciscat-rhel7-base", self.fake.groups)

    def test_missing_benchmark_files_fail_the_apply(self):
        out = self.fleet("apply", rc=1)
        self.assertIn("MISSING", out)
        st = self.status()["apply"]
        self.assertEqual(st["state"], "error")
        self.assertIn(PREFIX + "-oval.xml", " ".join(st["errors"]))
        self.companions()
        self.fleet("apply")
        self.assertEqual(self.status()["apply"]["state"], "ok")

    def test_apply_publishes_atomically_and_keeps_groups_it_does_not_own(self):
        self.companions()
        self.fleet("apply")
        # a group named like a combo but not made by the bridge keeps its agent and survives
        self.assertIn("ciscat-rhel7-handmade", self.fake.groups)
        self.assertIn("ciscat-rhel7-handmade", self.fake.agents["002"]["group"])
        self.assertIn("ciscat-rhel7-base", self.fake.agents["001"]["group"])
        os_dir = os.path.join(self.paths["shared_dir"], "os-rhel7")
        files = os.listdir(os_dir)
        self.assertFalse([f for f in files if f.startswith(".")], files)
        with open(os.path.join(os_dir, "ciscat-manifest.csv")) as f:
            manifest = f.read()
        for name in ("rhel7-custom-xccdf.xml", "refresh.conf", PREFIX + "-oval.xml"):
            self.assertIn(name + ";", manifest)
        with open(os.path.join(self.paths["shared_dir"], "ciscat-rhel7-base",
                               "cis_rhel7_tailored_l1_server.yml")) as f:
            policy = f.read()
        self.assertIn(r"r:^1\.1:pass$", policy)  # <check> without prefix: automated
        self.assertIn(r"r:^1\.2:pass$", policy)  # <xccdf:check>: automated too

    def test_a_second_apply_waits_for_the_first(self):
        self.companions()
        with open(os.path.join(self.paths["run_dir"], "apply.lock"), "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            p = subprocess.Popen([sys.executable, FLEET, "apply"], env=self.env,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            time.sleep(1.5)
            self.assertIsNone(p.poll())
            self.assertNotIn("apply", self.status())  # nothing written while it waits
        out, _ = p.communicate(timeout=60)
        self.assertEqual(p.returncode, 0, out)
        self.assertIn("another apply is running", out)
        self.assertEqual(self.status()["apply"]["state"], "ok")

    def test_trigger_renews_the_token_and_skips_disconnected_agents(self):
        self.env["CISCAT_TOKEN_MAX_AGE"] = "0"
        self.fleet("trigger", "--wave-size", "1", "--wave-pause", "0", "--job", "j1")
        auth = [c for c in self.fake.calls if c[1] == "/security/user/authenticate"]
        self.assertGreaterEqual(len(auth), 5)  # one per call once the token is "old"
        self.assertEqual(sorted(a for _, ids in self.fake.ar for a in ids),
                         ["001", "001", "002", "002"])
        st = self.status()["job-j1"]
        self.assertEqual((st["state"], st["sent"], st["skipped"]), ("ok", 2, ["003"]))

    def test_trigger_without_assessment_command_fails_cleanly(self):
        lib = entry()
        del lib["ar_refresh"]
        self.library({"rhel7": lib})
        out = self.fleet("trigger", "--job", "j2", rc=1)
        self.assertIn("no ar_bootstrap/ar_refresh/ar_assessment", out)
        self.assertEqual(self.fake.ar, [])
        self.assertEqual(self.status()["job-j2"]["failed"], 2)


class Credentials(unittest.TestCase):
    def run_plan(self, conf, env_password=None, args=()):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        fake = FakeWazuh(os.path.join(d, "shared"), {})
        fake.reject_auth = True
        url = fake.serve()
        try:
            etc = os.path.join(d, "etc")
            os.makedirs(etc)
            with open(os.path.join(etc, "ciscat-orchestrator.conf"), "w") as f:
                f.write(conf)
            with open(os.path.join(etc, "os-library.json"), "w") as f:
                json.dump({}, f)
            env = dict(os.environ, CISCAT_ETC_DIR=etc, CISCAT_API_URL=url,
                       CISCAT_PATHS_JSON=json.dumps({"lists_dir": d, "run_dir": d}))
            env.pop("WAZUH_API_PASSWORD", None)
            if env_password:
                env["WAZUH_API_PASSWORD"] = env_password
            return subprocess.run([sys.executable, FLEET, "plan"] + list(args), env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True).stdout
        finally:
            fake.server.shutdown()

    def test_conf_user_is_used_with_the_environment_password(self):
        out = self.run_plan("api_user=svc-ciscat\n", env_password="x")
        self.assertIn("for user 'svc-ciscat' (password from $WAZUH_API_PASSWORD)", out)

    def test_password_on_the_command_line_is_deprecated(self):
        out = self.run_plan("api_user=svc\n", args=("--password", "x"))
        self.assertIn("--password is visible in the process list and deprecated", out)

    def test_tls_context_and_owned_group_names(self):
        import importlib.util
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        os.environ["CISCAT_ETC_DIR"] = d
        os.environ["CISCAT_PATHS_JSON"] = json.dumps({"lists_dir": d, "run_dir": d,
                                                      "benchmarks_dir": d})
        try:
            with open(os.path.join(d, "os-library.json"), "w") as f:
                json.dump({}, f)
            spec = importlib.util.spec_from_file_location("ciscat_fleet", FLEET)
            fleet = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(fleet)
        finally:
            os.environ.pop("CISCAT_ETC_DIR")
            os.environ.pop("CISCAT_PATHS_JSON")
        self.assertEqual(fleet.ssl_context(None).verify_mode, ssl.CERT_NONE)
        ctx = fleet.ssl_context(ssl.get_default_verify_paths().cafile or None)
        if ssl.get_default_verify_paths().cafile:
            self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(ctx.check_hostname)
        self.assertTrue(fleet.is_combo_group("rhel7", "ciscat-rhel7-base"))
        self.assertTrue(fleet.is_combo_group("rhel7", "ciscat-rhel7-0123456789"))
        for g in ("ciscat-rhel7-handmade", "ciscat-rhel7-base-x", "ciscat-rhel7_v2-base",
                  "ciscat-rhel-base"):
            self.assertFalse(fleet.is_combo_group("rhel7", g), g)


if __name__ == "__main__":
    unittest.main()
