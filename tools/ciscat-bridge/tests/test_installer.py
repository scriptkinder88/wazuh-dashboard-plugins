"""The self-contained installer, run for real against a fake root (master role).

Starts from a v1 layout (ciscat-fleet.py with an OS_LIBRARY literal, exclusions CSVs, the old
orchestrator cron in root's crontab and /etc/cron.d) and checks install, idempotency and rollback.
"""
import glob
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "installer"))
sys.path.insert(0, os.path.join(HERE, "..", "bin"))
sys.path.insert(0, HERE)
import build  # noqa: E402
import ciscat_store as store  # noqa: E402

V1_FLEET = '''#!/usr/bin/env python3
OS_LIBRARY = {
    "rhel7": {"active": True, "family": "linux", "group": "os-rhel7", "profiles": [("l1_server", "L1")]},
    "debian12": {"active": False, "family": "linux", "group": "os-debian12", "profiles": [("l1_server", "L1")]},
}
'''
OLD_CRON = "0 22-23,0-5 * * *  root  /opt/ciscat/bin/ciscat-orchestrator.sh >/dev/null 2>&1\n"


def plugin_zip(path):
    """A minimal archive with the layout the plugin tool expects; returns its SHA-256."""
    import hashlib
    import zipfile
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("opensearch-dashboards/wazuh/package.json", '{"version": "new"}')
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class Installer(unittest.TestCase):
    def setUp(self):
        self.out = tempfile.mkdtemp()
        self.script = build.build(self.out)
        self.root = tempfile.mkdtemp()
        r = self.root
        for d in ("var/ossec/bin", "var/ossec/etc/rules", "var/ossec/etc/lists", "opt/ciscat/bin",
                  "opt/ciscat/etc", "opt/ciscat/tailoring/exclusions", "etc/cron.d"):
            os.makedirs(os.path.join(r, d))
        open(os.path.join(r, "var/ossec/bin/wazuh-analysisd"), "w").close()
        with open(os.path.join(r, "var/ossec/etc/ossec.conf"), "w") as f:
            f.write("<ossec_config><cluster><node_type>master</node_type><disabled>no</disabled>"
                    "</cluster></ossec_config>")
        with open(os.path.join(r, "opt/ciscat/bin/ciscat-fleet.py"), "w") as f:
            f.write(V1_FLEET)
        with open(os.path.join(r, "opt/ciscat/tailoring/exclusions/rhel7.csv"), "w") as f:
            f.write("# os-key: rhel7\nscope,scope_value,level,role,rule\n"
                    "os,rhel7,L1,Server,1.1.1.1\nos,rhel7,L1,Server,1.1.1.2\n")
        with open(os.path.join(r, "etc/cron.d/ciscat-orchestrator"), "w") as f:
            f.write("# comment\n" + OLD_CRON)
        with open(os.path.join(r, "opt/ciscat/etc/ciscat-orchestrator.conf"), "w") as f:
            f.write("api_user=wazuh\napi_pass_file=/opt/ciscat/etc/.ciscat_api_pass\n")
        pw = os.path.join(r, "opt/ciscat/etc/.ciscat_api_pass")
        with open(pw, "w") as f:
            f.write("secret\n")
        os.chmod(pw, 0o644)
        self.crontab = os.path.join(r, "crontab.txt")
        with open(self.crontab, "w") as f:
            f.write("MAILTO=root\n0 22-23,0-5 * * *  root  /var/ossec/etc/ciscat-orchestrator.sh\n")
        self.env = dict(os.environ, CISCAT_INSTALL_ROOT=r, CISCAT_CRONTAB_FILE=self.crontab,
                        CISCAT_INSTALL_SKIP_FLEET="1")

    def install(self, *args):
        p = subprocess.run(["sh", self.script] + list(args), env=self.env, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
        self.assertEqual(p.returncode, 0, p.stdout)
        return p.stdout

    def path(self, rel):
        return os.path.join(self.root, rel)

    def test_every_master_script_is_shipped(self):
        import ciscat_install
        bin_dir = os.path.join(HERE, "..", "bin")
        scripts = {f for f in os.listdir(bin_dir) if f.endswith((".py", ".sh"))}
        self.assertEqual(scripts - set(ciscat_install.MANAGED_BIN), set())

    def test_install_idempotency_and_rollback(self):
        out = self.install()
        # site OS table taken from the v1 fleet, flags kept
        with open(self.path("opt/ciscat/etc/os-library.json")) as f:
            lib = json.load(f)
        self.assertEqual({k: v["active"] for k, v in lib.items()}, {"rhel7": True, "debian12": False})
        self.assertEqual(lib["rhel7"]["profiles"], [["l1_server", "L1"]])
        # scripts, agent scripts, rule, version
        for rel in ("opt/ciscat/bin/ciscat-scheduler.py", "opt/ciscat/bin/maps/ciscat-profiles.json",
                    "opt/ciscat/agent/active-response/ciscat-assessment.ps1",
                    "var/ossec/etc/rules/ciscat_rules.xml"):
            self.assertTrue(os.path.exists(self.path(rel)), rel)
        with open(self.path("opt/ciscat/bin/ciscat-fleet.py")) as f:
            self.assertIn("load_os_library", f.read())
        # exclusions migrated to the dashboard list
        recs, errors = store.read_list(store.EXCLUSIONS, self.path("var/ossec/etc/lists"))
        valid, verrors = store.validate_exclusions(recs)
        self.assertEqual((len(valid), errors, verrors), (2, [], []))
        # old orchestrator cron disabled in both places, scheduler cron installed
        with open(self.crontab) as f:
            self.assertIn("# disabled by ciscat-bridge", f.read())
        with open(self.path("etc/cron.d/ciscat-orchestrator")) as f:
            self.assertTrue(all(l.startswith("#") for l in f if l.strip()))
        with open(self.path("etc/cron.d/ciscat-scheduler")) as f:
            self.assertIn("ciscat-scheduler.py", f.read())
        self.assertEqual(oct(os.stat(self.path("opt/ciscat/etc/.ciscat_api_pass")).st_mode & 0o777),
                         "0o600")
        self.assertIn("Nothing applied to the agents", out)
        (backup,) = glob.glob(self.path("opt/ciscat/backup/*.tgz"))

        # second run: nothing to update, site configuration and list untouched
        with open(self.path("opt/ciscat/etc/os-library.json"), "w") as f:
            json.dump(dict(lib, debian12=dict(lib["debian12"], active=True)), f)
        with open(self.path("var/ossec/etc/lists/ciscat-exclusions")) as f:
            before = f.read()
        out2 = self.install()
        self.assertIn("files updated: none", out2)
        self.assertIn("os-library.json kept", out2)
        self.assertIn("list already present", out2)
        with open(self.path("var/ossec/etc/lists/ciscat-exclusions")) as f:
            self.assertEqual(f.read(), before)
        self.assertEqual(len(glob.glob(self.path("opt/ciscat/backup/*.tgz"))), 2)
        with open(self.path("opt/ciscat/etc/os-library.json")) as f:
            self.assertTrue(json.load(f)["debian12"]["active"])

        # rollback to the state before the first install
        with tarfile.open(backup) as tar:
            self.assertIn("crontab-root.txt", tar.getnames())
        self.install("--rollback", backup)
        with open(self.path("opt/ciscat/bin/ciscat-fleet.py")) as f:
            self.assertEqual(f.read(), V1_FLEET)
        self.assertFalse(os.path.exists(self.path("etc/cron.d/ciscat-scheduler")))
        self.assertFalse(os.path.exists(self.path("var/ossec/etc/rules/ciscat_rules.xml")))
        with open(self.crontab) as f:
            self.assertNotIn("disabled by ciscat-bridge", f.read())
        with open(self.path("etc/cron.d/ciscat-orchestrator")) as f:
            self.assertIn(OLD_CRON, f.read())

    def test_refuses_a_worker_and_a_damaged_script(self):
        with open(self.path("var/ossec/etc/ossec.conf"), "w") as f:
            f.write("<ossec_config><cluster><node_type>worker</node_type><disabled>no</disabled>"
                    "</cluster></ossec_config>")
        p = subprocess.run(["sh", self.script], env=self.env, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("WORKER", p.stdout)
        # a copy that lost a character in the payload changes nothing
        with open(self.script) as f:
            text = f.read()
        head, _, body = text.partition("__CISCAT_PAYLOAD_BELOW__\n")
        damaged = os.path.join(self.out, "damaged.sh")
        with open(damaged, "w") as f:
            f.write(head + "__CISCAT_PAYLOAD_BELOW__\n" + body[:100] + body[101:])
        p = subprocess.run(["sh", damaged], env=self.env, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertFalse(os.path.exists(self.path("opt/ciscat/bin/ciscat-scheduler.py")))

    def test_rule_takes_the_first_free_id_and_keeps_it(self):
        with open(self.path("var/ossec/etc/rules/local_rules.xml"), "w") as f:
            f.write('<group name="local,"><rule id="100950" level="3"><match>x</match></rule>'
                    '<rule id="100951" level="3" frequency="2"><match>y</match></rule></group>')
        out = self.install()
        self.assertIn("manager rule 100952 installed", out)
        with open(self.path("var/ossec/etc/rules/ciscat_rules.xml")) as f:
            self.assertIn('<rule id="100952" level="7">', f.read())
        # a later clash-free run keeps 100952 and reports nothing to change
        self.assertNotIn("manager rule", self.install())


    def test_dashboard_plugin_is_installed_only_with_the_right_checksum(self):
        os.remove(self.path("var/ossec/bin/wazuh-analysisd"))  # dashboard-only host
        tool = self.path("usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin")
        os.makedirs(os.path.dirname(tool))
        calls = self.path("plugin-calls.txt")
        with open(tool, "w") as f:
            f.write('#!/bin/sh\necho "$@" >> {0}\n'.format(calls))
        os.chmod(tool, 0o755)
        zip_path = self.path("wazuh-4.14.10.zip")
        good = plugin_zip(zip_path)
        p = subprocess.run(["sh", self.script, "--plugin-file", zip_path, "--plugin-sha256", "0" * 64],
                           env=self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("checksum mismatch", p.stdout)
        self.assertFalse(os.path.exists(calls))
        out = self.install("--plugin-file", zip_path, "--plugin-sha256", good)
        with open(calls) as f:
            got = f.read().splitlines()
        self.assertEqual(got[0], "remove wazuh")
        self.assertRegex(got[1], r"^install file:///.*/ciscat-plugin-[^/]+/wazuh-plugin\.zip$")
        self.assertNotIn("Master:", out)
        self.assertIn("restart wazuh-dashboard to load it", out)

    def test_github_artifact_wrapper_is_opened(self):
        import hashlib
        import io
        import zipfile
        os.remove(self.path("var/ossec/bin/wazuh-analysisd"))
        tool = self.path("usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin")
        os.makedirs(os.path.dirname(tool))
        seen = self.path("seen.txt")
        # the fake tool records what the archive it receives contains
        with open(tool, "w") as f:
            f.write('#!/bin/sh\n[ "$1" = install ] && python3 -c "import sys,zipfile;'
                    'print(zipfile.ZipFile(sys.argv[1][7:]).namelist())" "$2" > {0}\nexit 0\n'.format(seen))
        os.chmod(tool, 0o755)
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr("opensearch-dashboards/wazuh/package.json", "{}")
        outer = self.path("artifact.zip")
        with zipfile.ZipFile(outer, "w") as z:
            z.writestr("wazuh-4.14.10-00.zip", inner.getvalue())
        with open(outer, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        out = self.install("--plugin-file", outer, "--plugin-sha256", digest)
        self.assertIn("taken from the wrapper archive", out)
        with open(seen) as f:
            self.assertIn("opensearch-dashboards/wazuh/package.json", f.read())

    def test_failed_plugin_install_restores_the_previous_plugin(self):
        os.remove(self.path("var/ossec/bin/wazuh-analysisd"))
        tool = self.path("usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin")
        os.makedirs(os.path.dirname(tool))
        plugin = self.path("usr/share/wazuh-dashboard/plugins/wazuh")
        os.makedirs(plugin)
        with open(os.path.join(plugin, "package.json"), "w") as f:
            f.write('{"version": "old"}')
        # remove works, install fails (as with an unreadable zip)
        with open(tool, "w") as f:
            f.write('#!/bin/sh\nif [ "$1" = remove ]; then rm -rf "{0}"; exit 0; fi\n'
                    'echo "EACCES: permission denied"; exit 70\n'.format(plugin))
        os.chmod(tool, 0o755)
        zip_path = self.path("p.zip")
        digest = plugin_zip(zip_path)
        p = subprocess.run(["sh", self.script, "--plugin-file", zip_path, "--plugin-sha256",
                            digest], env=self.env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("previous plugin restored", p.stdout)
        with open(os.path.join(plugin, "package.json")) as f:
            self.assertIn("old", f.read())


class InstallerV5(unittest.TestCase):
    """Wazuh 5.0 master: indexer store, Active Response channels and monitors, no XML rule."""

    def setUp(self):
        from fake_indexer import FakeIndexer
        self.out = tempfile.mkdtemp()
        self.script = build.build(self.out)
        self.root = r = tempfile.mkdtemp()
        for d in ("var/wazuh-manager/etc/shared", "opt/ciscat/etc", "opt/ciscat/tailoring/exclusions",
                  "etc/cron.d", "secrets"):
            os.makedirs(os.path.join(r, d))
        self.conf = os.path.join(r, "var/wazuh-manager/etc/wazuh-manager.conf")
        with open(self.conf, "w") as f:
            f.write("<wazuh_config><cluster><node_type>master</node_type></cluster></wazuh_config>")
        with open(os.path.join(r, "opt/ciscat/tailoring/exclusions/rhel7.csv"), "w") as f:
            f.write("scope,scope_value,level,role,rule\nos,rhel7,L1,Server,1.1.1.1\n")
        with open(os.path.join(r, "opt/ciscat/etc/ciscat-orchestrator.conf"), "w") as f:
            f.write("api_user=wazuh\napi_pass_file=/opt/ciscat/etc/.ciscat_api_pass\n")
        with open(os.path.join(r, "opt/ciscat/etc/.ciscat_api_pass"), "w") as f:
            f.write("secret\n")
        self.pw = os.path.join(r, "secrets", "indexer-password")
        with open(self.pw, "w") as f:
            f.write("s3cret\n")
        self.fake = FakeIndexer()
        self.url = self.fake.serve()
        self.addCleanup(self.fake.stop)
        self.env = dict(os.environ, CISCAT_INSTALL_ROOT=r, CISCAT_INSTALL_SKIP_FLEET="1",
                        CISCAT_CRONTAB_FILE=os.path.join(r, "crontab.txt"))
        self.env.pop("CISCAT_PLATFORM", None)
        self.env.pop("CISCAT_INDEXER_CONF", None)

    def run_script(self, *args):
        return subprocess.run(["sh", self.script] + list(args), env=self.env, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True)

    def install(self, *args):
        p = self.run_script(*args)
        self.assertEqual(p.returncode, 0, p.stdout)
        return p.stdout

    def path(self, rel):
        return os.path.join(self.root, rel)

    def test_install_and_idempotency(self):
        out = self.install("--indexer-url", self.url, "--indexer-user", "ciscat",
                           "--indexer-password-file", self.pw)
        self.assertIn("(Wazuh 5.0)", out)
        self.assertNotIn("s3cret", out)
        with open(self.path("opt/ciscat/etc/indexer.json")) as f:
            conf = json.load(f)
        self.assertEqual(conf, {"url": self.url, "user": "ciscat",
                                "password_file": self.path("opt/ciscat/etc/indexer.pass")})
        for rel in ("opt/ciscat/etc/indexer.json", "opt/ciscat/etc/indexer.pass"):
            self.assertEqual(oct(os.stat(self.path(rel)).st_mode & 0o777), "0o600", rel)
        with open(self.path("opt/ciscat/etc/indexer.pass")) as f:
            self.assertEqual(f.read(), "s3cret\n")
        # store index, migrated exclusions, channels and monitors
        self.assertIn("wz-dashboard-store-ciscat", self.fake.indices)
        doc = self.fake.doc("wz-dashboard-store-ciscat", "ciscat-exclusions")
        valid, errors = store.validate_exclusions(doc["data"]["records"])
        self.assertEqual((len(valid), errors), (1, []))
        self.assertEqual(sorted(c["name"] for c in self.fake.channels.values()),
                         ["ciscat-assessment-windows", "ciscat-bootstrap-linux",
                          "ciscat-bootstrap-windows", "ciscat-refresh-linux"])
        self.assertEqual(sorted(m["name"] for m in self.fake.monitors.values()),
                         sorted(c["name"] for c in self.fake.channels.values()))
        self.assertEqual({c["name"]: c["active_response"]["executable"]
                          for c in self.fake.channels.values()},
                         {"ciscat-bootstrap-linux": "ciscat-bootstrap.sh",
                          "ciscat-refresh-linux": "ciscat-refresh.sh",
                          "ciscat-bootstrap-windows": "ciscat-bootstrap.cmd",
                          "ciscat-assessment-windows": "ciscat-assessment.cmd"})
        # no XML rule, no CDB list, no ruleset test: the Sigma rule waits for import
        self.assertFalse(os.path.exists(self.path("var/ossec")))
        self.assertFalse(os.path.exists(self.path("var/wazuh-manager/etc/rules")))
        self.assertIn("/opt/ciscat/rules/ciscat-not-found.sigma.yml", out)
        self.assertTrue(os.path.isfile(self.path("opt/ciscat/rules/ciscat-not-found.sigma.yml")))
        self.assertIn("ciscat_platform.py", os.listdir(self.path("opt/ciscat/bin")))
        (backup,) = glob.glob(self.path("opt/ciscat/backup/*.tgz"))

        # second run, no option: everything kept, nothing written to the indexer
        writes = len(self.fake.writes())
        out2 = self.install()
        self.assertIn("files updated: none", out2)
        self.assertIn("indexer configuration kept", out2)
        self.assertIn("list already present", out2)
        self.assertEqual(out2.count("unchanged"), 8, out2)
        self.assertEqual(len(self.fake.writes()), writes + 1)  # the monitor search
        self.assertEqual((len(self.fake.channels), len(self.fake.monitors)), (4, 4))

        # rollback keeps the indexer side
        out3 = self.install("--rollback", backup)
        self.assertIn("left as they are", out3)
        self.assertFalse(os.path.exists(self.path("opt/ciscat/rules")))

    def test_refuses_a_worker_and_a_missing_indexer_config(self):
        p = self.run_script()
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("--indexer-url", p.stdout)
        self.assertEqual(self.fake.calls, [])
        with open(self.conf, "w") as f:
            f.write("<wazuh_config><cluster><node_type>worker</node_type></cluster></wazuh_config>")
        p = self.run_script("--indexer-url", self.url, "--indexer-user", "ciscat",
                            "--indexer-password-file", self.pw)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("WORKER", p.stdout)
        self.assertFalse(os.path.exists(self.path("opt/ciscat/bin/ciscat-scheduler.py")))

    def test_wrong_indexer_password_stops_without_showing_it(self):
        with open(self.pw, "w") as f:
            f.write("not-the-password\n")
        p = self.run_script("--indexer-url", self.url, "--indexer-user", "ciscat",
                            "--indexer-password-file", self.pw)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("HTTP 401", p.stdout)
        self.assertNotIn("not-the-password", p.stdout)


if __name__ == "__main__":
    unittest.main()
