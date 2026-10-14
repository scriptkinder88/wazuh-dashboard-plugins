"""packaging/kit/prod_bundle.py: the single bundle for a Wazuh master."""
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
BUILD = os.path.join(HERE, "..", "packaging", "build.py")
BUNDLE = os.path.join(HERE, "..", "packaging", "kit", "prod_bundle.py")
PLUGIN_SHA = "a" * 64


class ProdBundle(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.extras = os.path.join(self.d, "downloads")
        os.makedirs(self.extras)

    def download(self, name, windows):
        files = {"Assessor/Assessor-CLI.bat" if windows else "Assessor/Assessor-CLI.sh": "x",
                 "Assessor/jre/bin/java.exe" if windows else "Assessor/jre/bin/java": "x",
                 "Assessor/license/license.xml": "LIC",
                 "Assessor/benchmarks/CIS_Shared_Benchmark_v1.0.0-cpe-dictionary.xml": "same",
                 "Assessor/benchmarks/sub/CIS_{0}_Benchmark_v1.0.0-oval.xml".format(
                     "Win" if windows else "Lin"): "oval"}
        files["Assessor/benchmarks/CIS_{0}_Benchmark_v1.0.0-xccdf.xml".format(
            "Win" if windows else "Lin")] = "xccdf"
        path = os.path.join(self.extras, name)
        with zipfile.ZipFile(path, "w") as z:
            for n, c in files.items():
                z.writestr(n, c)
        return path

    def run_py(self, *args):
        return subprocess.run([sys.executable] + list(args), stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, universal_newlines=True)

    def packages(self, *extra):
        self.win = self.download("CIS-CAT-Assessor-Windows-jre-v4.67.0.zip", True)
        self.lin = self.download("CIS-CAT-Assessor-Linux-jre-v4.67.0.zip", False)
        self.release = os.path.join(self.d, "release")
        r = self.run_py(BUILD, "--plugin", "plugin.zip", "--plugin-sha256", PLUGIN_SHA, "--out",
                        self.release, "--assessor-windows", self.win, "--assessor-linux",
                        self.lin, *extra)
        self.assertEqual(r.returncode, 0, r.stdout)

    def bundle(self, plugin_sha=None):
        out = os.path.join(self.d, "ciscat-prod-2.3.1.tar.gz")
        return self.run_py(BUNDLE, "--windows", self.win, "--linux", self.lin, "--release",
                           self.release, "--extras", self.extras, "--version", "2.3.1",
                           "--plugin-sha256", plugin_sha or PLUGIN_SHA, "--out", out), out

    def test_everything_for_the_master_in_one_file(self):
        self.packages()
        plugin = b"plugin bytes"
        name = "wazuh-dashboard-plugins_wazuh_4.14.7-01_f7ccb4e.zip"
        with open(os.path.join(self.extras, name), "wb") as f:
            f.write(plugin)
        with open(os.path.join(self.extras, "license.xml"), "w") as f:
            f.write("<license/>")
        with open(os.path.join(self.extras, "ciscat-config-20261013.tgz"), "wb") as f:
            f.write(b"cfg")
        r, out = self.bundle(hashlib.sha256(plugin).hexdigest())
        self.assertEqual(r.returncode, 0, r.stdout)
        with tarfile.open(out) as t:
            members = {m.name: m for m in t.getmembers()}
            sums = t.extractfile("ciscat-prod-2.3.1/SHA256SUMS").read().decode()
            script = t.extractfile("ciscat-prod-2.3.1/install-prod.sh").read().decode()
            contents = {n: t.extractfile(m).read() for n, m in members.items() if m.isfile()}
        top = "ciscat-prod-2.3.1/"
        for n in ("install-prod.sh", "ciscat-master-2.3.1.zip", name, "license/license.xml",
                  "ciscat-config-20261013.tgz",
                  "benchmarks/CIS_Win_Benchmark_v1.0.0-xccdf.xml",
                  "benchmarks/CIS_Win_Benchmark_v1.0.0-oval.xml",
                  "benchmarks/CIS_Lin_Benchmark_v1.0.0-xccdf.xml",
                  "benchmarks/CIS_Lin_Benchmark_v1.0.0-oval.xml",
                  "benchmarks/CIS_Shared_Benchmark_v1.0.0-cpe-dictionary.xml",
                  "agents/ciscat-agent-linux-2.3.1-assessor-4.67.0.tar.gz",
                  "agents/ciscat-agent-windows-2.3.1-assessor-4.67.0.zip",
                  "agents/ciscat-e2e-linux.sh", "agents/ciscat-e2e-windows.ps1"):
            self.assertIn(top + n, members, n)
        self.assertEqual(members[top + "install-prod.sh"].mode, 0o755)
        self.assertEqual(members[top + "license/license.xml"].mode, 0o600)
        self.assertEqual(members[top.rstrip("/")].mode, 0o700)
        self.assertNotIn("@VERSION@", script)
        self.assertIn('VERSION=2.3.1', script)
        # every file of the bundle is in its SHA256SUMS
        listed = dict(line.split("  ", 1)[::-1] for line in sums.splitlines())
        for n, c in contents.items():
            rel = n[len(top):]
            if rel != "SHA256SUMS":
                self.assertEqual(listed.get(rel), hashlib.sha256(c).hexdigest(), rel)

    def test_a_plugin_of_another_build_or_a_pinned_key_is_refused(self):
        self.packages()
        with open(os.path.join(self.extras, "wazuh-dashboard-plugins_wazuh_4.14.7-01_f1ec8e4.zip"),
                  "wb") as f:
            f.write(b"other build")
        r, out = self.bundle()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("sha256 is not", r.stdout)
        os.remove(os.path.join(self.extras, "wazuh-dashboard-plugins_wazuh_4.14.7-01_f1ec8e4.zip"))
        keys = os.path.join(self.d, "keys")
        os.makedirs(keys)
        for n in ("ciscat-manifest.pub", "ciscat-manifest.pub.xml"):
            with open(os.path.join(keys, n), "w") as f:
                f.write("k")
        shutil.rmtree(self.release)
        self.packages("--master-keys", keys)
        r, out = self.bundle()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("pins a master key", r.stdout)


if __name__ == "__main__":
    unittest.main()
