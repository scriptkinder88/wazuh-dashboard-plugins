"""ciscat-bootstrap.sh installs the manifest's files only to the bridge's own places."""
import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "bin", "ciscat-bootstrap.sh")


class Bootstrap(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.shared = os.path.join(self.d, "shared")
        self.assessor = os.path.join(self.d, "Assessor")
        self.data = os.path.join(self.d, "data")
        self.ar_bin = os.path.join(self.d, "ar-bin")
        for p in (self.shared, self.assessor, self.ar_bin):
            os.makedirs(p)
        self.ar_log = os.path.join(self.d, "active-responses.log")
        open(self.ar_log, "w").close()
        self.env = dict(os.environ, CISCAT_AGENT_SHARED=self.shared, CISCAT_PATH=self.assessor,
                        CISCAT_DATA_DIR=self.data, CISCAT_AR_BIN=self.ar_bin,
                        CISCAT_AR_LOG=self.ar_log)
        self.lines = []

    def publish(self, name, dest, content=b"<x/>"):
        with open(os.path.join(self.shared, name), "wb") as f:
            f.write(content)
        self.lines.append("{0};{1};{2}".format(name, hashlib.sha256(content).hexdigest(), dest))

    def run_bootstrap(self, manifest=None):
        with open(os.path.join(self.shared, "ciscat-manifest.csv"), "w") as f:
            f.write(manifest if manifest is not None else
                    "# ciscat-manifest (test)\n# name;sha256;dest\n" + "\n".join(self.lines) + "\n")
        # as execd does: the alert as one JSON line on stdin
        r = subprocess.run(["sh", SCRIPT], env=self.env, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=30, text=True,
                           input='{"command":"add","parameters":{}}\n')
        self.assertEqual(r.stdout, "")  # under execd stdout is not a terminal: nothing on it
        with open(self.ar_log) as f:
            return r.returncode, f.read()

    def test_files_of_the_bridge_are_installed(self):
        bench = os.path.join(self.assessor, "benchmarks", "rhel7-custom-xccdf.xml")
        self.publish("rhel7-custom-xccdf.xml", bench)
        self.publish("refresh.conf", os.path.join(self.data, "refresh.conf"))
        self.publish("ciscat-refresh.sh", os.path.join(self.ar_bin, "ciscat-refresh.sh"), b"#!/bin/sh\n")
        rc, out = self.run_bootstrap()
        self.assertEqual(rc, 0, out)
        self.assertIn("installed=3 refused=0 missing=0", out)
        self.assertTrue(os.path.isfile(bench))
        self.assertEqual(os.stat(os.path.join(self.ar_bin, "ciscat-refresh.sh")).st_mode & 0o777, 0o750)

    def test_every_benchmark_manifest_is_installed(self):
        conf_d = os.path.join(self.data, "conf.d")
        for key in ("rhel7", "aks"):
            self.lines = []
            self.publish("ciscat-refresh-{0}.conf".format(key),
                         os.path.join(conf_d, key + ".conf"), key.encode())
            with open(os.path.join(self.shared, "ciscat-manifest-{0}.csv".format(key)), "w") as f:
                f.write("# ciscat-manifest ({0})\n# name;sha256;dest\n".format(key) +
                        "\n".join(self.lines) + "\n")
        # the group-wide manifest of older managers is not read next to the per-OS ones
        rc, out = self.run_bootstrap("# old\nmissing.xml;00;" +
                                     os.path.join(self.data, "x") + "\n")
        self.assertEqual(rc, 0, out)
        self.assertIn("installed=2 refused=0 missing=0", out)
        self.assertEqual(sorted(os.listdir(conf_d)), ["aks.conf", "rhel7.conf"])

    def test_manifest_is_read_from_the_shared_folder_only(self):
        os.makedirs(os.path.join(self.shared, "os-rhel7"))
        with open(os.path.join(self.shared, "os-rhel7", "ciscat-manifest.csv"), "w") as f:
            f.write("# ciscat-manifest\n")
        # as execd does: the alert as one JSON line on stdin
        r = subprocess.run(["sh", SCRIPT], env=self.env, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=30, text=True,
                           input='{"command":"add","parameters":{}}\n')
        self.assertEqual(r.returncode, 1)
        with open(self.ar_log) as f:
            self.assertIn("manifest not found in " + self.shared, f.read())

    def test_other_destinations_and_names_are_refused(self):
        outside = os.path.join(self.d, "etc", "cron.d", "evil")
        self.publish("evil", outside)
        self.publish("x.sh", os.path.join(self.ar_bin, "other.sh"))
        self.publish("y.xml", os.path.join(self.assessor, "benchmarks", "..", "..", "y.xml"))
        self.publish("z.xml", os.path.join(self.assessor, "benchmarks-other", "z.xml"))
        good = os.path.join(self.data, "refresh.conf")
        self.publish("refresh.conf", good)
        # a name that leaves the shared folder
        self.lines.append("../outside;{0};{1}".format("0" * 64, os.path.join(self.data, "o")))
        rc, out = self.run_bootstrap()
        self.assertEqual(rc, 2, out)
        self.assertIn("installed=1 refused=5 missing=0", out)
        self.assertIn("REFUSED (not a plain file name): ../outside", out)
        self.assertTrue(os.path.isfile(good))
        for p in (outside, os.path.join(self.ar_bin, "other.sh"), os.path.join(self.d, "y.xml"),
                  os.path.join(self.assessor, "benchmarks-other", "z.xml")):
            self.assertFalse(os.path.exists(p), p)


if __name__ == "__main__":
    unittest.main()
