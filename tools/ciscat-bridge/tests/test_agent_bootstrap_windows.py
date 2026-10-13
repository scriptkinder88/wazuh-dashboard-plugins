"""ciscat-bootstrap.ps1: the Assessor of a final agent package is checked once, before anything
runs (run with PowerShell 7 where it is installed; icacls is replaced by a stub)."""
import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "agent", "active-response", "ciscat-bootstrap.ps1")
PWSH = shutil.which("pwsh") or os.environ.get("CISCAT_PWSH")


@unittest.skipUnless(PWSH and os.path.isfile(PWSH), "PowerShell 7 (pwsh) not installed")
class WindowsAssessorCheck(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.root = os.path.join(self.d, "CIS")
        self.assessor = os.path.join(self.root, "Assessor")
        self.bin = os.path.join(self.d, "bin")
        self.shared = os.path.join(self.d, "shared")
        stub = os.path.join(self.d, "stub")
        for p in (self.assessor, self.bin, self.shared, stub):
            os.makedirs(p)
        shutil.copy(SCRIPT, self.bin)
        with open(os.path.join(stub, "icacls.exe"), "w") as f:
            f.write("#!/bin/sh\necho \"$@\" >> \"$ICACLS_LOG\"\n")
        os.chmod(os.path.join(stub, "icacls.exe"), 0o755)
        self.log = os.path.join(self.d, "active-responses.log")
        open(self.log, "w").close()
        self.env = dict(os.environ, PATH=stub + os.pathsep + os.environ["PATH"],
                        ICACLS_LOG=os.path.join(self.d, "icacls.log"))

    def package(self, files):
        lines = ["# CIS-CAT Pro Assessor 4.67.0: files of the package (sha256  path)"]
        for rel, content in files.items():
            path = os.path.join(self.assessor, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(content)
            lines.append("{0}  {1}".format(hashlib.sha256(content).hexdigest(), rel))
        with open(os.path.join(self.bin, "ciscat-assessor.sha256"), "w") as f:
            f.write("\r\n".join(lines) + "\r\n")

    def run_bootstrap(self):
        r = subprocess.run([PWSH, "-NoProfile", "-File",
                            os.path.join(self.bin, "ciscat-bootstrap.ps1"), "-Root", self.root,
                            "-SharedDir", self.shared, "-LogFile", self.log], env=self.env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True, timeout=120)
        with open(self.log) as f:
            return r.returncode, f.read()

    def test_checked_once_and_files_of_an_earlier_assessor_moved_aside(self):
        self.package({"Assessor-CLI.bat": b"@echo off\r\n", "lib/a 4.67.jar": b"new"})
        for rel in ("lib/a-4.63.jar", "license/license.xml", "benchmarks/b-xccdf.xml",
                    "config/assessor-cli.properties"):
            os.makedirs(os.path.join(self.assessor, os.path.dirname(rel)), exist_ok=True)
            with open(os.path.join(self.assessor, rel), "w") as f:
                f.write("x")
        rc, out = self.run_bootstrap()
        self.assertIn("Assessor checked against the agent package: 2 file(s) OK", out)
        self.assertIn("moved 1 file(s) of an earlier Assessor", out)
        # then the run goes on (to the master's key, missing here)
        self.assertIn("public key", out)
        self.assertFalse(os.path.exists(os.path.join(self.assessor, "lib", "a-4.63.jar")))
        for rel in ("license/license.xml", "benchmarks/b-xccdf.xml",
                    "config/assessor-cli.properties", "lib/a 4.67.jar"):
            self.assertTrue(os.path.isfile(os.path.join(self.assessor, rel)), rel)
        with open(os.path.join(self.d, "icacls.log")) as f:
            icacls = f.read()
        self.assertIn("/inheritance:r /grant:r *S-1-5-18:(OI)(CI)F", icacls)
        open(self.log, "w").close()
        rc, out = self.run_bootstrap()
        self.assertNotIn("Assessor checked", out)

    def test_an_assessor_that_differs_stops_the_run(self):
        self.package({"Assessor-CLI.bat": b"@echo off\r\n", "lib/a.jar": b"a"})
        with open(os.path.join(self.assessor, "lib", "a.jar"), "wb") as f:
            f.write(b"changed")
        rc, out = self.run_bootstrap()
        self.assertEqual(rc, 3)
        self.assertIn("ciscat-bootstrap: REFUSED (Assessor file differs from the package): lib/a.jar",
                      out)
        self.assertNotIn("public key", out)
        self.assertFalse(os.path.exists(os.path.join(self.root, "assessor-checked")))


if __name__ == "__main__":
    unittest.main()
