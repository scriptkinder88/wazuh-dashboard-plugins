"""packaging/build.py: the three release packages, complete and without licensed files."""
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
SHA = "a" * 64


class Packaging(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def build(self, *extra):
        out = os.path.join(self.d, "out")
        r = subprocess.run([sys.executable, BUILD, "--plugin", "plugin.zip", "--plugin-sha256",
                            SHA, "--out", out] + list(extra), stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)
        return out, sorted(os.listdir(out))

    def test_light_packages(self):
        out, names = self.build()
        self.assertEqual([n for n in names if n != "SHA256SUMS"], [
            "ciscat-agent-linux-2.3.0.tar.gz", "ciscat-agent-windows-2.3.0.zip",
            "ciscat-master-2.3.0.zip"])
        with zipfile.ZipFile(os.path.join(out, "ciscat-master-2.3.0.zip")) as z:
            setup = z.read("master/ciscat-master-setup.sh").decode()
        self.assertIn(SHA, setup)
        with zipfile.ZipFile(os.path.join(out, "ciscat-agent-windows-2.3.0.zip")) as z:
            ps1 = z.read("agent-windows/install-windows-agent.ps1")
        self.assertIn(b"\r\n", ps1)
        self.assertNotIn(b"Assessor/", b"".join(n.encode() for n in z.namelist()))

    def test_full_packages_leave_the_license_out(self):
        for os_name, cli in (("win", "Assessor-CLI.bat"), ("lin", "Assessor-CLI.sh")):
            for sub in ("license", "reports", "jre/bin"):
                os.makedirs(os.path.join(self.d, os_name, sub))
            for path in (cli, "license/license.xml", "reports/r.csv", "jre/bin/java"):
                with open(os.path.join(self.d, os_name, path), "w") as f:
                    f.write("x")
        out, names = self.build("--assessor-windows", os.path.join(self.d, "win"),
                                "--assessor-linux", os.path.join(self.d, "lin"),
                                "--assessor-version", "4.62.0")
        with tarfile.open(os.path.join(out, "ciscat-agent-linux-2.3.0-assessor-4.62.0.tar.gz")) as t:
            members = t.getnames()
        self.assertIn("agent-linux/Assessor/Assessor-CLI.sh", members)
        self.assertIn("agent-linux/ASSESSOR_VERSION", members)
        self.assertFalse([m for m in members if "/license" in m or "/reports" in m])
        with zipfile.ZipFile(os.path.join(out, "ciscat-agent-windows-2.3.0-assessor-4.62.0.zip")) as z:
            members = z.namelist()
        self.assertIn("agent-windows/Assessor/Assessor-CLI.bat", members)
        self.assertFalse([m for m in members if "/license" in m or "/reports" in m])


if __name__ == "__main__":
    unittest.main()
