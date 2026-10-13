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

    def run_build(self, *extra):
        out = os.path.join(self.d, "out")
        r = subprocess.run([sys.executable, BUILD, "--plugin", "plugin.zip", "--plugin-sha256",
                            SHA, "--out", out] + list(extra), stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, universal_newlines=True)
        return r, out

    def build(self, *extra):
        r, out = self.run_build(*extra)
        self.assertEqual(r.returncode, 0, r.stdout)
        return out, sorted(os.listdir(out))

    def download(self, name, windows, extra=(), wrap="Assessor", modes=False):
        """A CIS-CAT Pro download as CIS ships it: Assessor/ with license and benchmarks."""
        files = ["Assessor-CLI.bat" if windows else "Assessor-CLI.sh", "lib/assessor.jar",
                 "config/assessor-cli.properties", "license/license.xml",
                 "benchmarks/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v4.0.0-xccdf.xml",
                 "benchmarks/CIS_Microsoft_Windows_Server_2025_Benchmark_v1.0.0-xccdf.xml",
                 "jre/bin/java.exe" if windows else "jre/bin/java", "jre/legal/LICENSE",
                 "reports/old.html"] + list(extra)
        if not windows:
            files.append("jre/lib/jspawnhelper")
        path = os.path.join(self.d, name)
        with zipfile.ZipFile(path, "w") as z:
            for f in files:
                info = zipfile.ZipInfo((wrap + "/" if wrap else "") + f)
                # made on Windows: no unix mode, no exec bit
                info.external_attr = (0o100755 << 16) if modes else 0
                z.writestr(info, "x")
        return path

    def test_light_packages(self):
        out, names = self.build()
        self.assertEqual([n for n in names if n != "SHA256SUMS"], [
            "ciscat-agent-linux-2.3.1.tar.gz", "ciscat-agent-windows-2.3.1.zip",
            "ciscat-master-2.3.1.zip"])
        with zipfile.ZipFile(os.path.join(out, "ciscat-master-2.3.1.zip")) as z:
            setup = z.read("master/ciscat-master-setup.sh").decode()
        self.assertIn(SHA, setup)
        with zipfile.ZipFile(os.path.join(out, "ciscat-agent-windows-2.3.1.zip")) as z:
            ps1 = z.read("agent-windows/install-windows-agent.ps1")
        self.assertIn(b"\r\n", ps1)
        self.assertNotIn(b"Assessor/", b"".join(n.encode() for n in z.namelist()))

    def test_full_packages_leave_the_license_out(self):
        for os_name, cli, java in (("win", "Assessor-CLI.bat", "jre/bin/java.exe"),
                                   ("lin", "Assessor-CLI.sh", "jre/bin/java")):
            for sub in ("license", "benchmarks", "reports", "jre/bin"):
                os.makedirs(os.path.join(self.d, os_name, sub))
            for path in (cli, "license/license.xml", "benchmarks/b-xccdf.xml", "reports/r.csv",
                         java):
                with open(os.path.join(self.d, os_name, path), "w") as f:
                    f.write("x")
        out, names = self.build("--assessor-windows", os.path.join(self.d, "win"),
                                "--assessor-linux", os.path.join(self.d, "lin"),
                                "--assessor-version", "4.62.0")
        with tarfile.open(os.path.join(out, "ciscat-agent-linux-2.3.1-assessor-4.62.0.tar.gz")) as t:
            members = t.getnames()
        self.assertIn("agent-linux/Assessor/Assessor-CLI.sh", members)
        self.assertIn("agent-linux/ASSESSOR_VERSION", members)
        self.assertFalse([m for m in members if "/license" in m or "/reports" in m
                          or "/benchmarks" in m])
        with zipfile.ZipFile(os.path.join(out, "ciscat-agent-windows-2.3.1-assessor-4.62.0.zip")) as z:
            members = z.namelist()
        self.assertIn("agent-windows/Assessor/Assessor-CLI.bat", members)
        self.assertFalse([m for m in members if "/license" in m or "/reports" in m])

    def test_full_packages_from_the_cis_downloads(self):
        win = self.download("CIS-CAT-Assessor-windows-v4.64.0.zip", True)
        lin = self.download("CIS-CAT-Assessor-linux-v4.64.0.zip", False)
        out, names = self.build("--assessor-windows", win, "--assessor-linux", lin)
        self.assertIn("ciscat-agent-windows-2.3.1-assessor-4.64.0.zip", names)
        self.assertIn("ciscat-agent-linux-2.3.1-assessor-4.64.0.tar.gz", names)
        with tarfile.open(os.path.join(out, "ciscat-agent-linux-2.3.1-assessor-4.64.0.tar.gz")) as t:
            members = {m.name: m for m in t.getmembers()}
            version = t.extractfile("agent-linux/ASSESSOR_VERSION").read()
        self.assertEqual(version, b"4.64.0\n")
        for f in ("Assessor-CLI.sh", "jre/bin/java", "jre/lib/jspawnhelper"):
            self.assertEqual(members["agent-linux/Assessor/" + f].mode & 0o777, 0o755, f)
        self.assertIn("agent-linux/Assessor/jre/legal/LICENSE", members)
        self.assertIn("agent-linux/Assessor/config/assessor-cli.properties", members)
        for m in members:
            self.assertNotRegex(m, r"/Assessor/(license|benchmarks|reports)(/|$)|CIS_")
        with zipfile.ZipFile(os.path.join(out, "ciscat-agent-windows-2.3.1-assessor-4.64.0.zip")) as z:
            members = z.namelist()
            sums = z.read("agent-windows/SHA256SUMS").decode()
        self.assertIn("agent-windows/Assessor/jre/bin/java.exe", members)
        self.assertFalse([m for m in members if "/license/" in m or "CIS_" in m])
        self.assertIn("Assessor/lib/assessor.jar", sums)
        with open(os.path.join(out, "assessor-left-out-linux.txt")) as f:
            left = f.read().split()
        self.assertIn("license/license.xml", left)
        self.assertIn("reports/old.html", left)
        self.assertEqual(len([n for n in left if n.startswith("benchmarks/")]), 2)
        self.assertFalse(os.path.exists(os.path.join(out, "tmp")))

    def test_versions_per_platform_and_tar_downloads(self):
        win = self.download("assessor-win.zip", True, wrap="")
        src = os.path.join(self.d, "lin")
        with zipfile.ZipFile(self.download("x.zip", False, modes=True)) as z:
            z.extractall(src)
        lin = os.path.join(self.d, "CIS-CAT-Assessor-linux-v4.65.1.tar.gz")
        with tarfile.open(lin, "w:gz") as t:
            t.add(os.path.join(src, "Assessor"), arcname="Assessor")
        r, out = self.run_build("--assessor-windows", win, "--assessor-linux", lin)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no version in the name", r.stdout)
        out, names = self.build("--assessor-windows", win, "--assessor-version-windows",
                                "4.63.0", "--assessor-linux", lin)
        self.assertIn("ciscat-agent-windows-2.3.1-assessor-4.63.0.zip", names)
        self.assertIn("ciscat-agent-linux-2.3.1-assessor-4.65.1.tar.gz", names)

    def test_a_licensed_file_left_elsewhere_stops_the_build(self):
        lin = self.download("CIS-CAT-Assessor-linux-v4.64.0.zip", False,
                            extra=["misc/CIS_Ubuntu_Linux_24.04_LTS_Benchmark_v1.0.0.xml"])
        r, out = self.run_build("--assessor-linux", lin)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("licensed CIS file(s)", r.stdout)
        self.assertIn("misc/CIS_Ubuntu", r.stdout)
        lin = self.download("CIS-CAT-Assessor-linux-v4.64.1.zip", False,
                            extra=["config/license.xml"])
        r, out = self.run_build("--assessor-linux", lin)
        self.assertIn("config/license.xml", r.stdout)

    def test_the_wrong_platform_or_an_unsafe_archive_is_refused(self):
        win = self.download("CIS-CAT-Assessor-windows-v4.64.0.zip", True,
                            extra=["Assessor-CLI.sh"])
        r, out = self.run_build("--assessor-linux", win)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not the Linux Assessor", r.stdout)
        bad = self.download("CIS-CAT-Assessor-linux-v4.64.0.zip", False,
                            extra=["../../escape.sh"])
        r, out = self.run_build("--assessor-linux", bad)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("unsafe path", r.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.d, "escape.sh")))


if __name__ == "__main__":
    unittest.main()
