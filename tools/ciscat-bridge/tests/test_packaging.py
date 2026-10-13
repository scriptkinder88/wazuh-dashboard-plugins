"""packaging/build.py: the three release packages, complete and without licensed files."""
import hashlib
import os
import re
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
                 "benchmarks/oval/CIS_Microsoft_Windows_Server_2025_Benchmark_v1.0.0-oval.xml",
                 "jre/bin/java.exe" if windows else "jre/bin/java", "jre/legal/LICENSE",
                 "reports/old.html", "logs/"] + list(extra)
        if not windows:
            files.append("jre/lib/jspawnhelper")
        path = os.path.join(self.d, name)
        with zipfile.ZipFile(path, "w") as z:
            for f in files:
                info = zipfile.ZipInfo((wrap + "/" if wrap else "") + f)
                # made on Windows: no unix mode, no exec bit
                info.external_attr = (0o100755 << 16) if modes else 0
                if f.endswith("/"):  # an empty folder
                    info.external_attr = (0o040755 << 16) | 0x10
                z.writestr(info, "" if f.endswith("/") else "x")
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

    def test_full_packages_leave_only_the_license_and_benchmarks_out(self):
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
        self.assertIn("opt/ciscat/Assessor/Assessor-CLI.sh", members)
        self.assertIn("opt/ciscat/Assessor/.bridge-assessor-version", members)
        self.assertIn("opt/ciscat/Assessor/reports/r.csv", members)
        self.assertIn("opt/ciscat/Assessor/license", members)
        self.assertIn("opt/ciscat/Assessor/benchmarks", members)
        self.assertNotIn("agent-linux/install-linux-agent.sh", members)  # final: no installer
        self.assertFalse([m for m in members if "/benchmarks/" in m or "/license/" in m])
        with zipfile.ZipFile(os.path.join(out, "ciscat-agent-windows-2.3.1-assessor-4.62.0.zip")) as z:
            members = z.namelist()
        self.assertIn("CIS/Assessor/Assessor-CLI.bat", members)
        self.assertIn("CIS/Assessor/reports/r.csv", members)
        self.assertIn("CIS/Assessor/license/", members)
        self.assertIn("CIS/Assessor/benchmarks/", members)
        self.assertFalse([m for m in members if not m.endswith("/") and (
            "/benchmarks/" in m or "/license/" in m)])

    def test_full_packages_from_the_cis_downloads(self):
        win = self.download("CIS-CAT-Assessor-windows-v4.64.0.zip", True)
        lin = self.download("CIS-CAT-Assessor-linux-v4.64.0.zip", False)
        out, names = self.build("--assessor-windows", win, "--assessor-linux", lin)
        self.assertIn("ciscat-agent-windows-2.3.1-assessor-4.64.0.zip", names)
        self.assertIn("ciscat-agent-linux-2.3.1-assessor-4.64.0.tar.gz", names)
        with tarfile.open(os.path.join(out, "ciscat-agent-linux-2.3.1-assessor-4.64.0.tar.gz")) as t:
            members = {m.name: m for m in t.getmembers()}
            version = t.extractfile("opt/ciscat/Assessor/.bridge-assessor-version").read()
        self.assertEqual(version, b"4.64.0\n")
        for f in ("Assessor-CLI.sh", "jre/bin/java", "jre/lib/jspawnhelper"):
            self.assertEqual(members["opt/ciscat/Assessor/" + f].mode & 0o777, 0o755, f)
        for f in ("jre/legal/LICENSE", "config/assessor-cli.properties", "reports/old.html",
                  "lib/assessor.jar", "license", "benchmarks", "benchmarks/oval", "logs"):
            self.assertIn("opt/ciscat/Assessor/" + f, members)
        for m, info in members.items():
            if info.isfile():
                self.assertNotRegex(m, r"/Assessor/(license|benchmarks)/|CIS_|license\.xml|oval")
        with zipfile.ZipFile(os.path.join(out, "ciscat-agent-windows-2.3.1-assessor-4.64.0.zip")) as z:
            members = z.namelist()
            sums = z.read("Program Files (x86)/ossec-agent/active-response/bin/"
                          "ciscat-assessor.sha256").decode()
        # the folders stay, empty: license, benchmarks and its subfolders, logs
        for d in ("license/", "benchmarks/", "benchmarks/oval/", "logs/"):
            self.assertIn("CIS/Assessor/" + d, members)
        self.assertIn("CIS/Assessor/jre/bin/java.exe", members)
        self.assertIn("CIS/Assessor/reports/old.html", members)
        self.assertIn("CIS/Assessor/jre/legal/LICENSE", members)
        self.assertFalse([m for m in members if not m.endswith("/") and (
            "/benchmarks/" in m or "/license/" in m or "CIS_" in m or "oval" in m)])
        self.assertRegex(sums, r"(?m)^[0-9a-f]{64}  lib/assessor.jar\r$")
        with open(os.path.join(out, "assessor-left-out-linux.txt")) as f:
            left = f.read().split()
        self.assertEqual(sorted(left), [
            "benchmarks/CIS_Microsoft_Windows_Server_2025_Benchmark_v1.0.0-xccdf.xml",
            "benchmarks/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v4.0.0-xccdf.xml",
            "benchmarks/oval/CIS_Microsoft_Windows_Server_2025_Benchmark_v1.0.0-oval.xml",
            "license/license.xml"])
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

    def test_a_license_or_benchmark_left_elsewhere_stops_the_build(self):
        lin = self.download("CIS-CAT-Assessor-linux-v4.64.0.zip", False,
                            extra=["misc/CIS_Ubuntu_Linux_24.04_LTS_Benchmark_v1.0.0.xml"])
        r, out = self.run_build("--assessor-linux", lin)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("license or benchmark file(s)", r.stdout)
        self.assertIn("misc/CIS_Ubuntu", r.stdout)
        lin = self.download("CIS-CAT-Assessor-linux-v4.64.1.zip", False,
                            extra=["config/license.xml"])
        r, out = self.run_build("--assessor-linux", lin)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("config/license.xml", r.stdout)
        for name in ("misc/windows-oval.xml", "misc/oval.xml"):
            lin = self.download("CIS-CAT-Assessor-linux-v4.64.2.zip", False, extra=[name])
            r, out = self.run_build("--assessor-linux", lin)
            self.assertNotEqual(r.returncode, 0, name)
            self.assertIn(name, r.stdout)
        lin = self.download("CIS-CAT-Assessor-linux-v4.64.3.zip", False,
                            extra=["config/removal.xml"])
        r, out = self.run_build("--assessor-linux", lin)
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_the_wrong_platform_or_an_unsafe_archive_is_refused(self):
        win = self.download("CIS-CAT-Assessor-windows-v4.64.0.zip", True,
                            extra=["Assessor-CLI.sh"])
        r, out = self.run_build("--assessor-linux", win)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not the Linux Assessor", r.stdout)
        # the Linux download given as the Windows one
        lin = self.download("CIS-CAT-Assessor-Linux-jre-v4.67.0.zip", False)
        r, out = self.run_build("--assessor-windows", lin)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("it is the Linux Assessor, give it as --assessor-linux", r.stdout)
        # both JREs in one folder (or a shell that finds java.exe when asked for java)
        both = self.download("CIS-CAT-Assessor-linux-v4.64.2.zip", False,
                             extra=["jre/bin/java.exe"])
        r, out = self.run_build("--assessor-linux", both)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("java and java.exe", r.stdout)
        bad = self.download("CIS-CAT-Assessor-linux-v4.64.0.zip", False,
                            extra=["../../escape.sh"])
        r, out = self.run_build("--assessor-linux", bad)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("unsafe path", r.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.d, "escape.sh")))

    def test_package_modes_do_not_depend_on_the_disk(self):
        """As on Cygwin/MobaXterm: chmod does nothing and the disk shows every file as 0644."""
        lin = self.download("CIS-CAT-Assessor-linux-v4.64.0.zip", False, modes=False)
        with zipfile.ZipFile(lin, "a") as z:
            info = zipfile.ZipInfo("Assessor/misc/helper")
            info.external_attr = 0o100755 << 16
            z.writestr(info, "x")
        out = os.path.join(self.d, "out")
        code = ("import os, runpy, sys; sys.platform = 'cygwin'; "
                "os.chmod = lambda *a, **k: None; sys.argv = sys.argv[1:]; "
                "runpy.run_path(sys.argv[0], run_name='__main__')")
        r = subprocess.run([sys.executable, "-c", code, BUILD, "--plugin", "plugin.zip",
                            "--plugin-sha256", SHA, "--out", out, "--assessor-linux", lin],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True)
        self.assertEqual(r.returncode, 0, r.stdout)
        with tarfile.open(os.path.join(out, "ciscat-agent-linux-2.3.1-assessor-4.64.0.tar.gz")) as t:
            modes = {m.name: m.mode & 0o777 for m in t.getmembers()}
        for name, mode in (("var/ossec/active-response/bin/ciscat-bootstrap.sh", 0o750),
                           ("var/ossec/active-response/bin/ciscat-assessor.sha256", 0o640),
                           ("opt/ciscat", 0o755), ("opt/ciscat/Assessor", 0o700),
                           ("opt/ciscat/Assessor/Assessor-CLI.sh", 0o755),
                           ("opt/ciscat/Assessor/jre/bin/java", 0o755),
                           ("opt/ciscat/Assessor/jre/lib/jspawnhelper", 0o755),
                           ("opt/ciscat/Assessor/misc/helper", 0o755),
                           ("opt/ciscat/Assessor/lib/assessor.jar", 0o644),
                           ("var/lib/wazuh-ciscat", 0o700)):
            self.assertEqual(modes[name], mode, name)
        with zipfile.ZipFile(os.path.join(out, "ciscat-master-2.3.1.zip")) as z:
            info = z.getinfo("master/ciscat-master-setup.sh")
        self.assertEqual((info.external_attr >> 16) & 0o777, 0o755)

    def test_a_download_with_a_second_archive_inside_or_no_launcher(self):
        inner = self.download("inner.zip", True)
        outer = os.path.join(self.d, "CIS-CAT-Assessor-Windows-jre-v4.67.0.zip")
        with zipfile.ZipFile(outer, "w") as z:
            z.write(inner, "CIS-CAT Pro Assessor/Assessor-v4.67.0.zip")
            z.writestr("CIS-CAT Pro Assessor/README.txt", "x")
        out, names = self.build("--assessor-windows", outer)
        self.assertIn("ciscat-agent-windows-2.3.1-assessor-4.67.0.zip", names)
        with zipfile.ZipFile(os.path.join(out, names[names.index(
                "ciscat-agent-windows-2.3.1-assessor-4.67.0.zip")])) as z:
            self.assertIn("CIS/Assessor/Assessor-CLI.bat", z.namelist())
        # no launcher at all: the error shows what the download holds
        empty = os.path.join(self.d, "CIS-CAT-Assessor-Windows-jre-v4.68.0.zip")
        with zipfile.ZipFile(empty, "w") as z:
            z.writestr("Tool/Assessor-GUI.exe", "x")
        r, out = self.run_build("--assessor-windows", empty)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no Assessor-CLI.bat in " + empty, r.stdout)
        self.assertIn("Tool/Assessor-GUI.exe", r.stdout)

    def test_final_packages_unpack_in_place(self):
        """Unpacked in / and C:\\ as they are: no installer, no entry for folders that exist."""
        keys = os.path.join(self.d, "agent-keys")
        os.makedirs(keys)
        for n in ("ciscat-manifest.pub", "ciscat-manifest.pub.xml"):
            with open(os.path.join(keys, n), "w") as f:
                f.write("KEY " + n)
        win = self.download("CIS-CAT-Assessor-Windows-jre-v4.67.0.zip", True)
        lin = self.download("CIS-CAT-Assessor-Linux-jre-v4.67.0.zip", False)
        out, names = self.build("--assessor-windows", win, "--assessor-linux", lin,
                                "--master-keys", keys)
        self.assertEqual([n for n in names if n.startswith("ciscat-")], [
            "ciscat-agent-linux-2.3.1-assessor-4.67.0.tar.gz",
            "ciscat-agent-windows-2.3.1-assessor-4.67.0.zip",
            "ciscat-e2e-linux.sh", "ciscat-e2e-windows.ps1", "ciscat-master-2.3.1.zip"])
        with tarfile.open(os.path.join(out, "ciscat-agent-linux-2.3.1-assessor-4.67.0.tar.gz")) as t:
            members = {m.name: m for m in t.getmembers()}
            listing = t.extractfile("var/ossec/active-response/bin/ciscat-assessor.sha256").read()
            boot = t.extractfile("var/ossec/active-response/bin/ciscat-bootstrap.sh").read()
            props = t.extractfile("opt/ciscat/Assessor/config/assessor-cli.properties").read()
            files = {n: t.extractfile(m).read() for n, m in members.items() if m.isfile()}
        # only the bridge's own folders: unpacking in / leaves /var, /var/ossec, ... as they are
        dirs = sorted(n for n, m in members.items() if m.isdir())
        self.assertEqual([d for d in dirs if not d.startswith("opt/ciscat")],
                         ["var/lib/wazuh-ciscat"])
        self.assertTrue(all(n.startswith(("opt/ciscat/", "var/ossec/active-response/bin/",
                                          "var/lib/wazuh-ciscat/")) for n in files))
        b = members["var/ossec/active-response/bin/ciscat-bootstrap.sh"]
        self.assertEqual((b.uname, b.gname, b.mode), ("root", "wazuh", 0o750))
        with open(os.path.join(HERE, "..", "bin", "ciscat-bootstrap.sh"), "rb") as f:
            self.assertEqual(boot, f.read())
        self.assertEqual(files["var/lib/wazuh-ciscat/ciscat-manifest.pub"], b"KEY ciscat-manifest.pub")
        self.assertTrue(props.endswith(b"exit.on.invalid.signature=false\n"))
        # the list holds every Assessor file but the settings, with its sha256
        listed = {}
        for line in listing.decode().splitlines()[1:]:
            digest, rel = line.split("  ", 1)
            listed[rel] = digest
        expected = {n[len("opt/ciscat/Assessor/"):]: hashlib.sha256(c).hexdigest()
                    for n, c in files.items() if n.startswith("opt/ciscat/Assessor/")
                    and not re.search(r"Assessor/(config|reports|logs)/|/\.bridge-", n)}
        self.assertEqual(listed, expected)
        self.assertIn("Assessor-CLI.sh", listed)
        with zipfile.ZipFile(os.path.join(out, "ciscat-agent-windows-2.3.1-assessor-4.67.0.zip")) as z:
            names = z.namelist()
        binw = "Program Files (x86)/ossec-agent/active-response/bin/"
        for n in ("ciscat-assessment.cmd", "ciscat-bootstrap.ps1", "ciscat-assessor.sha256",
                  "ciscat-manifest.pub.xml"):
            self.assertIn(binw + n, names)
        self.assertIn("CIS/Assessor/Assessor-CLI.bat", names)
        self.assertTrue(all(n.startswith(("CIS/", binw)) for n in names))
        self.assertFalse([n for n in names if n.endswith("/") and n.startswith("Program Files")])


if __name__ == "__main__":
    unittest.main()
