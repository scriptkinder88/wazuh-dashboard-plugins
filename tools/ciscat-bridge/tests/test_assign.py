"""Agents into the group of their OS benchmark (ciscat_assign.py, ciscat-fleet.py assign)."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "bin")
sys.path.insert(0, BIN)
sys.path.insert(0, HERE)
import ciscat_assign as assign  # noqa: E402
from fake_wazuh_api import FakeWazuh  # noqa: E402


def entry(benchmark, group, active=True, discovered=False, family="linux"):
    return {"active": active, "discovered": discovered, "family": family, "group": group,
            "benchmark": benchmark}


LIBRARY = {
    "rhel7": entry("CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v4.0.0-xccdf.xml", "os-rhel7"),
    "rhel7_v3_1_1": entry("CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v3.1.1-xccdf.xml",
                          "os-rhel7_v3_1_1", discovered=True),
    "rhel8": entry("CIS_Red_Hat_Enterprise_Linux_8_Benchmark_v4.0.0-xccdf.xml", "os-rhel8",
                   active=False),
    "rhel9_v2_0_0": entry("CIS_Red_Hat_Enterprise_Linux_9_Benchmark_v2.0.0-xccdf.xml",
                          "os-rhel9_v2_0_0", discovered=True),
    "rhel9_stig_v1_0_0": entry("CIS_Red_Hat_Enterprise_Linux_9_STIG_Benchmark_v1.0.0-xccdf.xml",
                               "os-rhel9_stig_v1_0_0", discovered=True),
    "ubuntu_linux_22_04_lts_v2_0_0": entry(
        "CIS_Ubuntu_Linux_22.04_LTS_Benchmark_v2.0.0-xccdf.xml",
        "os-ubuntu_linux_22_04_lts_v2_0_0", discovered=True),
    "windows_server_2025": entry("CIS_Microsoft_Windows_Server_2025_Benchmark_v2.0.0-xccdf.xml",
                                 "os-windows_server_2025", family="windows"),
    "windows_server_2025_stand_alone_v2_0_0": entry(
        "CIS_Microsoft_Windows_Server_2025_Stand-alone_v2.0.0-xccdf.xml",
        "os-windows_server_2025_stand_alone_v2_0_0", discovered=True, family="windows"),
    "windows_11_enterprise_v4_0_0": entry(
        "CIS_Microsoft_Windows_11_Enterprise_Benchmark_v4.0.0-xccdf.xml",
        "os-windows_11_enterprise_v4_0_0", discovered=True, family="windows"),
    "apache_tomcat_9_v1_0_0": entry("CIS_Apache_Tomcat_9_Benchmark_v1.0.0-xccdf.xml",
                                    "web-servers", discovered=True),
}


class Matcher(unittest.TestCase):
    def test_agent_products(self):
        cases = [
            ({"platform": "rhel", "major": "7", "name": "Red Hat Enterprise Linux Server"},
             "Red_Hat_Enterprise_Linux_7"),
            ({"platform": "ol", "major": "9", "name": "Oracle Linux Server"}, "Oracle_Linux_9"),
            ({"platform": "rocky", "major": "8"}, "Rocky_Linux_8"),
            ({"platform": "almalinux", "major": "9"}, "AlmaLinux_OS_9"),
            ({"platform": "ubuntu", "major": "22", "minor": "04"}, "Ubuntu_Linux_22.04_LTS"),
            ({"platform": "ubuntu", "major": "24", "minor": "4"}, "Ubuntu_Linux_24.04_LTS"),
            ({"platform": "debian", "major": "12"}, "Debian_Linux_12"),
            ({"platform": "sles", "major": "15"}, "SUSE_Linux_Enterprise_15"),
            ({"platform": "amzn", "major": "2023"}, "Amazon_Linux_2023"),
            ({"platform": "", "major": "9", "name": "Rocky Linux"}, "Rocky_Linux_9"),
            ({"platform": "windows", "name": "Microsoft Windows Server 2025 Datacenter"},
             "Microsoft_Windows_Server_2025"),
            ({"platform": "windows", "name": "Microsoft Windows Server 2012 R2 Standard"},
             "Microsoft_Windows_Server_2012_R2"),
            ({"platform": "windows", "name": "Microsoft Windows Server 2012 Standard"},
             "Microsoft_Windows_Server_2012_(non-R2)"),
            ({"platform": "windows", "name": "Microsoft Windows 11 Pro"},
             "Microsoft_Windows_11_Enterprise"),
        ]
        for os_info, product in cases:
            self.assertEqual(assign.agent_product(os_info), product, os_info)
        for os_info in ({}, None, {"platform": "darwin", "major": "14"},
                        {"platform": "rhel"}, {"platform": "ubuntu", "major": "22"},
                        {"platform": "windows", "name": "Microsoft Windows Embedded"}):
            self.assertIsNone(assign.agent_product(os_info), os_info)

    def test_os_products(self):
        self.assertEqual(assign.os_product(LIBRARY["rhel9_stig_v1_0_0"]),
                         "Red_Hat_Enterprise_Linux_9")
        self.assertEqual(assign.os_product(LIBRARY["windows_server_2025_stand_alone_v2_0_0"]),
                         "Microsoft_Windows_Server_2025")
        self.assertIsNone(assign.os_product(LIBRARY["apache_tomcat_9_v1_0_0"]))

    def test_choose(self):
        rhel = {"platform": "rhel", "major": "7"}
        # the newest version, an os-library.json entry before a discovered one
        self.assertEqual(assign.choose(LIBRARY, rhel), ("rhel7", None))
        # the standard benchmark, never the STIG or Stand-alone variant
        self.assertEqual(assign.choose(LIBRARY, {"platform": "rhel", "major": "9"}),
                         ("rhel9_v2_0_0", None))
        self.assertEqual(assign.choose(LIBRARY, {"platform": "windows",
                                                 "name": "Microsoft Windows Server 2025"}),
                         ("windows_server_2025", None))
        self.assertEqual(assign.choose(LIBRARY, {"platform": "rhel", "major": "8"}),
                         (None, "rhel8 inactive in os-library.json"))
        self.assertEqual(assign.choose(LIBRARY, {"platform": "debian", "major": "12"}),
                         (None, "no benchmark for Debian_Linux_12"))
        self.assertEqual(assign.choose(LIBRARY, {}), (None, "OS not known yet"))


class FleetAssign(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        paths = {k: os.path.join(self.root, k) for k in
                 ("exclusions_dir", "benchmarks_dir", "shared_dir", "work_dir", "lists_dir",
                  "run_dir")}
        for d in paths.values():
            os.makedirs(d)
        self.etc = os.path.join(self.root, "etc")
        os.makedirs(self.etc)
        lib = {k: dict(v, base=k, role="Server", profiles=[["l1_server", "L1"]],
                       policy_id="p_" + k, policy_name=k)
               for k, v in LIBRARY.items()}
        with open(os.path.join(self.etc, "os-library.json"), "w") as f:
            json.dump(lib, f)
        rhel = lambda major: {"platform": "rhel", "major": major,  # noqa: E731
                              "name": "Red Hat Enterprise Linux"}
        self.fake = FakeWazuh(paths["shared_dir"], {
            "000": {"name": "manager", "status": "active", "group": [], "os": rhel("9")},
            "001": {"name": "rh7-a", "status": "active", "group": ["default"], "os": rhel("7")},
            "002": {"name": "rh7-b", "status": "active", "group": ["default", "os-rhel7"],
                    "os": rhel("7")},
            "003": {"name": "rh9-stig", "status": "active",
                    "group": ["default", "os-rhel9_stig_v1_0_0"], "os": rhel("9")},
            "004": {"name": "upgraded", "status": "active", "group": ["os-rhel7"],
                    "os": rhel("9")},
            "005": {"name": "win", "status": "disconnected", "group": ["default", "web-servers"],
                    "os": {"platform": "windows",
                           "name": "Microsoft Windows Server 2025 Datacenter"}},
            "006": {"name": "deb", "status": "active", "group": ["default"],
                    "os": {"platform": "debian", "major": "12"}},
            "007": {"name": "new", "status": "never_connected", "group": ["default"], "os": {}},
        })
        self.env = dict(os.environ, CISCAT_ETC_DIR=self.etc, CISCAT_PATHS_JSON=json.dumps(paths),
                        CISCAT_API_URL=self.fake.serve(), WAZUH_API_PASSWORD="x")

    def tearDown(self):
        self.fake.server.shutdown()

    def run_fleet(self, *args):
        r = subprocess.run([sys.executable, os.path.join(BIN, "ciscat-fleet.py"), "assign"] +
                           list(args), env=self.env, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
        return r.returncode, r.stdout

    def test_dry_run_changes_nothing(self):
        before = json.dumps(self.fake.agents, sort_keys=True)
        rc, out = self.run_fleet()
        self.assertEqual(rc, 0, out)
        self.assertIn("assign: 7 agent(s): 2 in their OS group, 2 to add, 2 without an OS "
                      "benchmark", out)
        self.assertIn("[+] 001 rh7-a: rhel7 -> os-rhel7", out)
        self.assertIn("[+] 005 win: windows_server_2025 -> os-windows_server_2025 (new group)",
                      out)
        self.assertIn("[!] 004 upgraded: in os-rhel7, but reports Red_Hat_Enterprise_Linux_9",
                      out)
        self.assertIn("[-] no benchmark for Debian_Linux_12: 1 agent(s) 006", out)
        self.assertIn("[-] OS not known yet: 1 agent(s) 007", out)
        self.assertIn("[dry-run] nothing changed", out)
        self.assertEqual(json.dumps(self.fake.agents, sort_keys=True), before)

    def test_apply_assigns_and_is_idempotent(self):
        self.run_fleet("--apply")
        g = {i: a["group"] for i, a in self.fake.agents.items()}
        self.assertEqual(g["001"], ["default", "os-rhel7"])
        self.assertEqual(g["005"], ["default", "web-servers", "os-windows_server_2025"])
        self.assertIn("os-windows_server_2025", self.fake.groups)
        # STIG chosen in the dashboard, upgraded host, unknown OS: left as they are
        self.assertEqual(g["003"], ["default", "os-rhel9_stig_v1_0_0"])
        self.assertEqual(g["004"], ["os-rhel7"])
        self.assertEqual(g["006"], ["default"])
        self.assertEqual(g["007"], ["default"])
        rc, out = self.run_fleet()
        self.assertIn("4 in their OS group, 0 to add", out)

    def test_auto_follows_the_conf(self):
        rc, out = self.run_fleet("--auto")
        self.assertEqual(rc, 0, out)
        self.assertIn("auto_assign is off", out)
        self.assertEqual(self.fake.agents["001"]["group"], ["default"])
        with open(os.path.join(self.etc, "ciscat-orchestrator.conf"), "w") as f:
            f.write("auto_assign=yes\n")
        self.run_fleet("--auto")
        self.assertEqual(self.fake.agents["001"]["group"], ["default", "os-rhel7"])


if __name__ == "__main__":
    unittest.main()
