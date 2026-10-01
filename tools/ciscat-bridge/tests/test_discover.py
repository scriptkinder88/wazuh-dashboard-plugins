"""Benchmarks present on the manager -> OS library entries (synthetic benchmark files)."""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin"))
import ciscat_discover as discover  # noqa: E402

P = "xccdf_org.cisecurity.benchmarks_profile_"


def bench(roles, extra=()):
    profiles = ['<xccdf:Profile id="{0}Level_{1}_-_{2}"/>'.format(P, lvl, r)
                for r in roles for lvl in (1, 2)]
    profiles += ['<xccdf:Profile id="{0}{1}"/>'.format(P, e) for e in extra]
    return "<xccdf:Benchmark>{0}</xccdf:Benchmark>".format("".join(profiles))


LIBRARY = {
    "rhel7": {"active": True, "family": "linux", "group": "os-rhel7",
              "benchmark": "CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v3.1.1-xccdf.xml",
              "companion_prefix": "CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v3.1.1",
              "ar_bootstrap": "!site-bootstrap-linux", "ar_refresh": "!site-refresh-linux"},
}


class Discover(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)

    def put(self, name, content):
        with open(os.path.join(self.dir, name), "w") as f:
            f.write(content)

    def test_names_and_keys(self):
        self.assertEqual(discover.parse_name("CIS_Ubuntu_Linux_22.04_LTS_Benchmark_v2.0.0-xccdf.xml"),
                         ("Ubuntu_Linux_22.04_LTS", "2.0.0"))
        self.assertIsNone(discover.parse_name("rhel7-custom-xccdf.xml"))
        self.assertIsNone(discover.parse_name("CIS_Foo_Benchmark_v1.0.0-oval.xml"))
        self.assertEqual(discover.os_key_for("Red_Hat_Enterprise_Linux_9"), "rhel9")
        self.assertEqual(discover.os_key_for("Microsoft_Windows_Server_2022"), "windows_server_2022")
        self.assertEqual(discover.os_key_for("IBM_AIX_7.2"), "ibm_aix_7_2")
        self.assertEqual(discover.family_for("Microsoft_SQL_Server_2019"), "windows")
        self.assertEqual(discover.family_for("IBM_AIX_7.2"), "linux")

    def test_every_benchmark_version_becomes_an_os(self):
        self.put("CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v3.1.1-xccdf.xml", bench(["Server"]))
        self.put("CIS_Red_Hat_Enterprise_Linux_9_Benchmark_v1.0.0-xccdf.xml", bench(["Server"]))
        self.put("CIS_Red_Hat_Enterprise_Linux_9_Benchmark_v2.0.0-xccdf.xml",
                 bench(["Workstation", "Server"]))
        self.put("CIS_Red_Hat_Enterprise_Linux_9_Benchmark_v2.0.0-oval.xml", "")
        self.put("CIS_Microsoft_Windows_Server_2022_Benchmark_v3.0.0-xccdf.xml",
                 bench(["Member_Server", "Domain_Controller"]))
        lib, notes = discover.merge(LIBRARY, self.dir)
        self.assertEqual(sorted(lib), ["rhel7", "rhel9_v1_0_0", "rhel9_v2_0_0",
                                       "windows_server_2022_v3_0_0"])
        self.assertEqual(dict(lib["rhel7"], title=None), dict(LIBRARY["rhel7"], title=None))
        self.assertEqual(lib["rhel7"]["title"], "Red Hat Enterprise Linux 7 v3.1.1")
        rhel9 = lib["rhel9_v2_0_0"]
        self.assertEqual(rhel9["title"], "Red Hat Enterprise Linux 9 v2.0.0")
        self.assertEqual(rhel9["benchmark"], "CIS_Red_Hat_Enterprise_Linux_9_Benchmark_v2.0.0-xccdf.xml")
        self.assertEqual(rhel9["companion_prefix"], "CIS_Red_Hat_Enterprise_Linux_9_Benchmark_v2.0.0")
        self.assertEqual((rhel9["role"], rhel9["group"], rhel9["profiles"]),
                         ("Server", "os-rhel9_v2_0_0", [["l1_server", "L1"]]))
        self.assertEqual(lib["rhel9_v1_0_0"]["benchmark"],
                         "CIS_Red_Hat_Enterprise_Linux_9_Benchmark_v1.0.0-xccdf.xml")
        self.assertEqual(rhel9["flat_path"], "/var/lib/wazuh-ciscat/reports-cache/l1_server/results.txt")
        # same Active Response commands as the OS already configured for the family
        self.assertEqual((rhel9["ar_bootstrap"], rhel9["ar_refresh"]),
                         ("!site-bootstrap-linux", "!site-refresh-linux"))
        win = lib["windows_server_2022_v3_0_0"]
        self.assertEqual((win["family"], win["role"], win["ar_assessment"]),
                         ("windows", "Member_Server", "!ciscat-assessment0"))
        self.assertTrue(win["flat_path"].endswith("\\cis_windows_server_2022_v3_0_0.ciscat-flat"))
        self.assertTrue(win["active"] and win["discovered"])
        self.assertIn("rhel9_v2_0_0: new OS from CIS_Red_Hat_Enterprise_Linux_9_Benchmark_v2.0.0-xccdf.xml "
                      "(role Server)", notes)

    def test_configured_os_follows_a_newer_benchmark(self):
        self.put("CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v4.0.0-xccdf.xml", bench(["Server"]))
        lib, notes = discover.merge(LIBRARY, self.dir)
        self.assertEqual(sorted(lib), ["rhel7"])
        self.assertEqual(lib["rhel7"]["benchmark"], "CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v4.0.0-xccdf.xml")
        self.assertEqual(lib["rhel7"]["companion_prefix"], "CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v4.0.0")
        self.assertEqual(lib["rhel7"]["title"], "Red Hat Enterprise Linux 7 v4.0.0")
        self.assertEqual(LIBRARY["rhel7"]["benchmark"],
                         "CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v3.1.1-xccdf.xml")  # input untouched
        self.assertEqual(len(notes), 1)

    def test_groups_chosen_in_the_dashboard(self):
        library = {"rhel7": dict(LIBRARY["rhel7"], active=False)}
        lib = discover.apply_targets(library, {"rhel7": {"group": "linux-prod"}, "gone": {"group": "x"}})
        self.assertEqual((lib["rhel7"]["group"], lib["rhel7"]["group_source"], lib["rhel7"]["active"]),
                         ("linux-prod", "dashboard", True))
        self.assertFalse(library["rhel7"]["active"])
        self.assertEqual(sorted(lib), ["rhel7"])
        self.assertEqual(LIBRARY["rhel7"]["group"], "os-rhel7")

    def test_benchmarks_without_role_profiles_are_skipped(self):
        self.put("CIS_Microsoft_Windows_11_Enterprise_Benchmark_v3.0.0-xccdf.xml",
                 bench([], extra=["Level_1_L1_-_CorporateEnterprise_Environment_general_use"]))
        lib, notes = discover.merge({}, self.dir)
        self.assertEqual(lib, {})
        self.assertIn("no Level 1 or STIG profile", notes[0])

    def test_stig_and_role_less_benchmarks(self):
        put = lambda name, ids: self.put(name, bench([], extra=ids))
        put("CIS_Red_Hat_Enterprise_Linux_9_STIG_Benchmark_v1.0.0-xccdf.xml",
            ["SEVERITY_CAT_I", "SEVERITY_CAT_II", "SEVERITY_CAT_III"])
        put("CIS_Microsoft_Windows_Server_2022_STIG_Benchmark_v3.0.0-xccdf.xml",
            ["DC_SEVERITY_CAT_I", "DC_SEVERITY_CAT_II", "MS_SEVERITY_CAT_I", "MS_SEVERITY_CAT_II",
             "MS_SEVERITY_CAT_III"])
        put("CIS_Microsoft_Windows_11_Enterprise_Benchmark_v5.1.0-xccdf.xml",
            ["BitLocker_BL", "Level_1_L1", "Level_1_L1__BitLocker_BL", "Level_2_L2"])
        put("CIS_Apache_Tomcat_10.1_Benchmark_v1.2.0-xccdf.xml", ["Level_1", "Level_2"])
        put("CIS_MongoDB_8_Benchmark_v2.0.0-xccdf.xml", ["Level_1-_MongoDB", "Level_2_-_MongoDB"])
        lib, notes = discover.merge({}, self.dir)
        got = {k: (v["role"], v["base_profiles"], v["profiles"]) for k, v in lib.items()}
        self.assertEqual(got, {
            "rhel9_stig_v1_0_0": ("STIG", ["SEVERITY_CAT_I", "SEVERITY_CAT_II", "SEVERITY_CAT_III"],
                                  [["l1_stig", "L1"]]),
            "windows_server_2022_stig_v3_0_0": (
                "Member_Server_STIG", ["MS_SEVERITY_CAT_I", "MS_SEVERITY_CAT_II", "MS_SEVERITY_CAT_III"],
                [["l1_member_server_stig", "L1"]]),
            "windows_11_enterprise_v5_1_0": ("Default", ["Level_1_L1"], [["l1_default", "L1"]]),
            "apache_tomcat_10_1_v1_2_0": ("Default", ["Level_1"], [["l1_default", "L1"]]),
            "mongodb_8_v2_0_0": ("MongoDB", ["Level_1-_MongoDB"], [["l1_mongodb", "L1"]]),
        })
        self.assertEqual(lib["windows_11_enterprise_v5_1_0"]["family"], "windows")
        self.assertIn("rhel9_stig_v1_0_0: new OS from CIS_Red_Hat_Enterprise_Linux_9_STIG_Benchmark_"
                      "v1.0.0-xccdf.xml (role STIG, profiles SEVERITY_CAT_I + SEVERITY_CAT_II + "
                      "SEVERITY_CAT_III)", notes)

    def test_standard_profiles_have_no_base_profiles(self):
        self.put("CIS_Red_Hat_Enterprise_Linux_8_STIG_Benchmark_v2.0.0-xccdf.xml",
                 bench(["Server", "Workstation"], extra=["STIG"]))
        lib, _ = discover.merge({}, self.dir)
        self.assertEqual(lib["rhel8_stig_v2_0_0"]["role"], "Server")
        self.assertNotIn("base_profiles", lib["rhel8_stig_v2_0_0"])

    def test_missing_folder(self):
        lib, notes = discover.merge(LIBRARY, os.path.join(self.dir, "none"))
        self.assertEqual((sorted(lib), lib["rhel7"]["benchmark"], notes),
                         (["rhel7"], LIBRARY["rhel7"]["benchmark"], []))


if __name__ == "__main__":
    unittest.main()
