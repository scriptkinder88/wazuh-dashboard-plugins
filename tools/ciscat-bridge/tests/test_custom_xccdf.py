"""Tailored profile built from several base profiles (STIG categories, role-less benchmarks)."""
import os
import re
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin"))
import csv_to_custom_xccdf as conv  # noqa: E402

P = "xccdf_org.cisecurity.benchmarks_profile_"
R = "xccdf_org.cisecurity.benchmarks_rule_{0}_Rule_{0}"


def profile(pid, selects):
    lines = ['<xccdf:Profile id="{0}{1}">'.format(P, pid),
             "<xccdf:title>{0}</xccdf:title>".format(pid)]
    lines += ['<xccdf:select idref="{0}" selected="{1}"/>'.format(R.format(n), str(on).lower())
              for n, on in selects]
    return "\n".join(lines + ["</xccdf:Profile>"])


BENCH = "<xccdf:Benchmark>\n{0}\n<xccdf:Rule id=\"x\"/>\n</xccdf:Benchmark>\n".format("\n".join([
    profile("SEVERITY_CAT_I", [("1.1", True), ("1.2", False), ("2.1", False)]),
    profile("SEVERITY_CAT_II", [("1.1", False), ("1.2", True), ("2.1", False)]),
    profile("SEVERITY_CAT_III", [("3.1", True)]),
]))


class BaseProfiles(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.bench = self.path("bench-xccdf.xml", BENCH)
        self.out = os.path.join(self.dir, "custom-xccdf.xml")

    def path(self, name, content):
        p = os.path.join(self.dir, name)
        with open(p, "w") as f:
            f.write(content)
        return p

    def build(self, rows, profiles=("SEVERITY_CAT_I", "SEVERITY_CAT_II", "SEVERITY_CAT_III")):
        csv = self.path("ex.csv", "scope,scope_value,level,role,rule,reason\n" + "".join(
            r + "\n" for r in rows))
        return conv.build_custom_xccdf(csv, self.bench, "os-rhel9", "rhel9_stig_v1_0_0", "STIG", [],
                                       self.out, list(profiles))

    def tailored(self):
        with open(self.out) as f:
            data = f.read()
        block = re.search(r'<xccdf:Profile id="{0}TAILORED_Level_1_-_STIG">.*?</xccdf:Profile>'
                          .format(P), data, re.S).group(0)
        return block, {n: s == "true" for n, s in re.findall(
            r'benchmarks_rule_([0-9.]+)_Rule_[0-9.]+" selected="(true|false)"', block)}

    def test_union_of_the_categories_minus_exclusions(self):
        summary, audit, rejected, _, role = self.build([
            "os,rhel9_stig_v1_0_0,all,,1.2,r",
            "os,rhel9_stig_v1_0_0,l1,SEVERITY_CAT_III,3.1,r",  # role of a dashboard column
            "os,rhel9_stig_v1_0_0,l2,,1.1,r",                  # another level: not this profile
            "os,other_os,all,,1.1,r",
        ])
        block, sel = self.tailored()
        self.assertEqual(sel, {"1.1": True, "1.2": False, "2.1": False, "3.1": False})
        self.assertIn("<xccdf:title>TAILORED L1 - STIG (os-rhel9)</xccdf:title>", block)
        self.assertEqual((summary, role, rejected),
                         ([("L1", P + "TAILORED_Level_1_-_STIG", 2)], "STIG", []))
        self.assertEqual(len(audit), 2)
        with open(self.out) as f:  # the standard profiles stay as they are
            self.assertEqual(f.read().count("<xccdf:Profile "), 4)

    def test_missing_profile(self):
        with self.assertRaises(SystemExit) as err:
            self.build([], profiles=["Level_1"])
        self.assertIn("['Level_1'] not found", str(err.exception))


if __name__ == "__main__":
    unittest.main()
