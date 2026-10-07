"""xccdf_to_sca_policy.py: Wazuh 4.x and 5.0 policy formats (synthetic XCCDF)."""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "bin", "xccdf_to_sca_policy.py")
P = "xccdf_org.cisecurity.benchmarks_profile_TAILORED_Level_1_-_Server"
R = "xccdf_org.cisecurity.benchmarks_rule_"


def rule(num, title, auto=True):
    check = '<check system="http://oval.mitre.org/XMLSchema/oval-definitions-5"/>' if auto else ""
    return ('<xccdf:Rule id="{0}{1}_Ensure_x"><xccdf:title>{2}</xccdf:title>'
            '<xccdf:description>Desc of {1}</xccdf:description>'
            '<xccdf:rationale>Why {1}</xccdf:rationale><xccdf:fixtext>Fix {1}</xccdf:fixtext>'
            '<xccdf:ident cc8:controlURI="http://cisecurity.org/20-cc/v8.0/control/4/subcontrol/8"/>'
            '{3}</xccdf:Rule>').format(R, num, title, check)


XCCDF = ('<xccdf:Benchmark>'
         '<xccdf:Profile id="{p}">'
         '<xccdf:select idref="{r}1.1.1_Ensure_x" selected="true"/>'
         '<xccdf:select idref="{r}1.1.2_Ensure_x" selected="true"/>'
         '<xccdf:select idref="{r}1.1.10_Ensure_x" selected="true"/>'
         '<xccdf:select idref="{r}2.1_Ensure_x" selected="false"/>'
         '</xccdf:Profile>'
         '<xccdf:Group id="xccdf_org.cisecurity.benchmarks_group_1_Initial_Setup">'
         '<xccdf:title>Initial Setup</xccdf:title>'
         '{a}{b}{c}</xccdf:Group></xccdf:Benchmark>').format(
             p=P, r=R, a=rule("1.1.1", "Ensure cramfs is disabled (it's unused)"),
             b=rule("1.1.2", "Manual check", auto=False), c=rule("1.1.10", "Ensure tmp | ok"))


class PolicyFormats(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        self.xccdf = os.path.join(self.d, "custom-xccdf.xml")
        with open(self.xccdf, "w") as f:
            f.write(XCCDF)

    def policy(self, *extra):
        out = os.path.join(self.d, "pol" + "".join(extra).replace("-", ""))
        r = subprocess.run([sys.executable, SCRIPT, "--xccdf", self.xccdf, "--profile-id", P,
                            "--flat-path", "C:\\Program Files (x86)\\ciscat\\results\\x.ciscat-flat",
                            "--policy-id", "cis_x", "--policy-name", "CIS X (os-x)", "--out", out]
                           + list(extra), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)
        with open(out + ".yml", encoding="utf-8") as f:
            return f.read()

    def test_4x_format(self):
        text = self.policy()
        self.assertEqual(text, self.policy("--format", "4"))
        self.assertIn("  title: 'CIS-CAT Pro installed and assessment results present'", text)
        self.assertIn("    title: '1.1.1 Ensure cramfs is disabled (it''s unused)'", text)
        self.assertIn("      - cis_csc_v8: ['4.8']\n      - cis_family: ['1 Initial Setup']", text)
        self.assertNotIn("1.1.2", text)  # manual

    def test_5_format(self):
        text = self.policy("--format", "5")
        v4 = self.policy()
        self.assertNotRegex(text, r"(?m)^\s+title:")
        self.assertIn("requirements:\n  name: 'CIS-CAT Pro installed and assessment results present'", text)
        names = re.findall(r"(?m)^    name: '(.*)'$", text)
        self.assertEqual(names, ["1.1.1 Ensure cramfs is disabled (it''s unused)",
                                 "1.1.10 Ensure tmp | ok"])
        self.assertNotIn("compliance", text)
        self.assertNotIn("cis_", text.replace("cis_x", ""))
        # the policy block, rules and everything else are those of 4.x
        self.assertEqual(re.sub(r"(?m)^(\s+)title:", r"\1name:",
                                re.sub(r"(?m)^    compliance:\n(      - .*\n)+", "", v4)), text)
        for regex in re.findall(r"-> r:(.*)'$", text, re.M):
            re.compile(regex)  # Python re accepts what PCRE2 does for these literals
            self.assertRegex(regex, r"^\^[0-9]+(\\\.[0-9]+)*:pass\$$")
        self.assertIn(r"r:^1\.1\.10:pass$", text)
        self.assertIn("    - 'f:C:\\Program Files (x86)\\ciscat\\results\\x.ciscat-flat'", text)


if __name__ == "__main__":
    unittest.main()
