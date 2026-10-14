"""ciscat_xccdf: the XCCDF parser shared by the bridge scripts (synthetic benchmarks only)."""
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "bin"))
import ciscat_xccdf as xccdf  # noqa: E402
import csv_to_custom_xccdf as conv  # noqa: E402

P = "xccdf_org.cisecurity.benchmarks_profile_"
R = "xccdf_org.cisecurity.benchmarks_rule_{0}_Rule_{0}"


def benchmark(prefix):
    """The same small benchmark, with every XCCDF element under `prefix` ("xccdf:" or "")."""
    x = prefix
    ns = ('xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2"' if x else
          'xmlns="http://checklists.nist.gov/xccdf/1.2"')
    return """<?xml version="1.0" encoding="UTF-8"?>
<{x}Benchmark {ns} xmlns:xhtml="http://www.w3.org/1999/xhtml"
    xmlns:cc8="http://cisecurity.org/20-cc/v8.0" id="xccdf_org.cisecurity.benchmarks_benchmark_T">
  <{x}version>2.0.0</{x}version>
  <{x}Profile id="{P}Level_1_-_Server">
    <{x}title>Level 1 - Server</{x}title>
    <{x}select idref="{r1}" selected="true"/>
    <{x}select idref="{r2}" selected="true"/>
    <{x}select idref="{r3}" selected="false"/>
  </{x}Profile>
  <{x}Group id="xccdf_org.cisecurity.benchmarks_group_1_Initial_Setup">
    <{x}title>Initial | Setup</{x}title>
    <{x}Group id="xccdf_org.cisecurity.benchmarks_group_1.1_Sub">
      <{x}title>Sub</{x}title>
      <{x}Rule id="{r1}">
        <{x}title>Ensure A &amp; B</{x}title>
        <{x}description><xhtml:p>Checks <xhtml:a href="https://x.example/a">the doc</xhtml:a>.</xhtml:p>
          <xhtml:ul><xhtml:li>one</xhtml:li><xhtml:li>two</xhtml:li></xhtml:ul>
          Line<xhtml:br/>two &lt;x&gt;</{x}description>
        <{x}fixtext>Run:
#!/bin/bash
echo fix</{x}fixtext>
        <{x}metadata><cc8:controls><cc8:framework cc8:controlURI="http://cisecurity.org/20-cc/v8.0/control/4/subcontrol/1"/>
          <cc8:framework cc8:controlURI="http://cisecurity.org/20-cc/v8.0/control/4/subcontrol/1"/></cc8:controls></{x}metadata>
        <{x}check system="oval"><{x}check-content-ref href="o.xml"/></{x}check>
      </{x}Rule>
      <{x}Rule id="{r2}">
        <{x}title>Manual rule</{x}title>
      </{x}Rule>
      <{x}Rule id="{r3}">
        <{x}title>Complex</{x}title>
        <{x}complex-check operator="AND"><{x}check system="oval"/></{x}complex-check>
      </{x}Rule>
    </{x}Group>
  </{x}Group>
</{x}Benchmark>
""".format(x=x, ns=ns, P=P, r1=R.format("1.1.1"), r2=R.format("1.1.2"), r3=R.format("1.1.3"))


class Parser(unittest.TestCase):
    def test_prefixed_and_default_namespace_read_the_same(self):
        for prefix in ("xccdf:", ""):
            b = xccdf.Benchmark(benchmark(prefix).encode())
            self.assertEqual((b.id, b.version), ("xccdf_org.cisecurity.benchmarks_benchmark_T", "2.0.0"))
            self.assertEqual(b.profile_ids(), [P + "Level_1_-_Server"])
            self.assertEqual(b.selected(b.profiles[0]), [R.format("1.1.1"), R.format("1.1.2")])
            self.assertEqual(b.manual_numbers(), {"1.1.2"}, prefix)
            self.assertEqual(b.rule_title(R.format("1.1.1")), "Ensure A & B")
            self.assertEqual(b.family_titles(), {"1": "Initial / Setup"})
            self.assertEqual(b.rule_controls_v8(R.format("1.1.1")), ["4.1"])
            self.assertEqual(b.rule_prose(R.format("1.1.1"), "description"),
                             "Checks the doc (https://x.example/a). - one - two Line two <x>")
            self.assertEqual(b.rule_prose(R.format("1.1.2"), "rationale"), "")

    def test_profile_text_is_the_exact_source(self):
        raw = benchmark("xccdf:").encode()
        b = xccdf.Benchmark(raw)
        text = b.profile_text(b.profiles[0])
        self.assertTrue(text.startswith('<xccdf:Profile id="') and text.endswith("</xccdf:Profile>"))
        self.assertEqual(raw[:b.profiles_end()].decode().rstrip().endswith("</xccdf:Profile>"), True)

    def test_doctype_and_entities_are_refused(self):
        bomb = ('<?xml version="1.0"?><!DOCTYPE b [<!ENTITY a "aaaaaaaaaa">'
                '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><Benchmark>&b;</Benchmark>')
        with self.assertRaises(xccdf.XccdfError):
            xccdf.Benchmark(bomb.encode())
        with self.assertRaises(xccdf.XccdfError):
            xccdf.Benchmark(b"<Benchmark><unclosed></Benchmark>")
        with self.assertRaises(xccdf.XccdfError):
            xccdf.Benchmark(b'<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2"/>')


class CustomXccdf(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.csv = os.path.join(self.d, "exc.csv")
        with open(self.csv, "w") as f:
            f.write("scope,scope_value,level,role,rule\nos,demo,l1,,1.1.1\n")

    def build(self, prefix):
        bench = os.path.join(self.d, "b-{0}-xccdf.xml".format(prefix or "default"))
        with open(bench, "w") as f:
            f.write(benchmark(prefix))
        out = os.path.join(self.d, "custom-{0}.xml".format(prefix or "default"))
        conv.build_custom_xccdf(self.csv, bench, "web-01", "demo", "", [], out)
        with open(out) as f:
            return f.read(), benchmark(prefix)

    def test_tailored_profile_is_added_in_either_namespace_form(self):
        for prefix in ("xccdf:", ""):
            custom, source = self.build(prefix)
            tailored = P + "TAILORED_Level_1_-_Server"
            b = xccdf.Benchmark(custom.encode())
            self.assertEqual(b.profile_ids(), [P + "Level_1_-_Server", tailored])
            self.assertEqual(b.selected(b.profile(tailored)), [R.format("1.1.2")])
            self.assertEqual(text_title(b, tailored), "TAILORED L1 - Server (web-01)")
            # everything else is the benchmark byte for byte
            self.assertEqual(custom.replace("\n" + b.profile_text(b.profile(tailored)), "", 1), source)

    def test_family_comes_from_the_os_key_prefix_or_the_benchmark(self):
        self.assertEqual(conv.family_of("windows_server_2025"), "windows_server")
        self.assertEqual(conv.family_of("rhel9_v2_0_0"), "rhel")
        self.assertIsNone(conv.family_of("windows_11_enterprise_v3_0_0"))
        self.assertIsNone(conv.family_of("ubuntu_linux_22_04_lts_v1_0_0"))


def text_title(bench, profile_id):
    return xccdf.text_of(bench.child(bench.profile(profile_id), "title"))


if __name__ == "__main__":
    unittest.main()
