"""packaging/kit/capture-ittest.sh and align-prod.sh: one-time alignment of a master."""
import glob
import hashlib
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.join(HERE, "..", "packaging", "kit")
DASH = "usr/share/wazuh-dashboard"

RPM = """#!/bin/sh
case "$*" in
    "-q wazuh-dashboard") echo wazuh-dashboard; exit 0 ;;
    "-q --qf"*) printf '%s' "$STUB_DASH_VERSION"; exit 0 ;;
    "-V wazuh-dashboard") [ -f "$STUB_VERIFY" ] && cat "$STUB_VERIFY"; exit 1 ;;
    "-qf "*) for u in $STUB_UNOWNED; do [ "$(basename "$2")" = "$u" ] && exit 1; done; exit 0 ;;
esac
exit 3
"""
# a plugin reinstall: the folder is replaced, custom images gone, stock PCI DSS texts
REINSTALL = """
W="$CISCAT_TEST_ROOT/usr/share/wazuh-dashboard/plugins/wazuh"
rm -rf "$W"
mkdir -p "$W/server/lib/reporting/summary-tables-definitions/agents" \
    "$W/server/lib/reporting/summary-tables-definitions/overview" "$W/server/controllers" \
    "$W/server/integration-files" "$W/common/compliance-requirements" "$W/public/assets" "$W/target/public"
echo bridge > "$W/server/lib/reporting/sca-report.js"
echo "PCI DSS 3.2.1" > "$W/server/integration-files/pci-requirements-pdfmake.js"
echo "PCI DSS 3.2.1" > "$W/common/compliance-requirements/pci-requirements.js"
for f in pci-request extended-information summary-tables-definitions/agents/index summary-tables-definitions/overview/index; do
    echo "exports.stock = 1;" > "$W/server/lib/reporting/$f.js"
done
printf 'class P {\n  addTimeRangeAndFilters(from, to, filters, timeZone) {\n    this.band = 1;\n  }\n}\n' > "$W/server/lib/reporting/printer.js"
printf 'function r(printer, array, agents, moduleID) {\n  printer.addVisualizations(array, agents, moduleID);\n}\n' > "$W/server/controllers/wazuh-reporting.js"
cat > "$W/target/public/wazuh.chunk.9.js" <<'JS'
const a=indexPatternId=>({id:"Wazuh-App-Overview-PCI-DSS-requirements",title:"Top 10 PCI DSS requirements",type:"line"});const b=indexPatternId=>({id:"Wazuh-App-Overview-PCI-DSS-Agents",title:"Top 10 agents by alerts count",type:"pie"});const c=indexPatternId=>({id:"Wazuh-App-Overview-PCI-DSS-Requirements-Agents-heatmap",title:"Last alerts",type:"heatmap"});const d=indexPatternId=>({id:"Wazuh-App-Overview-PCI-DSS-Requirements-by-agent",title:"Requirements by agent",type:"histogram"});
class R{async getVisualizationsFromDOM(){return[]}}
JS
[ -z "${STUB_BROKEN:-}" ] || sed -i 's/getVisualizationsFromDOM/somethingElse/' "$W/target/public/wazuh.chunk.9.js"
"""
# the prod plugin with its own PCI DSS report and dashboard (synthetic texts)
PROD_PLUGIN = {
    "server/lib/reporting/pci-request.js": "exports.site = 'site pci request';\n",
    "server/lib/reporting/extended-information.js": "exports.site = 'site sections';\n",
    "server/lib/reporting/summary-tables-definitions/agents/index.js": "exports.site = 1;\n",
    "server/lib/reporting/summary-tables-definitions/overview/index.js": "exports.site = 1;\n",
    "server/lib/reporting/printer.js": "exports.site = 1;\n",
    "server/controllers/wazuh-reporting.js": "exports.site = 1;\n",
    "target/public/wazuh.chunk.2.js": (
        'const a=indexPatternId=>({id:"Wazuh-App-Overview-PCI-DSS-requirements",title:"Site areas",'
        'type:"histogram",params:{x:"f(1)"}});const b=indexPatternId=>({id:"Wazuh-App-Overview-PCI-DSS-Agents",'
        'title:"Site systems",type:"histogram"});const c=indexPatternId=>({id:'
        '"Wazuh-App-Overview-PCI-DSS-Requirements-Agents-heatmap",title:"Site evidence",type:"table"});'
        'const d=indexPatternId=>({id:"Wazuh-App-Overview-PCI-DSS-Requirements-by-agent",'
        'title:"Site distribution",type:"table"});\n'),
}
CARRIED_VERIFY = "".join("S.5....T.    /usr/share/wazuh-dashboard/plugins/wazuh/" + f + "\n"
                         for f in PROD_PLUGIN)
SETUP = """#!/bin/sh
echo "$*" > "$CISCAT_TEST_ROOT/setup-args"
case "$*" in *--no-dashboard*) ;; *) """ + REINSTALL + """ ;; esac
[ -z "${STUB_TOUCH:-}" ] || echo changed >> "$CISCAT_TEST_ROOT/$STUB_TOUCH"
echo setup done
"""
INSTALLER = """#!/bin/sh
echo "$*" > "$CISCAT_TEST_ROOT/installer-args"
""" + REINSTALL
with open(os.path.join(KIT, "align-prod.sh")) as _f:
    _align = _f.read()
# a fleet stub that already waits on 429 (align-prod.sh leaves it as it is)
FLEET = ("#!/bin/sh\necho \"fleet $*\" >> \"$CISCAT_TEST_ROOT/fleet-calls\"\nexit 0\n" +
         _align[_align.index('NEW = """') + 9:_align.index('"""', _align.index('NEW = """') + 9)])


def write(path, text, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, mode)


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class Align(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        stubs = os.path.join(self.d, "stubs")
        write(os.path.join(stubs, "rpm"), RPM, 0o755)
        self.env = dict(os.environ, PATH=stubs + ":" + os.environ["PATH"],
                        STUB_DASH_VERSION="4.14.7-1", STUB_UNOWNED="")
        self.ittest = self.master("ittest")
        self.prod = self.master("prod")
        # the test master: configured bridge, a bridge build of the Wazuh plugin, a custom plugin
        it = self.ittest
        write(it + "/opt/ciscat/VERSION", "2.3.1\n")
        write(it + "/opt/ciscat/benchmarks/CIS_Win_v2.1.0-xccdf.xml", "xccdf")
        write(it + "/opt/ciscat/benchmarks/CIS_Win_v2.1.0-oval.xml", "oval")
        write(it + "/opt/ciscat/benchmarks/CIS_cpe-dictionary.xml", "cpe")
        write(it + "/opt/ciscat/license/license.xml", "LIC")
        write(it + "/opt/ciscat/etc/os-library.json", '{"it": 1}')
        write(it + "/opt/ciscat/etc/.ciscat_api_pass", "secret")
        write(it + "/opt/ciscat/etc/ciscat-orchestrator.conf", "api_user=ciscat-bridge")
        write(it + "/opt/ciscat/etc/ciscat-manifest.pub", "KEY")
        write(it + "/opt/ciscat/tailoring/exclusions/win.csv", "1.1.1")
        for l in ("ciscat-exclusions", "ciscat-schedule", "ciscat-targets", "ciscat-status"):
            write(it + "/var/ossec/etc/lists/" + l, l + ":x\n")
        write(it + "/" + DASH + "/plugins/wazuh/server/lib/reporting/sca-report.js", "bridge")
        write(it + "/" + DASH + "/plugins/customA/index.js", "custom A")
        write(it + "/" + DASH + "/plugins/stock/index.js", "stock")
        self.verify_it = os.path.join(self.d, "verify-it")
        write(self.verify_it, "S.5....T.    /usr/share/wazuh-dashboard/plugins/wazuh/target/a.js\n"
                              "missing     /usr/share/wazuh-dashboard/plugins/wazuh/target/b.js\n"
                              ".......T.    /usr/share/wazuh-dashboard/plugins/stock/index.js\n")
        # the production master: its own PCI DSS report settings and rules, an older benchmark
        pr = self.prod
        write(pr + "/" + DASH + "/data/wazuh/config/wazuh.yml", "customization.reports.header: Bank\n")
        write(pr + "/" + DASH + "/plugins/wazuh/target/a.js", "stock plugin")
        write(pr + "/" + DASH + "/plugins/wazuh/server/integration-files/pci-requirements-pdfmake.js",
              "PCI DSS 4.0.1 site texts")
        write(pr + "/" + DASH + "/plugins/wazuh/public/assets/custom/images/"
              "customization.logo.reports.png", "BANK LOGO")
        write(pr + "/var/ossec/etc/ossec.conf", "<ossec_config><ruleset><rule_dir>etc/rules</rule_dir>"
              "</ruleset></ossec_config>\n")
        write(pr + "/" + DASH + "/plugins/stock/index.js", "stock")
        write(pr + "/etc/wazuh-dashboard/opensearch_dashboards.yml", "server.port: 443\n")
        write(pr + "/var/ossec/etc/rules/local_rules.xml", "<pci/>")
        write(pr + "/var/ossec/etc/shared/pci-fim/agent.conf", "<agent_config/>")
        write(pr + "/var/ossec/etc/shared/ar.conf", "old")
        write(pr + "/opt/ciscat/benchmarks/CIS_Win_v2.0.0-xccdf.xml", "older")
        write(pr + "/var/ossec/etc/lists/ciscat-schedule", "prod schedule")
        self.verify_prod = os.path.join(self.d, "verify-prod")
        write(self.verify_prod, "S.5....T.    /usr/share/wazuh-dashboard/plugins/wazuh/server/"
                                "integration-files/pci-requirements-pdfmake.js\n")
        # the kit
        self.kit = os.path.join(self.d, "kit")
        os.makedirs(self.kit)
        for f in ("capture-ittest.sh", "align-prod.sh", "pci-keep.py"):
            shutil.copy(os.path.join(KIT, f), self.kit)
        with zipfile.ZipFile(os.path.join(self.kit, "ciscat-master-2.3.1.zip"), "w") as z:
            z.writestr("master/ciscat-master-setup.sh", SETUP)
            z.writestr("master/ciscat-bridge-install-2.3.1.sh", INSTALLER)
        plugin = os.path.join(self.kit, "wazuh-dashboard-plugins_wazuh_4.14.7-01_f7ccb4e (1).zip")
        write(plugin, "plugin zip")
        self.env["CISCAT_TEST_PLUGIN_SHA"] = sha(plugin)
        subprocess.run("sha256sum capture-ittest.sh align-prod.sh pci-keep.py ciscat-master-2.3.1.zip > SHA256SUMS",
                       shell=True, cwd=self.kit, check=True)

    def master(self, name):
        root = os.path.join(self.d, name)
        write(root + "/var/ossec/bin/wazuh-control", "#!/bin/sh\n", 0o755)
        os.makedirs(root + "/var/ossec/etc/lists", exist_ok=True)
        write(root + "/opt/ciscat/bin/ciscat-fleet.py", FLEET, 0o755)
        return root

    def run_sh(self, root, script, *args, verify=None, **env):
        e = dict(self.env, CISCAT_TEST_ROOT=root, STUB_VERIFY=verify or "", **env)
        return subprocess.run(["sh", script] + list(args), env=e, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, universal_newlines=True)

    def capture(self):
        r = self.run_sh(self.ittest, os.path.join(self.kit, "capture-ittest.sh"),
                        verify=self.verify_it, STUB_UNOWNED="customA")
        self.assertEqual(r.returncode, 0, r.stdout)
        tars = glob.glob(os.path.join(self.kit, "out", "ciscat-prod-2.3.1-*.tar.gz"))
        self.assertEqual(len(tars), 1, r.stdout)
        unpacked = os.path.join(self.d, "bundle")
        os.makedirs(unpacked, mode=0o700)
        with tarfile.open(tars[0]) as t:
            names = t.getnames()
            t.extractall(unpacked)
        return r, names, os.path.join(unpacked, "ciscat-prod-2.3.1")

    def align(self, bundle, *args, **env):
        return self.run_sh(self.prod, os.path.join(bundle, "align-prod.sh"), *args,
                           verify=self.verify_prod, **env)

    def read(self, root, path):
        with open(os.path.join(root, path)) as f:
            return f.read()

    def test_capture_takes_the_configuration_and_no_secret(self):
        r, names, _ = self.capture()
        files = {n.split("/", 1)[1] for n in names if "/" in n}
        for f in ("root/opt/ciscat/benchmarks/CIS_Win_v2.1.0-xccdf.xml",
                  "root/opt/ciscat/benchmarks/CIS_Win_v2.1.0-oval.xml",
                  "root/opt/ciscat/benchmarks/CIS_cpe-dictionary.xml",
                  "root/opt/ciscat/license/license.xml", "root/opt/ciscat/etc/os-library.json",
                  "root/opt/ciscat/tailoring/exclusions/win.csv",
                  "root/var/ossec/etc/lists/ciscat-exclusions",
                  "root/var/ossec/etc/lists/ciscat-schedule",
                  "root/var/ossec/etc/lists/ciscat-targets",
                  "wazuh-dashboard-plugins_wazuh_4.14.7-01_f7ccb4e.zip",
                  "dashboard-plugins/customA.tgz", "align-prod.sh", "ciscat-master-2.3.1.zip",
                  "ittest-info.txt", "SHA256SUMS"):
            self.assertIn(f, files, r.stdout)
        joined = "\n".join(names)
        for secret in (".ciscat_api_pass", "ciscat-orchestrator.conf", "ciscat-manifest",
                       "ciscat-status", "dashboard-plugins/stock", "dashboard-plugins/wazuh"):
            self.assertNotIn(secret, joined)

    def test_capture_stops_without_the_plugin_zip(self):
        for f in glob.glob(os.path.join(self.kit, "wazuh-dashboard-plugins_*")):
            os.remove(f)
        r = self.run_sh(self.ittest, os.path.join(self.kit, "capture-ittest.sh"),
                        verify=self.verify_it)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no dashboard plugin zip", r.stdout)

    def test_align_puts_the_files_and_keeps_pci_settings(self):
        _, _, bundle = self.capture()
        pr = self.prod
        yml = sha(pr + "/" + DASH + "/data/wazuh/config/wazuh.yml")
        r = self.align(bundle)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("RESULT: OK", r.stdout)
        self.assertEqual(self.read(pr, "opt/ciscat/benchmarks/CIS_Win_v2.1.0-oval.xml"), "oval")
        self.assertFalse(os.path.exists(pr + "/opt/ciscat/benchmarks/CIS_Win_v2.0.0-xccdf.xml"))
        self.assertEqual(self.read(pr, "opt/ciscat/license/license.xml"), "LIC")
        self.assertEqual(self.read(pr, "var/ossec/etc/lists/ciscat-schedule"), "ciscat-schedule:x\n")
        self.assertEqual(self.read(pr, DASH + "/plugins/customA/index.js"), "custom A")
        self.assertEqual(sha(pr + "/" + DASH + "/data/wazuh/config/wazuh.yml"), yml)
        self.assertEqual(self.read(pr, "setup-args").strip(), "--auto-assign")
        self.assertIn("fleet apply", self.read(pr, "fleet-calls"))
        self.assertTrue(os.path.exists(glob.glob(pr + "/opt/ciscat/install/2.3.1/master/"
                                                 "wazuh-dashboard-plugins_*.zip")[0]))
        backup = glob.glob(pr + "/opt/ciscat/backup/prod-before-*")[0]
        self.assertTrue(os.path.exists(backup + "/removed/opt/ciscat/benchmarks/CIS_Win_v2.0.0-xccdf.xml"))
        with tarfile.open(backup + "/files.tgz") as t:
            self.assertIn("var/ossec/etc/lists/ciscat-schedule", t.getnames())
            self.assertIn(DASH + "/data/wazuh/config/wazuh.yml", t.getnames())

    def test_align_stops_on_a_locally_changed_wazuh_plugin(self):
        _, _, bundle = self.capture()
        write(self.verify_prod, "S.5....T.    /usr/share/wazuh-dashboard/plugins/wazuh/server/"
                                "routes/wazuh-api.js\n")
        r = self.align(bundle)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("PCI DSS", r.stdout)
        self.assertIn("wazuh-api.js", r.stdout)
        self.assertEqual(self.read(self.prod, "var/ossec/etc/lists/ciscat-schedule"), "prod schedule")
        self.assertFalse(os.path.exists(self.prod + "/opt/ciscat/backup"))
        # everything else, the dashboard plugins left as they are
        r = self.align(bundle, "--no-dashboard-plugins")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(self.read(self.prod, "setup-args").strip(), "--auto-assign --no-dashboard")
        self.assertFalse(os.path.exists(self.prod + "/" + DASH + "/plugins/customA"))
        self.assertEqual(self.read(self.prod, "var/ossec/etc/lists/ciscat-schedule"),
                         "ciscat-schedule:x\n")

    def test_align_stops_on_a_different_custom_plugin_of_prod(self):
        _, _, bundle = self.capture()
        write(self.prod + "/" + DASH + "/plugins/customA/index.js", "prod own A")
        r = self.align(bundle, STUB_UNOWNED="customA")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("plugin customA of this dashboard has its own changes", r.stdout)
        self.assertEqual(self.read(self.prod, DASH + "/plugins/customA/index.js"), "prod own A")
        # the same plugin: nothing to do
        shutil.rmtree(self.prod + "/" + DASH + "/plugins/customA")
        shutil.copytree(self.ittest + "/" + DASH + "/plugins/customA",
                        self.prod + "/" + DASH + "/plugins/customA")
        r = self.align(bundle, STUB_UNOWNED="customA")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("custom plugin customA: already the same", r.stdout)

    def test_align_stops_on_another_dashboard_version(self):
        _, _, bundle = self.capture()
        r = self.align(bundle, STUB_DASH_VERSION="4.14.8-1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("captured on wazuh-dashboard 4.14.7-1", r.stdout)

    def test_align_reports_a_changed_protected_file(self):
        _, _, bundle = self.capture()
        r = self.align(bundle, STUB_TOUCH=DASH + "/data/wazuh/config/wazuh.yml")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("RESULT: CHECK", r.stdout)
        self.assertIn("wazuh.yml", r.stdout)

    def test_align_refuses_a_damaged_bundle(self):
        _, _, bundle = self.capture()
        write(bundle + "/root/opt/ciscat/license/license.xml", "other")
        r = self.align(bundle)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("damaged", r.stdout)

    def test_align_keeps_the_pci_dss_layer_of_the_site(self):
        _, _, bundle = self.capture()
        r = self.align(bundle)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("PCI DSS requirement texts customized here", r.stdout)
        wz = self.prod + "/" + DASH + "/plugins/wazuh/"
        self.assertTrue(os.path.exists(wz + "server/lib/reporting/sca-report.js"))  # new plugin
        self.assertEqual(self.read(wz, "server/integration-files/pci-requirements-pdfmake.js"),
                         "PCI DSS 4.0.1 site texts")
        self.assertEqual(self.read(wz, "public/assets/custom/images/customization.logo.reports.png"),
                         "BANK LOGO")
        self.assertIn("RESULT: OK", r.stdout)

    def test_align_dashboard_only_host(self):
        _, _, bundle = self.capture()
        shutil.rmtree(self.prod + "/var/ossec")
        r = self.align(bundle, "--dashboard-only")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("--plugin-sha256", self.read(self.prod, "installer-args"))
        self.assertFalse(os.path.exists(self.prod + "/setup-args"))
        # the CIS-CAT files of the master are not touched on a dashboard host
        self.assertTrue(os.path.exists(self.prod + "/opt/ciscat/benchmarks/CIS_Win_v2.0.0-xccdf.xml"))
        self.assertFalse(os.path.exists(self.prod + "/opt/ciscat/benchmarks/CIS_Win_v2.1.0-xccdf.xml"))
        wz = self.prod + "/" + DASH + "/plugins/wazuh/"
        self.assertEqual(self.read(wz, "public/assets/custom/images/customization.logo.reports.png"),
                         "BANK LOGO")
        self.assertEqual(self.read(wz, "server/integration-files/pci-requirements-pdfmake.js"),
                         "PCI DSS 4.0.1 site texts")

    def test_align_reports_a_changed_ruleset(self):
        _, _, bundle = self.capture()
        r = self.align(bundle, STUB_TOUCH="var/ossec/etc/rules/local_rules.xml")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("local_rules.xml", r.stdout)

    def prod_pci_plugin(self):
        for f, text in PROD_PLUGIN.items():
            write(self.prod + "/" + DASH + "/plugins/wazuh/" + f, text)
        write(self.verify_prod, CARRIED_VERIFY)

    def test_align_carries_the_pci_customizations_into_the_new_plugin(self):
        _, _, bundle = self.capture()
        self.prod_pci_plugin()
        r = self.align(bundle)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("carried into the new plugin by pci-keep.py", r.stdout)
        wz = self.prod + "/" + DASH + "/plugins/wazuh/"
        self.assertTrue(os.path.exists(wz + "server/lib/reporting/sca-report.js"))  # new plugin
        self.assertEqual(self.read(wz, "server/lib/reporting/extended-information.js"),
                         "exports.site = 'site sections';\n")
        self.assertIn("return; // this site's reports have no time range",
                      self.read(wz, "server/lib/reporting/printer.js"))
        self.assertIn("moduleID === 'pci'", self.read(wz, "server/controllers/wazuh-reporting.js"))
        chunk = self.read(wz, "target/public/wazuh.chunk.9.js")
        for title in ("Site areas", "Site systems", "Site evidence", "Site distribution"):
            self.assertIn(title, chunk)
        self.assertIn("siteAllVisualizationsFromDOM", chunk)
        self.assertEqual(self.read(wz, "public/assets/custom/images/customization.logo.reports.png"),
                         "BANK LOGO")
        self.assertIn("RESULT: OK", r.stdout)

    def test_the_old_plugin_comes_back_when_carrying_fails(self):
        _, _, bundle = self.capture()
        self.prod_pci_plugin()
        r = self.align(bundle, STUB_BROKEN="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("restored as it was", r.stdout)
        wz = self.prod + "/" + DASH + "/plugins/wazuh/"
        self.assertFalse(os.path.exists(wz + "server/lib/reporting/sca-report.js"))
        self.assertEqual(self.read(wz, "target/public/wazuh.chunk.2.js"),
                         PROD_PLUGIN["target/public/wazuh.chunk.2.js"])
        self.assertEqual(self.read(wz, "public/assets/custom/images/customization.logo.reports.png"),
                         "BANK LOGO")


if __name__ == "__main__":
    unittest.main()
