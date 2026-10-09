import csv
import json
import io
import os
import re
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
import ciscat_store as s  # noqa: E402

# Wazuh 4.14 framework/wazuh/core/cdb_list.py validate_cdb_list
WAZUH_CDB_LINE = re.compile(r'(?:^"([\w\-: ]+?)"|^[^:"\s]+):(?:"([\w\-: ]*?)"$|[^:\"]*$)')


def exclusion(**kw):
    rec = {"os_key": "rhel7", "scope": "os", "scope_value": "", "level": "L1", "role": "Server",
           "rule": "1.1.1.1", "reason": "Kernel module needed: \"cramfs\", see: KB-1"}
    rec.update(kw)
    return s.validate_exclusion(rec)


class Encoding(unittest.TestCase):
    def test_round_trip_keeps_any_text(self):
        obj = {"t": 'Ensure "x" is set: 24 or more | a,b è', "n": 3}
        self.assertEqual(s.decode(s.encode(obj)), obj)

    def test_rendered_lists_pass_wazuh_validation(self):
        rec = exclusion()
        text = s.render_list({s.exclusion_key(rec): rec, "1.1.1.1": {"t": 'a:"b"'}})
        for line in text.splitlines():
            self.assertRegex(line, WAZUH_CDB_LINE)

    def test_parse_reports_bad_lines_and_keeps_good_ones(self):
        good = s.encode({"a": 1})
        records, errors = s.parse_list("k1:{}\n\nbad line\nk2:not base64!\n".format(good))
        self.assertEqual(records, {"k1": {"a": 1}})
        self.assertEqual(len(errors), 2)

    def test_list_names_are_confined(self):
        for name in ("../etc/ossec.conf", "other-list", "ciscat-x/../../y"):
            with self.assertRaises(s.StoreError):
                s.list_path(name)
        with self.assertRaises(s.StoreError):
            s.bench_list_name("../x")

    def test_atomic_write_and_read(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        rec = exclusion()
        s.write_list(s.EXCLUSIONS, {s.exclusion_key(rec): rec}, lists_dir=d)
        self.assertEqual(oct(os.stat(os.path.join(d, s.EXCLUSIONS)).st_mode & 0o777), "0o660")
        records, errors = s.read_list(s.EXCLUSIONS, lists_dir=d)
        self.assertEqual((records, errors), ({s.exclusion_key(rec): rec}, []))
        self.assertEqual([f for f in os.listdir(d) if f.startswith(".")], [])


class Exclusions(unittest.TestCase):
    def test_scope_values_are_normalized(self):
        self.assertEqual(exclusion(scope="os", scope_value="whatever")["scope_value"], "rhel7")
        self.assertEqual(exclusion(scope="global")["scope_value"], "all")
        self.assertEqual(exclusion(scope="HOST", scope_value="web-01")["scope"], "host")

    def test_rejects_invalid_records(self):
        bad = [dict(scope="group", scope_value="x"), dict(scope="host", scope_value="a b"),
               dict(rule="1.1.x"), dict(level="L3"), dict(os_key="RHEL 7"),
               dict(scope="host", scope_value="")]
        for kw in bad:
            with self.assertRaises(s.StoreError, msg=kw):
                exclusion(**kw)

    def test_key_identifies_the_exclusion(self):
        a = exclusion(scope="host", scope_value="Web-01")
        b = exclusion(scope="host", scope_value="web-01", reason="other")
        self.assertEqual(s.exclusion_key(a), s.exclusion_key(b))
        self.assertNotEqual(s.exclusion_key(a), s.exclusion_key(exclusion(rule="1.1.1.2")))
        valid, errors = s.validate_exclusions({"e0000000000000000": a, "_empty": {"v": 1}})
        self.assertEqual(valid, {})
        self.assertEqual(len(errors), 1)
        self.assertIn("key does not match", errors[0])

    def test_csv_round_trip_with_csv_to_custom_xccdf_layout(self):
        recs = {}
        for kw in (dict(), dict(scope="host", scope_value="web-01", rule="2.2.1"),
                   dict(scope="app_group", scope_value="app-sap", level="ALL", role="")):
            r = exclusion(**kw)
            recs[s.exclusion_key(r)] = r
        recs[s.exclusion_key(exclusion(os_key="debian12"))] = exclusion(os_key="debian12")
        rows = s.exclusions_to_csv_rows(recs, "rhel7")
        self.assertEqual(rows[0], s.CSV_HEADER)
        self.assertEqual(len(rows), 4)
        buf = io.StringIO()
        csv.writer(buf).writerows(rows)
        back, errors = s.exclusions_from_csv_rows(list(csv.reader(io.StringIO(buf.getvalue()))),
                                                  "rhel7")
        self.assertEqual(errors, [])
        self.assertEqual(set(back), {k for k, r in recs.items() if r["os_key"] == "rhel7"})

    def test_maps_old_composer_scopes(self):
        rows = [["scope", "scope_value", "level", "role", "rule", "reason"],
                ["group", "app-sap", "L1", "Server", "1.1", "x"],
                ["host_list", "web-01; web-02,web-03", "L1", "Server", "1.2", "y"]]
        records, errors = s.exclusions_from_csv_rows(rows, "rhel7")
        self.assertEqual(errors, [])
        got = sorted((r["scope"], r["scope_value"], r["rule"]) for r in records.values())
        self.assertEqual(got, [("app_group", "app-sap", "1.1"), ("host", "web-01", "1.2"),
                               ("host", "web-02", "1.2"), ("host", "web-03", "1.2")])

    def test_reads_legacy_positional_csv(self):
        rows = [["# comment"], ["os", "rhel7", "l1", "1.1.1.1", "why", "T-1", "me"],
                ["bogus", "x", "l1", "1.1"]]
        records, errors = s.exclusions_from_csv_rows(rows, "rhel7")
        (rec,) = records.values()
        self.assertEqual((rec["rule"], rec["ticket"], rec["owner"]), ("1.1.1.1", "T-1", "me"))
        self.assertEqual(len(errors), 1)


class Jobs(unittest.TestCase):
    def test_valid_jobs(self):
        once = s.validate_job({"type": "once", "at": "2026-10-31T22:00", "targets": ["rhel7"]})
        self.assertEqual((once["wave_size"], once["wave_pause_s"], once["enabled"]), (50, 300, True))
        self.assertEqual(s.validate_job({"type": "monthly", "day": -3, "time": "02:30"})["day"], -3)
        self.assertEqual(s.validate_job({"type": "weekly", "weekday": 6, "time": "23:59"})
                         ["targets"], ["*"])

    def test_invalid_jobs(self):
        for rec in ({"type": "cron"}, {"type": "once", "at": "2026-02-30T10:00"},
                    {"type": "once", "at": "tomorrow"}, {"type": "monthly", "day": 0, "time": "01:00"},
                    {"type": "monthly", "day": -29, "time": "01:00"},
                    {"type": "weekly", "weekday": 7, "time": "01:00"},
                    {"type": "weekly", "weekday": 1, "time": "24:00"},
                    {"type": "once", "at": "2026-10-31T22:00", "targets": ["../x"]},
                    {"type": "once", "at": "2026-10-31T22:00", "wave_size": 0},
                    {"type": "once", "at": "2026-10-31T22:00", "enabled": "yes"}):
            with self.assertRaises(s.StoreError, msg=rec):
                s.validate_job(rec)

    def test_run_scope_is_os_keys_agents_or_groups(self):
        base = {"type": "weekly", "weekday": 1, "time": "01:00"}
        job = s.validate_job(dict(base, agents=["017", "003", "003"]))
        self.assertEqual((job["targets"], job["agents"], job["groups"]), ([], ["003", "017"], []))
        job = s.validate_job(dict(base, groups=["web-prod", "os-rhel7"], targets=[]))
        self.assertEqual((job["targets"], job["groups"]), ([], ["os-rhel7", "web-prod"]))
        job = s.validate_job(base)
        self.assertEqual((job["targets"], job["agents"], job["groups"]), (["*"], [], []))
        for bad in ({"agents": ["000"]}, {"agents": ["3"]}, {"agents": ["003; id"]},
                    {"agents": "003"}, {"groups": ["ciscat-rhel7-base"]}, {"groups": ["a b"]},
                    {"agents": ["003"], "groups": ["x"]}, {"agents": ["003"], "targets": ["*"]},
                    {"targets": []},
                    {"agents": ["{0:03d}".format(i) for i in range(1, 1003)]}):
            with self.assertRaises(s.StoreError, msg=bad):
                s.validate_job(dict(base, **bad))
        run = s.validate_request({"action": "run", "agents": ["003"]})
        self.assertEqual((run["targets"], run["agents"], run["groups"]), ([], ["003"], []))

    def test_bridge_groups_are_not_targets(self):
        with self.assertRaises(s.StoreError):
            s.validate_target({"group": "ciscat-windows_server_2025-base"})

    def test_requests(self):
        self.assertEqual(s.validate_request({"action": "apply"})["action"], "apply")
        with self.assertRaises(s.StoreError):
            s.validate_request({"action": "rm -rf"})
        run = s.validate_request({"action": "run", "targets": ["rhel7"], "wave_size": 5})
        self.assertEqual((run["targets"], run["wave_size"], run["wave_pause_s"]), (["rhel7"], 5, 300))
        with self.assertRaises(s.StoreError):
            s.validate_request({"action": "run", "targets": ["$(id)"]})


class SharedVectors(unittest.TestCase):
    def test_typescript_vectors_are_current(self):
        sys.path.insert(0, os.path.dirname(__file__))
        import make_vectors
        # compared as data: the repository formatter may re-indent the file
        with open(make_vectors.OUT, encoding="utf-8") as f:
            self.assertEqual(json.load(f), make_vectors.build(),
                             "run tools/ciscat-bridge/tests/make_vectors.py")


if __name__ == "__main__":
    unittest.main()
