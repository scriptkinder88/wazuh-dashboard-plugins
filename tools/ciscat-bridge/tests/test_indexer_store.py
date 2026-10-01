"""Wazuh 5.0: the store backend in the dashboard store index of the Wazuh indexer."""
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "bin"))
sys.path.insert(0, HERE)
import ciscat_indexer  # noqa: E402
import ciscat_platform  # noqa: E402
import ciscat_store as store  # noqa: E402
from fake_indexer import FakeIndexer  # noqa: E402


def write_conf(d, url, password="s3cret", user="ciscat"):
    pw = os.path.join(d, "indexer.pass")
    with open(pw, "w") as f:
        f.write(password + "\n")
    conf = os.path.join(d, "indexer.json")
    with open(conf, "w") as f:
        json.dump({"url": url, "user": user, "password_file": pw}, f)
    return conf


class IndexerStore(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        self.fake = FakeIndexer()
        self.addCleanup(self.fake.stop)
        self.conf = write_conf(self.d, self.fake.serve())
        old = os.environ.get("CISCAT_INDEXER_CONF")
        os.environ["CISCAT_INDEXER_CONF"] = self.conf
        self.addCleanup(lambda: os.environ.__setitem__("CISCAT_INDEXER_CONF", old) if old
                        else os.environ.pop("CISCAT_INDEXER_CONF", None))
        store._INDEXERS.clear()
        self.lists = os.path.join(self.d, "lists-not-used")
        self.run_dir = os.path.join(self.d, "run")

    def test_missing_list_reads_empty_without_creating_anything(self):
        self.assertEqual(store.read_list(store.STATUS, self.lists), ({}, []))
        self.assertFalse(store.list_exists(store.EXCLUSIONS, self.lists))
        self.assertEqual(self.fake.writes(), [])
        self.assertFalse(os.path.exists(self.lists))

    def test_write_creates_the_index_like_the_dashboard_and_reads_back(self):
        recs = {"rhel7": {"v": 1, "group": "os-rhel7", "title": 'a:"b" è'}}
        self.assertEqual(store.write_list(store.OSKEYS, recs, self.lists), store.OSKEYS)
        index = self.fake.indices[ciscat_indexer.STORE_INDEX]["body"]
        self.assertEqual(index["settings"], {"index": {"hidden": True, "number_of_shards": 1}})
        self.assertEqual(index["mappings"]["properties"]["data"], {"type": "object", "enabled": False})
        doc = self.fake.doc(ciscat_indexer.STORE_INDEX, store.OSKEYS)
        self.assertEqual((doc["kind"], doc["key"], doc["data"], doc["updated_by"]),
                         ("list", store.OSKEYS, {"records": recs}, "ciscat-bridge"))
        self.assertRegex(doc["updated_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.000Z$")
        self.assertEqual(store.read_list(store.OSKEYS, self.lists), (recs, []))
        self.assertTrue(store.list_exists(store.OSKEYS))
        store.write_list(store.TARGETS, {}, self.lists)  # the index is created once
        self.assertEqual(len([c for c in self.fake.calls if c[:2] == ("PUT", "/" + ciscat_indexer.STORE_INDEX)]), 1)
        with self.assertRaises(store.StoreError):
            store.write_list(store.OSKEYS, {"bad key": {}})
        with self.assertRaises(store.StoreError):
            store.write_list("../x", {})

    def test_bad_records_written_by_hand_are_reported(self):
        store.write_list(store.SCHEDULE, {}, self.lists)
        src = self.fake.doc(ciscat_indexer.STORE_INDEX, store.SCHEDULE)
        src["data"]["records"] = {"jaaaaaaaaaaaa": {"type": "once"}, "j b": {}, "jbad": "text"}
        records, errors = store.read_list(store.SCHEDULE)
        self.assertEqual(list(records), ["jaaaaaaaaaaaa"])
        self.assertEqual(len(errors), 2)
        src["data"] = {"records": ["not", "an", "object"]}
        records, errors = store.read_list(store.SCHEDULE)
        self.assertEqual(records, {})
        self.assertIn("records missing or not an object", errors[0])

    def test_update_records_merges_and_retries_on_conflicts(self):
        store.update_records(store.STATUS, {"scheduler": {"last_tick": "t1"}}, self.lists, self.run_dir)
        self.fake.conflicts = 2  # two other writers in a row
        recs = store.update_records(store.STATUS, {"apply": {"state": "ok"}, "scheduler": {"jobs": 2}},
                                    self.lists, self.run_dir)
        stored, _ = store.read_list(store.STATUS)
        self.assertEqual(stored, recs)
        self.assertEqual(stored["scheduler"], {"v": 1, "last_tick": "t1", "jobs": 2})
        self.assertEqual(stored["apply"], {"v": 1, "state": "ok"})
        self.assertIn("other-writer", stored)  # the concurrent change is not lost
        conditional = [c for c in self.fake.calls if c[0] == "PUT" and "if_seq_no" in c[2]]
        self.assertEqual(len(conditional), 3)
        store.update_records(store.STATUS, {"apply": {"state": None}}, self.lists, self.run_dir,
                             remove=["other-writer"])
        stored, _ = store.read_list(store.STATUS)
        self.assertEqual(sorted(stored), ["apply", "scheduler"])
        self.assertEqual(stored["apply"], {"v": 1})

    def test_first_update_creates_and_gives_up_after_repeated_conflicts(self):
        self.fake.conflicts = 1
        store.update_records(store.STATUS, {"apply": {"state": "ok"}}, self.lists, self.run_dir)
        self.assertEqual(sorted(store.read_list(store.STATUS)[0]), ["apply", "other-writer"])
        self.fake.conflicts = store.CONFLICT_RETRIES
        with self.assertRaises(store.StoreError):
            store.update_records(store.STATUS, {"apply": {"state": "x"}}, self.lists, self.run_dir)

    def test_password_is_never_shown(self):
        ix = ciscat_indexer.Indexer.from_config(self.conf)
        self.assertNotIn("s3cret", repr(ix))
        bad = ciscat_indexer.Indexer(ix.url, "ciscat", "wrong")
        with self.assertRaises(ciscat_indexer.IndexerError) as ctx:
            bad.request("GET", "x/_doc/y")
        self.assertEqual(ctx.exception.status, 401)
        self.assertNotIn("wrong", str(ctx.exception))
        down = ciscat_indexer.Indexer("http://127.0.0.1:9", "u", "s3cret", timeout=2)
        with self.assertRaises(ciscat_indexer.IndexerError) as ctx:
            down.request("GET", "x")
        self.assertNotIn("s3cret", str(ctx.exception))

    def test_without_config_the_list_files_are_used(self):
        os.environ["CISCAT_INDEXER_CONF"] = os.path.join(self.d, "missing.json")
        self.assertIsNone(store.indexer())
        os.makedirs(self.lists)
        store.write_list(store.OSKEYS, {"rhel7": {"v": 1}}, self.lists)
        self.assertTrue(os.path.isfile(os.path.join(self.lists, store.OSKEYS)))


class ActiveResponseSetup(unittest.TestCase):
    def test_channels_and_monitors_are_created_once_and_repaired(self):
        fake = FakeIndexer()
        self.addCleanup(fake.stop)
        ix = ciscat_indexer.Indexer(fake.serve(), "ciscat", "s3cret")
        actions = ciscat_platform.AR_ACTIONS
        report = ciscat_indexer.ensure_active_response(ix, actions, ciscat_platform.TRIGGER_PATTERN)
        self.assertEqual(sum("created" in r for r in report), 8, report)
        by_name = {c["name"]: (cid, c) for cid, c in fake.channels.items()}
        cid, ch = by_name["ciscat-refresh-linux"]
        self.assertEqual((ch["config_type"], ch["active_response"]),
                         ("active_response", {"executable": "ciscat-refresh.sh", "type": "stateless",
                                              "location": "local"}))
        self.assertEqual(by_name["ciscat-assessment-windows"][1]["active_response"]["executable"],
                         "ciscat-assessment.cmd")
        (mon,) = [m for m in fake.monitors.values() if m["name"] == "ciscat-refresh-linux"]
        self.assertEqual(mon["monitor_type"], "active_response_monitor")
        self.assertEqual(mon["schedule"], {"period": {"interval": 1, "unit": "MINUTES"}})
        inp = mon["inputs"][0]["doc_level_input"]
        self.assertEqual(inp["indices"], ["wazuh-findings-v5-ciscat*"])
        self.assertEqual(inp["queries"][0]["query"], 'event.action:"ciscat-refresh-linux"')
        action = mon["triggers"][0]["document_level_trigger"]["actions"][0]
        self.assertEqual(action["destination_id"], cid)
        self.assertEqual(action["message_template"]["source"], "{{ctx.alerts.0.related_doc_ids}}")
        # second run: nothing written
        writes = len(fake.writes())
        report = ciscat_indexer.ensure_active_response(ix, actions, ciscat_platform.TRIGGER_PATTERN)
        self.assertTrue(all("unchanged" in r for r in report), report)
        self.assertEqual(len(fake.writes()), writes + 1)  # the monitor search only
        # a channel disabled by hand and a monitor pointing elsewhere are put back
        fake.channels[cid]["is_enabled"] = False
        (mid,) = [k for k, m in fake.monitors.items() if m["name"] == "ciscat-refresh-linux"]
        fake.monitors[mid]["triggers"][0]["document_level_trigger"]["actions"][0]["destination_id"] = "x"
        report = ciscat_indexer.ensure_active_response(ix, actions, ciscat_platform.TRIGGER_PATTERN)
        self.assertIn("channel ciscat-refresh-linux updated (ciscat-refresh.sh)", report)
        self.assertIn("monitor ciscat-refresh-linux updated", report)
        self.assertEqual((len(fake.channels), len(fake.monitors)), (4, 4))


class Platform(unittest.TestCase):
    def test_detection_and_paths(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        old = os.environ.pop("CISCAT_PLATFORM", None)
        self.addCleanup(lambda: old and os.environ.__setitem__("CISCAT_PLATFORM", old))
        self.assertEqual(ciscat_platform.detect(d), 4)
        os.makedirs(os.path.join(d, "var", "wazuh-manager"))
        self.assertEqual(ciscat_platform.detect(d), 5)
        os.environ["CISCAT_PLATFORM"] = "4"
        self.assertEqual(ciscat_platform.detect(d), 4)
        os.environ["CISCAT_PLATFORM"] = "6"
        with self.assertRaises(ValueError):
            ciscat_platform.detect(d)
        os.environ.pop("CISCAT_PLATFORM")
        self.assertEqual(ciscat_platform.shared_dir(5), "/var/wazuh-manager/etc/shared")
        self.assertEqual(ciscat_platform.manager_conf(5), "/var/wazuh-manager/etc/wazuh-manager.conf")
        self.assertEqual(ciscat_platform.owner(5), ("wazuh-manager", "wazuh-manager"))
        self.assertEqual(ciscat_platform.owner(4), ("wazuh", "wazuh"))

    def test_worker_detection(self):
        worker = "<wazuh_config><cluster><node_type>worker</node_type></cluster></wazuh_config>"
        self.assertTrue(ciscat_platform.is_worker(worker, 5))
        self.assertFalse(ciscat_platform.is_worker(worker, 4))  # 4.x: only an enabled cluster
        self.assertFalse(ciscat_platform.is_worker("<wazuh_config><cluster/></wazuh_config>", 5))
        self.assertTrue(ciscat_platform.is_worker(
            "<ossec_config><cluster><node_type>worker</node_type><disabled>no</disabled></cluster>", 4))

    def test_active_response_names(self):
        entry = {"family": "linux", "ar_bootstrap": "!ciscat-bootstrap-linux0",
                 "ar_refresh": "!ciscat-refresh-linux0"}
        self.assertIs(ciscat_platform.ar_entry_for(entry, 4), entry)
        self.assertEqual(ciscat_platform.ar_entry_for(entry, 5)["ar_refresh"], "ciscat-refresh-linux")
        win = {"family": "windows", "ar_bootstrap": "!ciscat-bootstrap0", "ar_assessment": "!site0"}
        self.assertEqual(ciscat_platform.ar_entry_for(win, 5),
                         dict(win, ar_bootstrap="ciscat-bootstrap-windows",
                              ar_assessment="ciscat-assessment-windows"))
        self.assertEqual(ciscat_platform.ar_action("site-refresh", "linux", "ar_refresh"), "site-refresh")
        self.assertEqual(set(ciscat_platform.LEGACY_AR.values()), set(ciscat_platform.AR_ACTIONS))


if __name__ == "__main__":
    unittest.main()
