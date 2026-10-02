import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "bin")
sys.path.insert(0, BIN)
import ciscat_store as store  # noqa: E402

STUB = """#!/usr/bin/env python3
import json, os, sys
with open(os.environ["STUB_LOG"], "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\\n")
"""


class Scheduler(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.lists = os.path.join(self.d, "lists")
        os.makedirs(self.lists)
        stub = os.path.join(self.d, "fleet-stub.py")
        with open(stub, "w") as f:
            f.write(STUB)
        self.calls_file = os.path.join(self.d, "calls.jsonl")
        self.env = dict(os.environ, CISCAT_LISTS_DIR=self.lists,
                        CISCAT_RUN_DIR=os.path.join(self.d, "run"),
                        CISCAT_LOG_DIR=os.path.join(self.d, "log"),
                        CISCAT_FLEET_CMD=stub, STUB_LOG=self.calls_file)

    def tick(self, now):
        r = subprocess.run([sys.executable, os.path.join(BIN, "ciscat-scheduler.py")],
                           env=dict(self.env, CISCAT_NOW=now), stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)
        return r.stdout

    def calls(self, history=False):
        """Fleet calls, without the daily history snapshot unless asked."""
        try:
            with open(self.calls_file) as f:
                calls = [json.loads(line) for line in f]
        except FileNotFoundError:
            return []
        return [c for c in calls if history or c[0] != "history"]

    def wait_calls(self, n):
        """Triggers are detached processes: wait for their calls to land."""
        deadline = time.time() + 5
        while time.time() < deadline:
            got = self.calls()
            if len(got) >= n:
                return got
            time.sleep(0.05)
        return self.calls()

    def status(self):
        return store.read_list(store.STATUS, self.lists)[0]

    def test_history_is_recorded_once_a_day(self):
        self.tick("2026-10-01T10:00:00")
        self.tick("2026-10-01T23:55:00")
        self.tick("2026-10-02T00:00:00")
        self.assertEqual([c for c in self.calls(history=True) if c[0] == "history"],
                         [["history", "--day", "2026-10-01"], ["history", "--day", "2026-10-02"]])
        self.assertEqual(self.status()["scheduler"]["last_history"], "2026-10-02")

    def test_sync_is_hourly(self):
        self.tick("2026-10-01T10:00:00")
        self.tick("2026-10-01T10:05:00")
        self.tick("2026-10-01T11:00:00")
        self.assertEqual([c[0] for c in self.calls()], ["sync", "sync"])

    def test_once_job_runs_at_its_tick_with_its_waves(self):
        job = store.validate_job({"type": "once", "at": "2026-10-01T10:07", "targets": ["rhel7"],
                                  "wave_size": 25, "wave_pause_s": 60, "label": "test"})
        store.write_list(store.SCHEDULE, {"jaaaaaaaaaaaa": job, "jbad": {"type": "x"}}, self.lists)
        self.tick("2026-10-01T10:05:00")
        self.assertEqual(self.status()["job-jaaaaaaaaaaaa"]["next_run"], "2026-10-01T10:07")
        out = self.tick("2026-10-01T10:10:00")
        self.assertIn("job rejected", out)
        calls = self.wait_calls(2)
        self.assertEqual(calls[1], ["trigger", "--targets", "rhel7", "--wave-size", "25",
                                    "--wave-pause", "60", "--job", "jaaaaaaaaaaaa"])
        st = self.status()["job-jaaaaaaaaaaaa"]
        self.assertEqual((st["state"], st["last_run"], st["next_run"]),
                         ("starting", "2026-10-01T10:10:00", ""))
        self.tick("2026-10-01T10:15:00")
        self.assertEqual(len(self.wait_calls(2)), 2)  # not again

    def test_pending_applies_run_once(self):
        reqs = {"r1700000000000aaaa": {"action": "apply", "requested_by": "alice"},
                "r1700000000001bbbb": {"action": "apply", "requested_by": "bob"},
                "r1700000000002cccc": {"action": "reboot"}}
        store.write_list(store.REQUESTS, reqs, self.lists)
        self.tick("2026-10-01T10:00:00")
        self.tick("2026-10-01T10:05:00")
        applies = [c for c in self.calls() if c[0] == "apply"]
        self.assertEqual(applies, [["apply", "--request", "r1700000000001bbbb"]])
        self.assertEqual(self.status()["requests"]["processed"],
                         ["r1700000000000aaaa", "r1700000000001bbbb"])

    def test_run_now_request_starts_after_apply(self):
        reqs = {"r1700000000000aaaa": {"action": "apply"},
                "r1700000000001bbbb": {"action": "run", "targets": ["windows_server_2025"],
                                       "wave_size": 10, "requested_by": "alice"}}
        store.write_list(store.REQUESTS, reqs, self.lists)
        self.tick("2026-10-01T10:00:00")
        calls = self.wait_calls(3)
        self.assertEqual(calls[1], ["apply", "--request", "r1700000000000aaaa"])
        self.assertEqual(calls[2], ["trigger", "--targets", "windows_server_2025", "--wave-size",
                                    "10", "--wave-pause", "300", "--job", "r1700000000001bbbb"])
        st = self.status()
        self.assertEqual(st["job-r1700000000001bbbb"]["requested_by"], "alice")
        self.assertIn("utc_offset", st["scheduler"])
        self.tick("2026-10-01T10:05:00")  # the run-now status is not a deleted job
        self.assertIn("job-r1700000000001bbbb", self.status())

    def test_missed_runs_are_reported_not_run(self):
        store.update_records(store.STATUS, {"scheduler": {"last_tick": "2026-10-01T02:00:00",
                                                          "last_sync": "2026-10-01T09:30:00"}},
                             self.lists, os.path.join(self.d, "run"))
        job = store.validate_job({"type": "weekly", "weekday": 3, "time": "03:00"})  # Thursday
        store.write_list(store.SCHEDULE, {"jbbbbbbbbbbbb": job}, self.lists)
        self.tick("2026-10-01T10:00:00")  # 2026-10-01 is a Thursday: 7 hours late
        self.assertEqual(self.calls(), [])
        st = self.status()["job-jbbbbbbbbbbbb"]
        self.assertEqual((st["missed"], st["next_run"]), (["2026-10-01T03:00"], "2026-10-08T03:00"))

    def test_running_job_is_not_started_twice_and_deleted_jobs_are_dropped(self):
        job = store.validate_job({"type": "once", "at": "2026-10-01T10:02"})
        store.write_list(store.SCHEDULE, {"jcccccccccccc": job}, self.lists)
        store.update_records(store.STATUS, {
            "scheduler": {"last_tick": "2026-10-01T10:00:00", "last_sync": "2026-10-01T09:59:00"},
            "job-jcccccccccccc": {"state": "running", "last_run": "2026-10-01T09:00:00+02:00"},
            "job-jdead00000000": {"state": "ok"}}, self.lists, os.path.join(self.d, "run"))
        out = self.tick("2026-10-01T10:05:00")
        self.assertIn("still running", out)
        self.assertEqual(self.calls(), [])
        self.assertNotIn("job-jdead00000000", self.status())


class SchedulerOnIndexer(Scheduler):
    """Wazuh 5.0: the same ticks with the lists in the indexer store."""

    def setUp(self):
        super().setUp()
        sys.path.insert(0, HERE)
        from fake_indexer import FakeIndexer
        from test_indexer_store import write_conf
        self.ix = FakeIndexer()
        conf = write_conf(self.d, self.ix.serve())
        self.env["CISCAT_INDEXER_CONF"] = conf
        old = os.environ.get("CISCAT_INDEXER_CONF")
        os.environ["CISCAT_INDEXER_CONF"] = conf
        store._INDEXERS.clear()

        def restore():
            if old is None:
                os.environ.pop("CISCAT_INDEXER_CONF", None)
            else:
                os.environ["CISCAT_INDEXER_CONF"] = old
            store._INDEXERS.clear()
            self.ix.stop()
        self.addCleanup(restore)

    def tearDown(self):
        self.assertEqual(os.listdir(self.lists), [])  # no list file written


if __name__ == "__main__":
    unittest.main()
