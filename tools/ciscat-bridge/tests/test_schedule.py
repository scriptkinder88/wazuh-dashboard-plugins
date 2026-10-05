import os
import sys
import unittest
from datetime import datetime as D

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
import ciscat_schedule as sc  # noqa: E402
import ciscat_store as st  # noqa: E402


def job(**kw):
    return st.validate_job(kw)


class Occurrences(unittest.TestCase):
    def test_once(self):
        j = job(type="once", at="2026-10-31T22:00")
        self.assertEqual(sc.occurrences(j, D(2026, 10, 31, 21, 55), D(2026, 10, 31, 22, 0)),
                         [D(2026, 10, 31, 22, 0)])
        # the window is (start, end]: a tick exactly at the time does not run it twice
        self.assertEqual(sc.occurrences(j, D(2026, 10, 31, 22, 0), D(2026, 10, 31, 22, 5)), [])
        self.assertIsNone(sc.next_run(j, D(2026, 11, 1)))

    def test_monthly_day_is_clamped_to_short_months(self):
        j = job(type="monthly", day=31, time="02:00")
        got = sc.occurrences(j, D(2026, 1, 1), D(2026, 4, 30, 23, 59))
        self.assertEqual(got, [D(2026, 1, 31, 2), D(2026, 2, 28, 2), D(2026, 3, 31, 2),
                               D(2026, 4, 30, 2)])

    def test_monthly_from_the_end(self):
        j = job(type="monthly", day=-3, time="23:30")  # third-last day
        self.assertEqual(sc.occurrences(j, D(2028, 2, 1), D(2028, 3, 31, 23, 59)),
                         [D(2028, 2, 27, 23, 30), D(2028, 3, 29, 23, 30)])  # 2028 is leap
        self.assertEqual(sc.next_run(j, D(2026, 12, 29, 23, 30)), D(2027, 1, 29, 23, 30))

    def test_weekly(self):
        j = job(type="weekly", weekday=0, time="01:15")  # Mondays
        self.assertEqual(sc.occurrences(j, D(2026, 9, 28, 1, 15), D(2026, 10, 12, 1, 15)),
                         [D(2026, 10, 5, 1, 15), D(2026, 10, 12, 1, 15)])
        self.assertEqual(sc.next_run(j, D(2026, 9, 30, 12)), D(2026, 10, 5, 1, 15))


class Due(unittest.TestCase):
    def test_runs_once_per_tick_and_skips_disabled(self):
        j = job(type="weekly", weekday=2, time="10:00")
        self.assertEqual(sc.due(j, D(2026, 9, 30, 9, 55), D(2026, 9, 30, 10, 0)), (True, []))
        self.assertEqual(sc.due(j, D(2026, 9, 30, 10, 0), D(2026, 9, 30, 10, 5)), (False, []))
        j["enabled"] = False
        self.assertEqual(sc.due(j, D(2026, 9, 30, 9, 55), D(2026, 9, 30, 10, 0)), (False, []))

    def test_late_tick_catches_up_only_recent_occurrences(self):
        j = job(type="once", at="2026-09-30T10:00")
        self.assertEqual(sc.due(j, D(2026, 9, 30, 9), D(2026, 9, 30, 15, 59)), (True, []))
        run, missed = sc.due(j, D(2026, 9, 30, 9), D(2026, 9, 30, 16, 1))
        self.assertEqual((run, missed), (False, [D(2026, 9, 30, 10)]))


if __name__ == "__main__":
    unittest.main()
