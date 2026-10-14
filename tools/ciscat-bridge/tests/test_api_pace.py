"""bin/ciscat-fleet.py: the bridge keeps to a share of the Wazuh API request limit."""
import importlib.util
import os
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
FLEET = os.path.join(HERE, "..", "bin", "ciscat-fleet.py")


def load():
    spec = importlib.util.spec_from_file_location("ciscat_fleet_pace", FLEET)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Pace(unittest.TestCase):
    def setUp(self):
        self.mod = load()
        self.now = [1000.0]
        self.slept = []

        def sleep(s):
            self.slept.append(s)
            self.now[0] += s
        # a clock of the test's own, in place of the time module of the loaded script
        self.mod.time = types.SimpleNamespace(monotonic=lambda: self.now[0], sleep=sleep)
        del self.mod._API_SENT[:]

    def test_the_requests_of_a_minute_stay_under_the_limit(self):
        self.mod.API["per_minute"] = 3
        for _ in range(3):
            self.mod.api_pace()
        self.assertEqual(self.slept, [])
        self.mod.api_pace()  # the 4th waits for the minute of the 1st
        self.assertEqual(len(self.slept), 1)
        self.assertGreaterEqual(self.now[0] - 1000.0, 60)

    def test_zero_means_no_limit(self):
        self.mod.API["per_minute"] = 0
        for _ in range(500):
            self.mod.api_pace()
        self.assertEqual(self.slept, [])

    def test_the_default_is_a_third_of_the_wazuh_default(self):
        self.mod.API.pop("per_minute", None)
        for _ in range(100):
            self.mod.api_pace()
        self.assertEqual(self.slept, [])
        self.mod.api_pace()
        self.assertEqual(len(self.slept), 1)


if __name__ == "__main__":
    unittest.main()
