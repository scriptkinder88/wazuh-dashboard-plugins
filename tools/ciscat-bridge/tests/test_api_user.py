"""packaging/master/ciscat-api-user.py: login check of the new bridge user."""
import importlib.util
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "packaging", "master", "ciscat-api-user.py")


def load():
    os.environ["CISCAT_ETC_DIR"] = tempfile.mkdtemp()
    spec = importlib.util.spec_from_file_location("ciscat_api_user", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class LoginCheck(unittest.TestCase):
    def setUp(self):
        self.mod = load()
        self.calls = []
        self.mod.time.sleep = lambda s: None

    def fake(self, refusals):
        def call(method, path, token=None, body=None, basic=None):
            self.calls.append(path)
            if path.startswith("/security/user/authenticate"):
                return "tok%d" % len(self.calls)
            if path.startswith("/groups") and refusals:
                refusals.pop()
                raise SystemExit('STOP: API GET /groups?limit=1: 401 {"title": "Unauthorized", '
                                 '"detail": "Invalid token"}')
            return {}
        self.mod.call = call

    def test_a_token_revoked_in_the_same_second_is_retried(self):
        self.fake([1, 1])
        self.mod.check_login("secret")
        self.assertEqual(self.calls.count("/security/user/authenticate?raw=true"), 3)
        self.assertIn("/agents?limit=1&select=id", self.calls)

    def test_still_refused_stops(self):
        self.fake([1] * 10)
        with self.assertRaises(SystemExit):
            self.mod.check_login("secret", tries=3)
        self.assertEqual(self.calls.count("/security/user/authenticate?raw=true"), 3)

    def test_another_error_is_not_retried(self):
        def call(method, path, token=None, body=None, basic=None):
            self.calls.append(path)
            raise SystemExit("STOP: API POST /security/user/authenticate?raw=true: 500 boom")
        self.mod.call = call
        with self.assertRaises(SystemExit):
            self.mod.check_login("secret")
        self.assertEqual(len(self.calls), 1)


if __name__ == "__main__":
    unittest.main()
