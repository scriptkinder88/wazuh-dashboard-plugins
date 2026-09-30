"""Minimal in-memory stand-in for the Wazuh server API endpoints the bridge uses (tests only)."""
import json
import os
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeWazuh:
    def __init__(self, shared_dir, agents):
        # agents: {id: {"name":..., "status":..., "group": [...]}}
        self.shared_dir = shared_dir
        self.agents = agents
        self.groups = {g for a in agents.values() for g in a["group"]} | {"default"}
        self.calls = []
        self.ar = []
        self.reject_auth = False
        for g in self.groups:
            os.makedirs(os.path.join(shared_dir, g), exist_ok=True)

    def handle(self, method, path, query, body):
        self.calls.append((method, path))
        if path == "/security/user/authenticate":
            return "fake-token", True
        if method == "GET" and path.startswith("/groups/") and path.endswith("/agents"):
            g = urllib.parse.unquote(path.split("/")[2])
            items = [dict(id=i, **a) for i, a in sorted(self.agents.items()) if g in a["group"]]
            off, lim = int(query.get("offset", 0)), int(query.get("limit", 500))
            return {"affected_items": items[off:off + lim], "total_affected_items": len(items)}, False
        if method == "GET" and path == "/groups":
            return {"affected_items": [{"name": g} for g in sorted(self.groups)]}, False
        if method == "POST" and path == "/groups":
            self.groups.add(body["group_id"])
            os.makedirs(os.path.join(self.shared_dir, body["group_id"]), exist_ok=True)
            return {}, False
        if method == "DELETE" and path == "/groups":
            for g in query["groups_list"].split(","):
                assert not any(g in a["group"] for a in self.agents.values()), "group in use: " + g
                self.groups.discard(g)
            return {}, False
        if path.startswith("/agents/") and "/group/" in path:
            _, _, aid, _, g = path.split("/")
            assert g in self.groups, "unknown group " + g
            grp = self.agents[aid]["group"]
            if method == "PUT" and g not in grp:
                grp.append(g)
            if method == "DELETE" and g in grp:
                grp.remove(g)
            return {}, False
        if method == "PUT" and path == "/active-response":
            ids = query["agents_list"].split(",")
            self.ar.append((body["command"], ids))
            return {"total_affected_items": len(ids), "total_failed_items": 0}, False
        raise AssertionError("unexpected call {} {}".format(method, path))

    def serve(self):
        fake = self

        class H(BaseHTTPRequestHandler):
            def _do(self):
                u = urllib.parse.urlparse(self.path)
                q = dict(urllib.parse.parse_qsl(u.query))
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n)) if n else None
                if fake.reject_auth and u.path == "/security/user/authenticate":
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b'{"title": "Unauthorized"}')
                    return
                try:
                    data, raw = fake.handle(self.command, u.path, q, body)
                    payload = data.encode() if raw else json.dumps({"error": 0, "data": data}).encode()
                    self.send_response(200)
                except AssertionError as e:
                    payload = json.dumps({"error": 1, "message": str(e)}).encode()
                    self.send_response(400)
                self.end_headers()
                self.wfile.write(payload)
            do_GET = do_POST = do_PUT = do_DELETE = _do

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return "http://127.0.0.1:{}".format(self.server.server_address[1])
