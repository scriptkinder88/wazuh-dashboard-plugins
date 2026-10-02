"""Minimal in-memory stand-in for the Wazuh indexer endpoints the bridge uses on Wazuh 5.0
(tests only): documents with seq_no/primary_term, data stream bulk create, the SCA states search,
Notifications configs and Alerting monitors."""
import base64
import itertools
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# fields the wazuh-findings-v5* template accepts (strict mapping), as used by the bridge
FINDINGS_FIELDS = {"@timestamp", "event.action", "event.kind", "event.module", "event.dataset",
                   "rule.name", "wazuh.agent.id", "wazuh.agent.name", "wazuh.agent.groups",
                   "wazuh.integration.name"}


def flatten(doc, prefix=""):
    out = {}
    for k, v in doc.items():
        if isinstance(v, dict):
            out.update(flatten(v, prefix + k + "."))
        else:
            out[prefix + k] = v
    return out


class HttpError(Exception):
    def __init__(self, status, body):
        super().__init__(status)
        self.status, self.body = status, body


def error(status, kind, reason=""):
    return HttpError(status, {"error": {"type": kind, "reason": reason}, "status": status})


class FakeIndexer:
    def __init__(self, user="ciscat", password="s3cret"):
        self.auth = "Basic " + base64.b64encode("{0}:{1}".format(user, password).encode()).decode()
        self.indices = {}        # name -> {"body": create body, "docs": {id: (source, seq_no)}}
        self.streams = {}        # data stream -> [documents]
        self.seq = itertools.count(0)
        self.calls = []
        self.conflicts = 0       # next N conditional store writes fail as if another writer won
        self.reject_bulk = set()  # agent ids whose trigger documents are rejected
        self.sca_states = []     # [(agent id, policy id, result)]
        self.channels = {}       # id -> config
        self.monitors = {}       # id -> monitor
        self.ids = itertools.count(1)
        self.lock = threading.Lock()

    # ---------------------------------------------------------------- helpers for tests
    def doc(self, index, doc_id):
        entry = self.indices.get(index, {}).get("docs", {}).get(doc_id)
        return entry[0] if entry else None

    def writes(self):
        return [c for c in self.calls if c[0] in ("PUT", "POST", "DELETE")]

    # ---------------------------------------------------------------- dispatch
    def handle(self, method, path, query, body):
        parts = [urllib.parse.unquote(p) for p in path.strip("/").split("/")]
        if parts[:2] == ["_plugins", "_notifications"]:
            return self.notifications(method, parts[2:], query, body)
        if parts[:2] == ["_plugins", "_alerting"]:
            return self.alerting(method, parts[2:], body)
        index = parts[0]
        if len(parts) == 1:
            if method == "HEAD":
                if index not in self.indices:
                    raise HttpError(404, {})
                return 200, {}
            if method == "PUT":
                if index in self.indices:
                    raise error(400, "resource_already_exists_exception", index)
                self.indices[index] = {"body": body, "docs": {}}
                return 200, {"acknowledged": True, "index": index}
        if parts[1:] == ["_bulk"] and method == "POST":
            return self.bulk(index, body)
        if parts[1:] == ["_search"] and method == "POST":
            return self.search_sca(index, body)
        if len(parts) == 3 and parts[1] in ("_doc", "_create"):
            return self.document(method, index, parts[1], parts[2], query, body)
        raise error(400, "unexpected", "{0} {1}".format(method, path))

    def document(self, method, index, op, doc_id, query, body):
        docs = self.indices.get(index, {}).get("docs")
        if method == "GET":
            if docs is None:
                raise error(404, "index_not_found_exception", index)
            if doc_id not in docs:
                raise HttpError(404, {"_index": index, "_id": doc_id, "found": False})
            src, seq = docs[doc_id]
            return 200, {"_index": index, "_id": doc_id, "found": True, "_seq_no": seq,
                         "_primary_term": 1, "_source": src}
        if method != "PUT":
            raise error(400, "unexpected", method)
        if docs is None:  # the bridge creates the store index first
            raise error(404, "index_not_found_exception", index)
        strict = (self.indices[index]["body"] or {}).get("mappings", {})
        extra = set(body) - set(strict.get("properties", {}))
        if strict.get("dynamic") == "strict" and extra:
            raise error(400, "strict_dynamic_mapping_exception", ",".join(sorted(extra)))
        conditional = op == "_create" or "if_seq_no" in query
        if conditional and self.conflicts:
            self.conflicts -= 1
            # another writer got there first: its change is kept
            if doc_id in docs:
                src, _ = docs[doc_id]
                src = json.loads(json.dumps(src))
                src["data"]["records"]["other-writer"] = {"v": 1}
            else:
                src = {"kind": "list", "key": doc_id, "data": {"records": {"other-writer": {"v": 1}}},
                       "updated_by": "other", "updated_at": "2026-10-01T00:00:00.000Z"}
            docs[doc_id] = (src, next(self.seq))
            raise error(409, "version_conflict_engine_exception", doc_id)
        if op == "_create" and doc_id in docs:
            raise error(409, "version_conflict_engine_exception", doc_id)
        if "if_seq_no" in query:
            if doc_id not in docs or docs[doc_id][1] != int(query["if_seq_no"]) or \
                    int(query.get("if_primary_term", 0)) != 1:
                raise error(409, "version_conflict_engine_exception", doc_id)
        seq = next(self.seq)
        docs[doc_id] = (body, seq)
        return 200, {"_index": index, "_id": doc_id, "_seq_no": seq, "_primary_term": 1,
                     "result": "updated"}

    def bulk(self, stream, lines):
        items = []
        for action, doc in zip(lines[0::2], lines[1::2]):
            if list(action) != ["create"]:  # data streams accept create only
                items.append({"index": {"status": 400, "error": {"reason": "create only"}}})
                continue
            fields = set(flatten(doc))
            if fields - FINDINGS_FIELDS:
                items.append({"create": {"status": 400, "error": {
                    "type": "strict_dynamic_mapping_exception",
                    "reason": ",".join(sorted(fields - FINDINGS_FIELDS))}}})
            elif doc["wazuh"]["agent"]["id"] in self.reject_bulk:
                items.append({"create": {"status": 429, "error": {"reason": "rejected"}}})
            else:
                self.streams.setdefault(stream, []).append(doc)
                items.append({"create": {"status": 201}})
        return 200, {"errors": any(i[next(iter(i))]["status"] >= 300 for i in items),
                     "items": items}

    def search_sca(self, index, body):
        assert index == "wazuh-states-sca*", index
        policy = body["query"]["bool"]["filter"][0]["term"]["policy.id"]
        agg = {}
        for aid, pid, result in self.sca_states:
            if pid == policy:
                agg.setdefault(aid, {}).setdefault(result, 0)
                agg[aid][result] += 1
        buckets = [{"key": aid, "doc_count": sum(r.values()), "results": {"buckets": [
            {"key": k, "doc_count": v} for k, v in sorted(r.items())]}} for aid, r in sorted(agg.items())]
        return 200, {"hits": {"total": {"value": 0}, "hits": []},
                     "aggregations": {"agents": {"buckets": buckets}}}

    def notifications(self, method, parts, query, body):
        if parts == ["configs"] and method == "GET":
            return 200, {"start_index": 0, "total_hits": len(self.channels), "config_list": [
                {"config_id": cid, "last_updated_time_ms": 1, "created_time_ms": 1, "config": cfg}
                for cid, cfg in sorted(self.channels.items())]}
        if parts == ["configs"] and method == "POST":
            cid = "ch{0}".format(next(self.ids))
            self.channels[cid] = body["config"]
            return 200, {"config_id": cid}
        if len(parts) == 2 and parts[0] == "configs" and method == "PUT":
            if parts[1] not in self.channels:
                raise error(404, "not_found", parts[1])
            self.channels[parts[1]] = body["config"]
            return 200, {"config_id": parts[1]}
        raise error(400, "unexpected", "/".join(parts))

    def alerting(self, method, parts, body):
        if parts == ["monitors", "_search"] and method == "POST":
            names = {c["match_phrase"]["monitor.name"] for c in body["query"]["bool"]["should"]}
            hits = [{"_id": mid, "_seq_no": 0, "_primary_term": 1, "_source": {"monitor": dict(
                m, last_update_time=1, schema_version=5, triggers=[
                    {"document_level_trigger": dict(t["document_level_trigger"], id="t-" + mid)}
                    for t in m["triggers"]])}}
                for mid, m in sorted(self.monitors.items()) if m["name"] in names]
            return 200, {"hits": {"total": {"value": len(hits)}, "hits": hits}}
        if parts == ["monitors"] and method == "POST":
            mid = "mon{0}".format(next(self.ids))
            self.monitors[mid] = body
            return 200, {"_id": mid, "monitor": body}
        if len(parts) == 2 and parts[0] == "monitors" and method == "PUT":
            if parts[1] not in self.monitors:
                raise error(404, "not_found", parts[1])
            self.monitors[parts[1]] = body
            return 200, {"_id": parts[1]}
        raise error(400, "unexpected", "/".join(parts))

    # ---------------------------------------------------------------- server
    def serve(self):
        fake = self

        class H(BaseHTTPRequestHandler):
            def _do(self):
                u = urllib.parse.urlparse(self.path)
                q = dict(urllib.parse.parse_qsl(u.query))
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n).decode() if n else ""
                if self.headers.get("Content-Type") == "application/x-ndjson":
                    body = [json.loads(line) for line in raw.splitlines() if line.strip()]
                else:
                    body = json.loads(raw) if raw else None
                with fake.lock:
                    fake.calls.append((self.command, u.path, q))
                    try:
                        if self.headers.get("Authorization") != fake.auth:
                            raise error(401, "security_exception", "Unauthorized")
                        status, data = fake.handle(self.command, u.path, q, body)
                    except HttpError as e:
                        status, data = e.status, e.body
                payload = json.dumps(data).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(0 if self.command == "HEAD" else len(payload)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)
            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _do

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return "http://127.0.0.1:{}".format(self.server.server_address[1])

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
