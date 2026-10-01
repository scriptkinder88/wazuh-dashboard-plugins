"""Small Wazuh indexer (OpenSearch) client for the CIS-CAT bridge on Wazuh 5.0.

- the dashboard store: each former ciscat-* CDB list is one document of the hidden index
  wz-dashboard-store-ciscat (id = list name, {kind: "list", key, data: {records}, updated_by,
  updated_at}), the same documents the dashboard reads and writes (CONTRACT.md);
- trigger documents for runs (data stream wazuh-findings-v5-ciscat, bulk create);
- the Active Response channels and Alerting monitors that turn those documents into runs.

Configuration (/opt/ciscat/etc/indexer.json, or $CISCAT_INDEXER_CONF):
    {"url": "https://127.0.0.1:9200", "user": "...", "password_file": "/opt/ciscat/etc/indexer.pass",
     "ca": "/path/root-ca.pem"}
The password is read from its file and never printed or put in an error message.

Stdlib only; runs on Python 3.6+.
"""
import base64
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

DEFAULT_CONF = "/opt/ciscat/etc/indexer.json"
STORE_INDEX = "wz-dashboard-store-ciscat"
STORE_KIND = "list"
WRITER = "ciscat-bridge"
# same mapping and settings as the dashboard (plugins/main/server/lib/dashboard-store.ts)
STORE_INDEX_BODY = {
    "settings": {"index": {"hidden": True, "number_of_shards": 1}},
    "mappings": {
        "dynamic": "strict",
        "properties": {
            "kind": {"type": "keyword"},
            "key": {"type": "keyword"},
            "data": {"type": "object", "enabled": False},
            "updated_by": {"type": "keyword"},
            "updated_at": {"type": "date"},
        },
    },
}


class IndexerError(RuntimeError):
    def __init__(self, status, message):
        super().__init__("indexer: HTTP {0}: {1}".format(status, message))
        self.status = status


def conf_path():
    return os.environ.get("CISCAT_INDEXER_CONF") or DEFAULT_CONF


class Indexer:
    def __init__(self, url, user, password, ca=None, timeout=60):
        self.url = url.rstrip("/")
        self._auth = "Basic " + base64.b64encode(
            "{0}:{1}".format(user, password).encode("utf-8")).decode("ascii")
        self.user = user
        self.timeout = timeout
        self._ctx = None
        if self.url.startswith("https:"):
            self._ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
        self._store_ready = False

    def __repr__(self):  # never shows the password
        return "Indexer({0!r}, user={1!r})".format(self.url, self.user)

    @classmethod
    def from_config(cls, path=None):
        """Indexer from the JSON config, or None when the file does not exist."""
        path = path or conf_path()
        if not os.path.isfile(path):
            return None
        with open(path, encoding="utf-8") as f:
            conf = json.load(f)
        for field in ("url", "user", "password_file"):
            if not conf.get(field):
                raise IndexerError(0, "{0}: '{1}' is missing".format(path, field))
        with open(conf["password_file"], encoding="utf-8") as f:
            password = f.readline().rstrip("\r\n")
        return cls(conf["url"], conf["user"], password, conf.get("ca") or None,
                   int(conf.get("timeout", 60)))

    def request(self, method, path, body=None, ndjson=None, params=None):
        """(status, decoded JSON body). 2xx only; anything else raises IndexerError."""
        url = self.url + "/" + path.lstrip("/")
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, method=method)
        req.add_header("Authorization", self._auth)
        if ndjson is not None:
            req.add_header("Content-Type", "application/x-ndjson")
            req.data = "".join(json.dumps(line, separators=(",", ":")) + "\n"
                               for line in ndjson).encode("utf-8")
        elif body is not None:
            req.add_header("Content-Type", "application/json")
            req.data = json.dumps(body).encode("utf-8")
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=self.timeout) as r:
                raw = r.read().decode("utf-8") if method != "HEAD" else ""
                return r.status, (json.loads(raw) if raw.strip() else {})
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace") if method != "HEAD" else ""
            try:
                err = json.loads(raw).get("error", raw)
                if isinstance(err, dict):
                    err = "{0}: {1}".format(err.get("type", ""), err.get("reason", ""))
            except ValueError:
                err = raw
            raise IndexerError(e.code, str(err)[:500])
        except urllib.error.URLError as e:
            raise IndexerError(0, "{0} unreachable: {1}".format(self.url, e.reason))

    def exists(self, path):
        try:
            self.request("HEAD", path)
            return True
        except IndexerError as e:
            if e.status == 404:
                return False
            raise

    # ------------------------------------------------------------------ dashboard store
    def ensure_store_index(self):
        """Creates the store index when missing (as the dashboard does). True if created."""
        if self._store_ready:
            return False
        created = False
        if not self.exists(STORE_INDEX):
            try:
                self.request("PUT", STORE_INDEX, STORE_INDEX_BODY)
                created = True
            except IndexerError as e:
                if e.status != 400 or "resource_already_exists" not in str(e):
                    raise
        self._store_ready = True
        return created

    def get_list(self, name):
        """(records or None when missing, seq_no, primary_term, error or None)."""
        try:
            _, doc = self.request("GET", "{0}/_doc/{1}".format(STORE_INDEX, name))
        except IndexerError as e:
            if e.status == 404:  # no document, or no index yet
                return None, None, None, None
            raise
        if not doc.get("found", True):
            return None, None, None, None
        records = (doc.get("_source") or {}).get("data", {}).get("records")
        error = None
        if not isinstance(records, dict):
            records, error = {}, "{0}: records missing or not an object".format(name)
        return records, doc.get("_seq_no"), doc.get("_primary_term"), error

    def put_list(self, name, records, seq_no=None, primary_term=None, create=False):
        """Writes a list document. With seq_no/primary_term (or create) it fails with HTTP 409 if
        the document changed (or exists) meanwhile."""
        self.ensure_store_index()
        body = {"kind": STORE_KIND, "key": name, "data": {"records": records},
                "updated_by": WRITER,
                "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")}
        params = {"refresh": "wait_for"}
        if create:
            path = "{0}/_create/{1}".format(STORE_INDEX, name)
        else:
            path = "{0}/_doc/{1}".format(STORE_INDEX, name)
            if seq_no is not None and primary_term is not None:
                params.update(if_seq_no=seq_no, if_primary_term=primary_term)
        return self.request("PUT", path, body, params=params)[1]

    # ------------------------------------------------------------------ trigger documents
    def bulk_create(self, index, docs):
        """(created, failed, [errors]) for documents created in a data stream."""
        if not docs:
            return 0, 0, []
        lines = []
        for doc in docs:
            lines += [{"create": {}}, doc]
        _, body = self.request("POST", "{0}/_bulk".format(index), ndjson=lines)
        ok, failed, errors = 0, 0, []
        for item in body.get("items", []):
            res = item.get("create") or next(iter(item.values()), {})
            if 200 <= int(res.get("status", 500)) < 300:
                ok += 1
            else:
                failed += 1
                err = res.get("error") or {}
                errors.append(err.get("reason") or str(err) if isinstance(err, dict) else str(err))
        failed += max(0, len(docs) - ok - failed)  # items missing from the response
        return ok, failed, errors

    # ------------------------------------------------------------------ AR channels / monitors
    def channels_by_name(self):
        _, body = self.request("GET", "_plugins/_notifications/configs",
                               params={"max_items": 1000})
        out = {}
        for item in body.get("config_list", []):
            cfg = item.get("config") or {}
            if cfg.get("name"):
                out[cfg["name"]] = (item.get("config_id"), cfg)
        return out

    def monitors_by_name(self, names):
        should = [{"match_phrase": {"monitor.name": n}} for n in sorted(names)]
        _, body = self.request("POST", "_plugins/_alerting/monitors/_search", {
            "size": 1000, "query": {"bool": {"should": should, "minimum_should_match": 1}}})
        out = {}
        for hit in (body.get("hits") or {}).get("hits", []):
            src = hit.get("_source") or {}
            src = src.get("monitor", src)
            if src.get("name") in names:
                out[src["name"]] = (hit.get("_id"), src)
        return out


def ar_channel_config(name, executable):
    return {"name": name, "description": "CIS-CAT bridge: run {0} on the agent".format(executable),
            "config_type": "active_response", "is_enabled": True,
            "active_response": {"executable": executable, "type": "stateless", "location": "local"}}


def ar_monitor(name, channel_id, pattern):
    query = 'event.action:"{0}"'.format(name)
    return {
        "type": "monitor", "monitor_type": "active_response_monitor", "name": name,
        "enabled": True, "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
        "inputs": [{"doc_level_input": {"indices": [pattern], "queries": [
            {"id": "q1", "name": "q1", "query": query, "tags": []}]}}],
        "triggers": [{"document_level_trigger": {
            "name": "run", "severity": "1",
            "condition": {"script": {"source": "query[name=q1]", "lang": "painless"}},
            "actions": [{"name": "ar", "destination_id": channel_id,
                         "message_template": {"source": "{{ctx.alerts.0.related_doc_ids}}"},
                         "action_execution_policy": {"action_execution_scope": {
                             "per_alert": {"actionable_alerts": ["DEDUPED", "NEW"]}}}}]}}],
    }


def contains(want, have):
    """True when every field of `want` is in `have` with the same value (extra fields of `have`,
    such as ids and timestamps the indexer adds, are ignored)."""
    if isinstance(want, dict):
        return isinstance(have, dict) and all(k in have and contains(v, have[k])
                                              for k, v in want.items())
    if isinstance(want, list):
        return isinstance(have, list) and len(want) == len(have) and all(
            contains(w, h) for w, h in zip(want, have))
    return want == have


def ensure_active_response(ix, actions, pattern):
    """Creates or updates, matched by name, one channel and one monitor per action
    ({name: executable}). Returns report lines; running it again changes nothing."""
    report = []
    channels = ix.channels_by_name()
    channel_ids = {}
    for name, executable in sorted(actions.items()):
        want = ar_channel_config(name, executable)
        if name not in channels:
            _, body = ix.request("POST", "_plugins/_notifications/configs", {"config": want})
            channel_ids[name] = body.get("config_id")
            report.append("channel {0} created ({1})".format(name, executable))
            continue
        cid, have = channels[name]
        channel_ids[name] = cid
        if contains(want, have):
            report.append("channel {0} unchanged".format(name))
        else:
            ix.request("PUT", "_plugins/_notifications/configs/" + urllib.parse.quote(cid),
                       {"config": want})
            report.append("channel {0} updated ({1})".format(name, executable))
    monitors = ix.monitors_by_name(set(actions))
    for name in sorted(actions):
        want = ar_monitor(name, channel_ids[name], pattern)
        if name not in monitors:
            ix.request("POST", "_plugins/_alerting/monitors", want)
            report.append("monitor {0} created".format(name))
            continue
        mid, have = monitors[name]
        if contains(want, have):
            report.append("monitor {0} unchanged".format(name))
        else:
            ix.request("PUT", "_plugins/_alerting/monitors/" + urllib.parse.quote(mid), want)
            report.append("monitor {0} updated".format(name))
    return report


def wait_retry(attempt):
    time.sleep(min(0.05 * (2 ** attempt), 1.0))
