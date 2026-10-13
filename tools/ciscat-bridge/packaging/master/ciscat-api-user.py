#!/usr/bin/env python3
"""ciscat-api-user.py - CIS-CAT bridge @VERSION@: creates (or updates) the Wazuh API user of the bridge
with only the rights the bridge uses, and gives it a new random password kept in a root-only file.

  CISCAT_ADMIN_USER=<admin> CISCAT_ADMIN_PASS=<password> python3 ciscat-api-user.py
  (ciscat-master-setup.sh asks for them once; they are never written anywhere)

Rights (Wazuh RBAC), nothing else:
  agents:  agent:read, agent:modify_group, active-response:command, sca:read
  groups:  group:read, group:create, group:delete (never "default"), group:modify_assignments
  (no group:update_config: the bridge writes agent.conf on disk; the "baseline" action, not used
  by the dashboard, needs an administrator's credentials)
Rerun it to rotate the password. Prints RESULT: OK.
"""
import json
import os
import secrets
import ssl
import string
import sys
import urllib.error
import urllib.parse
import urllib.request
from base64 import b64encode

API = os.environ.get("CISCAT_API_URL", "https://localhost:55000")
USER = os.environ.get("CISCAT_BRIDGE_USER", "ciscat-bridge")
ETC = os.environ.get("CISCAT_ETC_DIR", "/opt/ciscat/etc")
CONF = os.path.join(ETC, "ciscat-orchestrator.conf")
PASSF = os.path.join(ETC, ".ciscat_api_pass")
ROLE = "ciscat-bridge"
POLICIES = {
    "ciscat-bridge-agents": {
        "actions": ["agent:read", "agent:modify_group", "active-response:command", "sca:read"],
        "resources": ["agent:id:*", "agent:group:*"], "effect": "allow"},
    "ciscat-bridge-groups": {
        "actions": ["group:read", "group:delete", "group:modify_assignments"],
        "resources": ["group:id:*"], "effect": "allow"},
    "ciscat-bridge-keep-default": {
        "actions": ["group:delete"], "resources": ["group:id:default"], "effect": "deny"},
    "ciscat-bridge-group-create": {
        "actions": ["group:create"], "resources": ["*:*:*"], "effect": "allow"},
}


def read_conf():
    conf = []
    if os.path.isfile(CONF):
        with open(CONF, encoding="utf-8") as f:
            conf = [line.rstrip("\n") for line in f]
    return conf


def conf_value(lines, key):
    for line in lines:
        if "=" in line and not line.lstrip().startswith("#") and line.split("=", 1)[0].strip() == key:
            return line.split("=", 1)[1].strip()
    return ""


# as the bridge: verified TLS when api_ca names the CA, else only the local API (self-signed)
CA = conf_value(read_conf(), "api_ca")
if CA:
    CTX = ssl.create_default_context(cafile=CA)
elif (urllib.parse.urlsplit(API).hostname or "") not in ("localhost", "127.0.0.1", "::1"):
    raise SystemExit("STOP: {0} is not on this host: set api_ca in {1} first".format(API, CONF))
else:
    CTX = ssl.create_default_context()
    CTX.check_hostname = False
    CTX.verify_mode = ssl.CERT_NONE


def call(method, path, token=None, body=None, basic=None):
    req = urllib.request.Request(API + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if basic:
        req.add_header("Authorization", "Basic " + b64encode(":".join(basic).encode()).decode())
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=30) as r:
            data = r.read().decode()
    except urllib.error.HTTPError as e:
        raise SystemExit("STOP: API {0} {1}: {2} {3}".format(method, path, e.code, e.read().decode()[:300]))
    except (urllib.error.URLError, OSError) as e:
        raise SystemExit("STOP: the Wazuh API at {0} cannot be reached ({1}): is wazuh-manager "
                         "running?".format(API, getattr(e, "reason", e)))
    if path.startswith("/security/user/authenticate"):
        return data.strip()
    out = json.loads(data)
    if out.get("error") not in (0, None):
        raise SystemExit("STOP: API {0} {1}: {2}".format(method, path, json.dumps(out)[:300]))
    return out.get("data", {})


def find(token, kind, name, key):
    items = call("GET", "/security/{0}?limit=500&search={1}".format(kind, urllib.parse.quote(name)),
                 token).get("affected_items", [])
    return next((i for i in items if i.get(key) == name), None)


def password():
    """Meets the API rules (8-64 characters, upper and lower case, digit, symbol)."""
    symbols = "!#%+-_=.:@"
    while True:
        p = "".join(secrets.choice(string.ascii_letters + string.digits + symbols) for _ in range(32))
        if (any(c.islower() for c in p) and any(c.isupper() for c in p)
                and any(c.isdigit() for c in p) and any(c in symbols for c in p)):
            return p


def main():
    admin = (os.environ.get("CISCAT_ADMIN_USER") or "", os.environ.get("CISCAT_ADMIN_PASS") or "")
    if not all(admin):
        raise SystemExit("STOP: CISCAT_ADMIN_USER and CISCAT_ADMIN_PASS are needed")
    token = call("POST", "/security/user/authenticate?raw=true", basic=admin)
    ids = []
    for name, policy in POLICIES.items():
        cur = find(token, "policies", name, "name")
        if cur:
            call("PUT", "/security/policies/{0}".format(cur["id"]), token, {"policy": policy})
            ids.append(cur["id"])
        else:
            ids.append(call("POST", "/security/policies", token,
                            {"name": name, "policy": policy})["affected_items"][0]["id"])
    role = find(token, "roles", ROLE, "name")
    role_id = role["id"] if role else call("POST", "/security/roles", token,
                                           {"name": ROLE})["affected_items"][0]["id"]
    have = set((role or {}).get("policies", []))
    missing = [i for i in ids if i not in have]
    if missing:
        call("POST", "/security/roles/{0}/policies?policy_ids={1}".format(
            role_id, ",".join(map(str, missing))), token)
    secret = password()
    user = find(token, "users", USER, "username")
    if user:
        call("PUT", "/security/users/{0}".format(user["id"]), token, {"password": secret})
        user_id = user["id"]
    else:
        user_id = call("POST", "/security/users", token,
                       {"username": USER, "password": secret})["affected_items"][0]["id"]
    if role_id not in (user or {}).get("roles", []):
        call("POST", "/security/users/{0}/roles?role_ids={1}".format(user_id, role_id), token)
    # the new user can work: log in and read groups and agents
    check = call("POST", "/security/user/authenticate?raw=true", basic=(USER, secret))
    call("GET", "/groups?limit=1", check)
    call("GET", "/agents?limit=1&select=id", check)
    os.makedirs(ETC, exist_ok=True)
    old = os.umask(0o077)
    try:
        with open(PASSF + ".new", "w") as f:
            f.write(secret + "\n")
        os.chmod(PASSF + ".new", 0o600)
        os.replace(PASSF + ".new", PASSF)
        # other settings of the conf (api_ca...) are kept
        keep = [line for line in read_conf() if not ("=" in line and line.split("=", 1)[0].strip()
                                                      in ("api_user", "api_pass_file"))]
        with open(CONF + ".new", "w") as f:
            f.write("".join(line + "\n" for line in keep))
            f.write("api_user={0}\napi_pass_file={1}\n".format(USER, PASSF))
        os.chmod(CONF + ".new", 0o640)
        os.replace(CONF + ".new", CONF)
    finally:
        os.umask(old)
    print("   user {0}: role {1} with policies {2}; password in {3} (root only)".format(
        USER, ROLE, ", ".join(POLICIES), PASSF))
    print("RESULT: OK")


if __name__ == "__main__":
    sys.exit(main())
