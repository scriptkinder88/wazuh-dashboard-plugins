#!/usr/bin/env python3
"""Builds dist/ciscat-bridge-install-<version>.sh: one self-contained script (payload embedded as
base64 with its SHA-256) to run on the Wazuh master and/or dashboard host. Nothing to transfer
but the script text itself; no network access needed on the master.

    python3 tools/ciscat-bridge/installer/build.py
"""
import base64
import gzip
import hashlib
import io
import os
import re
import sys
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
BRIDGE = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import ciscat_install  # noqa: E402

TEMPLATE = """#!/bin/sh
# CIS-CAT bridge installer {version} - self-contained (payload below, SHA-256 checked).
# Run as root on the Wazuh master (and/or the Wazuh dashboard host):
#   sh {name}                     install/update, migrate, sync, plan
#   sh {name} --apply             ... and apply the policies to the agents
#   sh {name} --restart-manager   ... and restart wazuh-manager to load the CIS-CAT rule
#   sh {name} --rollback /opt/ciscat/backup/ciscat-bridge-<date>.tgz
# Dashboard host: --plugin-url <https URL in the internal repository> --plugin-sha256 <hex>
#                 [--restart-dashboard]
set -eu
PAYLOAD_SHA256="{sha}"
command -v python3 >/dev/null 2>&1 || {{ echo "python3 is required"; exit 1; }}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
sed -n '/^__CISCAT_PAYLOAD_BELOW__$/,$p' "$0" | tail -n +2 | tr -d '\\r' | base64 -d > "$tmp/payload.tgz"
got=$(sha256sum "$tmp/payload.tgz" | cut -d' ' -f1)
if [ "$got" != "$PAYLOAD_SHA256" ]; then
    echo "payload checksum mismatch: the script was damaged while copying, nothing was changed"
    exit 1
fi
tar xzf "$tmp/payload.tgz" -C "$tmp"
python3 "$tmp/ciscat_install.py" "$@"
exit $?
__CISCAT_PAYLOAD_BELOW__
"""


def version():
    with open(os.path.join(BRIDGE, "bin", "ciscat-fleet.py"), encoding="utf-8") as f:
        return re.search(r'^VERSION = "([^"]+)"', f.read(), re.M).group(1)


def payload(ver):
    files = [(os.path.join(HERE, "ciscat_install.py"), "ciscat_install.py"),
             (os.path.join(BRIDGE, "rules", "ciscat_rules.xml"), "rules/ciscat_rules.xml")]
    files += [(os.path.join(BRIDGE, "bin", rel), "bin/" + rel) for rel in ciscat_install.MANAGED_BIN]
    files += [(os.path.join(BRIDGE, "agent", "active-response", rel), "agent/active-response/" + rel)
              for rel in ciscat_install.MANAGED_AGENT]
    buf = io.BytesIO()
    # deterministic archive (no timestamps): same sources, same bytes, same checksum
    gz = gzip.GzipFile(filename="", mode="wb", fileobj=buf, compresslevel=9, mtime=0)
    with tarfile.open(fileobj=gz, mode="w") as tar:
        def add(name, data, mode):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), mode, 0
            info.uname = info.gname = "root"
            tar.addfile(info, io.BytesIO(data))
        add("VERSION", (ver + "\n").encode(), 0o644)
        for src, name in files:
            with open(src, "rb") as f:
                add(name, f.read(), 0o755 if name.endswith((".py", ".sh")) else 0o644)
    gz.close()
    return buf.getvalue()


def build(out_dir=os.path.join(BRIDGE, "dist")):
    ver = version()
    data = payload(ver)
    name = "ciscat-bridge-install-{0}.sh".format(ver)
    b64 = base64.b64encode(data).decode()
    body = "\n".join(b64[i:i + 76] for i in range(0, len(b64), 76))
    script = TEMPLATE.format(version=ver, name=name, sha=hashlib.sha256(data).hexdigest()) + body + "\n"
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, name)
    with open(path, "w", newline="\n") as f:
        f.write(script)
    os.chmod(path, 0o755)
    with open(path + ".sha256", "w") as f:
        f.write("{0}  {1}\n".format(hashlib.sha256(script.encode()).hexdigest(), name))
    return path


if __name__ == "__main__":
    p = build()
    print("{0} ({1} KB)".format(p, os.path.getsize(p) // 1024))
