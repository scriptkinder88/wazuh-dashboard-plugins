#!/bin/sh
# ciscat-master-setup.sh - CIS-CAT bridge @VERSION@, complete setup of a Wazuh @WAZUH@ master
# (and of the Wazuh dashboard when it runs on the same host). Run as root from this folder:
#   sh ciscat-master-setup.sh [--import ciscat-config-<date>.tgz] [--with-targets] [--no-dashboard]
#                             [--new-api-user]
#
#   1. checks: root, Wazuh master @WAZUH@, files of this package (SHA-256)
#   2. folders /opt/ciscat/... (root only)
#   3. --import: benchmarks (original CIS files) and bridge configuration exported from another
#      master by ciscat-export-config.sh (--with-targets also takes the benchmark groups)
#   4. Wazuh API user ciscat-bridge (ciscat-api-user.py): role and policies with only the rights the
#      bridge uses, random password in a root-only file; an API administrator is asked once and
#      never stored (--new-api-user rotates the password)
#   5. Active Response <command>/<active-response> blocks in ossec.conf (backup, checked by
#      wazuh-analysisd -t, restored if refused)
#   6. bridge installer: scripts, rule, cron, policies (--apply), manager restart
#   7. dashboard plugin from the file of this package (when the dashboard is on this host;
#      otherwise prints the command for the dashboard host)
#   6b. manifest signing key: created once in /opt/ciscat/etc (root only); its public key is
#      copied to ./agent-keys for the agent installers
#   8. summary: what was done, and the plan of the policies
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
INSTALLER="$HERE/@INSTALLER@"
PLUGIN="$HERE/@PLUGIN@"
PLUGIN_SHA="@PLUGIN_SHA@"
IMPORT=""; WITH_TARGETS=""; DASHBOARD=1; NEW_API_USER=""
while [ $# -gt 0 ]; do
    case "$1" in
        --import) IMPORT=${2:-}; shift ;;
        --with-targets) WITH_TARGETS=1 ;;
        --no-dashboard) DASHBOARD="" ;;
        --new-api-user) NEW_API_USER=1 ;;
        *) echo "usage: sh $0 [--import <tgz>] [--with-targets] [--no-dashboard] [--new-api-user]"; exit 2 ;;
    esac
    shift
done
STAMP=$(date +%Y%m%d%H%M)
say() { printf '%s\n' "$*"; }
stop() { say "STOP: $*"; exit 1; }

say "== 1. checks"
[ "$(id -u)" = 0 ] || stop "run as root"
# the package must be unpacked in a root-only folder, not in a home or temporary folder:
# what is run as root from it must not be replaceable by another user
case "$HERE" in
    /root|/root/*|/home/*|/tmp|/tmp/*|/var/tmp|/var/tmp/*|/dev/shm|/dev/shm/*)
        stop "unpack the package in /opt/ciscat/install/@VERSION@ (root:root 0700), not in $HERE" ;;
esac
pkg_perm=$(stat -c '%U %a' "$HERE")
case "$pkg_perm" in
    "root "*[2367][0-7]|"root "*[0-7][2367]) stop "$HERE is writable by group or others ($pkg_perm): chmod 700 $HERE" ;;
    "root "*) ;;
    *) stop "$HERE is not owned by root ($pkg_perm): chown -R root:root $HERE" ;;
esac
info=$(/var/ossec/bin/wazuh-control info 2>/dev/null)
echo "$info" | grep -q 'WAZUH_TYPE="server"' || stop "not a Wazuh manager"
echo "$info" | grep -q 'WAZUH_VERSION="v@WAZUH@"' || stop "Wazuh @WAZUH@ expected, found: $(echo "$info" | grep VERSION)"
command -v python3 >/dev/null || stop "python3 missing"
(cd "$HERE" && sha256sum -c --quiet SHA256SUMS) || stop "a file of this package is damaged (SHA256SUMS)"
say "   Wazuh manager @WAZUH@, package files verified"
# the plugin zip downloaded from the CI build (the browser may add .zip or (1) to its name)
if [ ! -f "$PLUGIN" ]; then
    PLUGIN=$(ls "$HERE"/wazuh-dashboard-plugins_wazuh_* 2>/dev/null | head -1)
fi
if [ -n "$DASHBOARD" ]; then
    [ -n "$PLUGIN" ] && [ -f "$PLUGIN" ] || stop "plugin zip not found in $HERE (see README.txt); --no-dashboard to skip it"
    [ "$(sha256sum "$PLUGIN" | cut -d' ' -f1)" = "$PLUGIN_SHA" ] || stop "plugin zip $(basename "$PLUGIN"): sha256 is not $PLUGIN_SHA"
    say "   plugin zip verified: $(basename "$PLUGIN")"
fi

say "== 2. folders"
for d in /opt/ciscat /opt/ciscat/benchmarks /opt/ciscat/etc /opt/ciscat/backup /opt/ciscat/log \
         /opt/ciscat/run /opt/ciscat/tailoring/exclusions; do
    mkdir -p "$d"
done
chown -R root:root /opt/ciscat && chmod 755 /opt/ciscat && chmod 750 /opt/ciscat/benchmarks /opt/ciscat/etc \
    /opt/ciscat/log /opt/ciscat/run /opt/ciscat/tailoring && chmod 700 /opt/ciscat/backup
say "   /opt/ciscat ready (root)"

if [ -n "$IMPORT" ]; then
    say "== 3. import $IMPORT"
    [ -f "$IMPORT" ] || stop "$IMPORT not found"
    [ -f "$IMPORT.sha256" ] && { (cd "$(dirname "$IMPORT")" && sha256sum -c --quiet "$(basename "$IMPORT").sha256") || stop "$IMPORT damaged"; }
    X=$(mktemp -d); tar -xzf "$IMPORT" -C "$X" --no-same-owner || stop "cannot read $IMPORT"
    find "$X" -type l | grep -q . && stop "the import contains links: refused"
    n=0
    for f in "$X"/benchmarks/*; do
        [ -f "$f" ] || continue
        install -o root -g root -m 0640 "$f" /opt/ciscat/benchmarks/ && n=$((n + 1))
    done
    say "   benchmarks: $n file(s) in /opt/ciscat/benchmarks"
    if [ -f "$X/etc/os-library.json" ]; then
        if [ -f /opt/ciscat/etc/os-library.json ]; then
            install -m 0640 "$X/etc/os-library.json" "/opt/ciscat/etc/os-library.json.imported-$STAMP"
            say "   os-library.json kept; the imported one is os-library.json.imported-$STAMP"
        else
            install -m 0640 "$X/etc/os-library.json" /opt/ciscat/etc/os-library.json
            say "   os-library.json imported"
        fi
    fi
    lists="ciscat-exclusions ciscat-schedule"
    [ -n "$WITH_TARGETS" ] && lists="$lists ciscat-targets"
    for l in $lists; do
        [ -f "$X/lists/$l" ] || continue
        if [ -f "/var/ossec/etc/lists/$l" ]; then
            say "   $l kept (already present)"
        else
            install -o wazuh -g wazuh -m 0660 "$X/lists/$l" "/var/ossec/etc/lists/$l" && say "   $l imported"
        fi
    done
    for f in "$X"/tailoring/*; do
        [ -f "$f" ] && install -o root -g root -m 0640 "$f" /opt/ciscat/tailoring/exclusions/
    done
    rm -rf "$X"
else
    say "== 3. no import: copy the CIS benchmarks (xccdf, oval, cpe) to /opt/ciscat/benchmarks"
fi

say "== 4. Wazuh API user of the bridge"
CONF=/opt/ciscat/etc/ciscat-orchestrator.conf
PASSF=/opt/ciscat/etc/.ciscat_api_pass
if [ -z "$NEW_API_USER" ] && grep -q '^api_user=ciscat-bridge$' "$CONF" 2>/dev/null && [ -s "$PASSF" ]; then
    say "   kept: user ciscat-bridge ($CONF, password in $PASSF); --new-api-user to rotate it"
else
    say "   creates the API user ciscat-bridge with only the rights the bridge uses"
    say "   (an API administrator is needed once: not stored anywhere)"
    printf '   API administrator [wazuh]: '
    read -r AU; AU=${AU:-wazuh}
    stty -echo 2>/dev/null; printf '   password: '; read -r AP; stty echo 2>/dev/null; echo
    [ -n "$AP" ] || stop "empty password"
    CISCAT_ADMIN_USER=$AU CISCAT_ADMIN_PASS=$AP python3 "$HERE/ciscat-api-user.py" | sed 's/^/   /'
    unset AP AU
    grep -q '^api_user=ciscat-bridge$' "$CONF" 2>/dev/null && [ -s "$PASSF" ] || stop "API user not created (see above)"
fi

say "== 5. Active Response commands in ossec.conf"
cp -p /var/ossec/etc/ossec.conf "/opt/ciscat/backup/ossec.conf.$STAMP"
python3 - <<'PY' || stop "ossec.conf not changed"
import re
path = "/var/ossec/etc/ossec.conf"
need = {"ciscat-bootstrap-linux": "ciscat-bootstrap.sh", "ciscat-refresh-linux": "ciscat-refresh.sh",
        "ciscat-assessment": "ciscat-assessment.cmd"}
text = open(path, encoding="utf-8").read()
live = re.sub(r"<!--.*?-->", lambda m: " " * len(m.group(0)), text, flags=re.S)
changed = []
for name, exe in need.items():
    m = re.search(r"<command>\s*<name>\s*" + re.escape(name) + r"\s*</name>\s*<executable>\s*([^<]*?)\s*</executable>", live)
    if m and m.group(1) != exe:
        text = text[:m.start(1)] + exe + text[m.end(1):]
        live = live[:m.start(1)] + exe + live[m.end(1):]
        changed.append("{0}: executable {1} -> {2}".format(name, m.group(1), exe))
    add = ""
    if not m:
        add += ("  <command>\n    <name>{0}</name>\n    <executable>{1}</executable>\n"
                "    <timeout_allowed>no</timeout_allowed>\n  </command>\n").format(name, exe)
    if not re.search(r"<active-response>(?:(?!</active-response>).)*?<command>\s*" + re.escape(name) + r"\s*</command>", live, re.S):
        add += ("  <active-response>\n    <disabled>no</disabled>\n    <command>{0}</command>\n"
                "    <location>local</location>\n  </active-response>\n").format(name)
    if add:
        end = live.rfind("</ossec_config>")
        if end < 0:
            raise SystemExit("no </ossec_config> in ossec.conf")
        block = "\n  <!-- CIS-CAT bridge: Active Response -->\n" + add
        text = text[:end] + block + text[end:]
        live = live[:end] + block + live[end:]
        changed.append("{0}: blocks added".format(name))
# the Windows bootstrap command of earlier versions (ciscat-bootstrap.exe): 2.3.0 never sends it
spans = []
for m in re.finditer(r"<command>(?:(?!</command>).)*?<name>\s*ciscat-bootstrap\s*</name>"
                     r"(?:(?!</command>).)*?</command>", live, re.S):
    if re.search(r"<executable>\s*ciscat-bootstrap\.exe\s*</executable>", m.group(0)):
        spans.append(m.span())
        for a in re.finditer(r"<active-response>(?:(?!</active-response>).)*?"
                             r"<command>\s*ciscat-bootstrap\s*</command>"
                             r"(?:(?!</active-response>).)*?</active-response>", live, re.S):
            spans.append(a.span())
for start, end in sorted(set(spans), reverse=True):
    text = text[:start] + text[end:]
    live = live[:start] + live[end:]
if spans:
    changed.append("ciscat-bootstrap (ciscat-bootstrap.exe, earlier versions): removed")
if changed:
    open(path, "w", encoding="utf-8").write(text)
print("   " + ("; ".join(changed) if changed else "already configured"))
PY
if ! /var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1; then
    cp -p "/opt/ciscat/backup/ossec.conf.$STAMP" /var/ossec/etc/ossec.conf
    stop "wazuh-analysisd -t refused the new ossec.conf: previous one restored"
fi
say "   ossec.conf checked by wazuh-analysisd -t (backup /opt/ciscat/backup/ossec.conf.$STAMP)"

say "== 6. bridge"
sh "$INSTALLER" --apply --restart-manager || stop "bridge installer failed (it restored its backup)"

say "== 6b. manifest signing key (agents accept only manifests signed with it)"
/opt/ciscat/bin/ciscat-fleet.py key | sed 's/^/   /' || stop "signing key not available"
mkdir -p "$HERE/agent-keys"
install -m 0644 /opt/ciscat/etc/ciscat-manifest.pub /opt/ciscat/etc/ciscat-manifest.pub.xml "$HERE/agent-keys/"
say "   copied to $HERE/agent-keys: ciscat-manifest.pub (next to install-linux-agent.sh) and"
say "   ciscat-manifest.pub.xml (next to install-windows-agent.ps1) on every agent"

say "== 7. dashboard plugin"
if [ -z "$DASHBOARD" ]; then
    say "   skipped (--no-dashboard): the installed plugin is left as it is"
elif [ -x /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin ]; then
    sh "$INSTALLER" --plugin-file "$PLUGIN" --plugin-sha256 "$PLUGIN_SHA" --restart-dashboard \
        || stop "plugin installation failed (the previous plugin was restored)"
else
    say "   the dashboard is not on this host: copy $(basename "$INSTALLER") and $(basename "$PLUGIN")"
    say "   there and run as root:"
    say "   sh $(basename "$INSTALLER") --plugin-file $(basename "$PLUGIN") --plugin-sha256 $PLUGIN_SHA --restart-dashboard"
fi

say "== 8. summary"
grep ciscat /var/ossec/etc/shared/ar.conf 2>/dev/null | sed 's/^/   ar.conf: /'
say "   benchmarks: $(ls /opt/ciscat/benchmarks 2>/dev/null | grep -c xccdf) xccdf file(s)"
/opt/ciscat/bin/ciscat-fleet.py plan 2>&1 | grep -E '^\[|ERROR|would' | sed 's/^/   /' | head -40
say "RESULT: OK - CIS-CAT bridge @VERSION@ installed. Next: agents (Windows and Linux packages), then the end-to-end test."
