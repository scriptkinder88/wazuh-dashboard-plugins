#!/bin/sh
# CIS-CAT bridge @VERSION@: complete installation on the Wazuh master from this bundle, in one go.
#
#   as root, in the unpacked bundle (a root-only folder, e.g. /opt/ciscat/install/bundle):
#     sh install-prod.sh
#
# It checks the bundle (SHA256SUMS), unpacks the master package in /opt/ciscat/install/@VERSION@,
# copies the CIS benchmarks (XCCDF, OVAL, CPE) to /opt/ciscat/benchmarks and the CIS-CAT Pro
# license to /opt/ciscat/license, runs the master setup (dashboard plugin, API user, Active
# Response, bridge, signing key, agents into the group of their OS; with the configuration
# exported from another master when the bundle has one) and publishes the groups. The agent
# packages for Satellite are in agents/.
# The only question: the first time, a Wazuh API administrator to create the bridge's own API
# user (never stored).
set -eu
VERSION=@VERSION@
HERE=$(cd "$(dirname "$0")" && pwd)
say() { printf '%s\n' "$*"; }
stop() { say "STOP: $*"; exit 1; }

say "== CIS-CAT bridge $VERSION: bundle checks"
[ "$(id -u)" = 0 ] || stop "run as root"
case "$HERE" in
    /root|/root/*|/home/*|/tmp|/tmp/*|/var/tmp|/var/tmp/*|/dev/shm|/dev/shm/*)
        stop "unpack the bundle in a root-only folder (e.g. /opt/ciscat/install/bundle), not in $HERE" ;;
esac
case "$(stat -c '%U %a' "$HERE")" in
    "root "*[2367][0-7]|"root "*[0-7][2367]) stop "$HERE is writable by group or others: chmod 700 $HERE" ;;
    "root "*) ;;
    *) stop "$HERE is not owned by root: chown -R root:root $HERE" ;;
esac
for t in unzip sha256sum python3; do command -v $t >/dev/null || stop "$t missing"; done
(cd "$HERE" && sha256sum -c --quiet SHA256SUMS) || stop "a file of the bundle is damaged (SHA256SUMS)"
say "   bundle verified ($(grep -c . "$HERE/SHA256SUMS") files)"

say "== master package in /opt/ciscat/install/$VERSION"
DEST=/opt/ciscat/install/$VERSION
install -d -m 0755 -o root -g root /opt/ciscat
install -d -m 0700 -o root -g root /opt/ciscat/install "$DEST"
(cd "$DEST" && unzip -o -q "$HERE/ciscat-master-$VERSION.zip")
chown -R root:root "$DEST" && chmod -R go-w "$DEST"
SETUP_ARGS="--auto-assign"
PLUGIN=$(ls "$HERE"/wazuh-dashboard-plugins_wazuh_*.zip 2>/dev/null | head -1 || true)
if [ -n "$PLUGIN" ]; then
    install -m 0640 -o root -g root "$PLUGIN" "$DEST/master/"
    say "   dashboard plugin: $(basename "$PLUGIN")"
else
    SETUP_ARGS="$SETUP_ARGS --no-dashboard"
    say "   no dashboard plugin in the bundle: dashboard left as it is"
fi

say "== CIS benchmarks in /opt/ciscat/benchmarks"
install -d -m 0750 -o root -g root /opt/ciscat/benchmarks
n=0
for f in "$HERE"/benchmarks/*; do
    [ -f "$f" ] || continue
    install -m 0640 -o root -g root "$f" /opt/ciscat/benchmarks/ && n=$((n + 1))
done
say "   $n file(s) (XCCDF, OVAL, CPE)"

if [ -f "$HERE/license/license.xml" ]; then
    say "== CIS-CAT Pro license"
    install -d -m 0700 -o root -g root /opt/ciscat/license
    install -m 0600 -o root -g root "$HERE/license/license.xml" /opt/ciscat/license/license.xml
    say "   /opt/ciscat/license/license.xml (sent to the agents with the signed manifests)"
fi

CONFIG=$(ls "$HERE"/ciscat-config-*.tgz 2>/dev/null | tail -1 || true)
if [ -n "$CONFIG" ]; then
    SETUP_ARGS="$SETUP_ARGS --import $CONFIG"
    say "== configuration of the other master: $(basename "$CONFIG") (imported by the setup)"
fi

say "== master setup ($SETUP_ARGS)"
(cd "$DEST/master" && sh ciscat-master-setup.sh $SETUP_ARGS) || stop "master setup failed (see above)"

say "== groups published to the agents"
/opt/ciscat/bin/ciscat-fleet.py apply || stop "ciscat-fleet.py apply failed (see above)"
/opt/ciscat/bin/ciscat-fleet.py key

say ""
say "Agent packages for Satellite: $HERE/agents (SHA256SUMS there). The agents take the master's"
say "key from their group files at their first run (alert 100953 shows its sha256, compare with"
say "the key above)."
say "RESULT: OK - CIS-CAT bridge $VERSION installed on this master"
