#!/bin/sh
# CIS-CAT bridge 2.3.1: captures from a configured Wazuh master (the test master) everything
# another master needs to become the same, in one file. Run as root, in the unpacked capture kit
# (a root-only folder, e.g. /opt/ciscat/install/capture):
#   sh capture-ittest.sh [--no-plugin]
#
# Takes, from this master:
#   /opt/ciscat/benchmarks/*                  original CIS benchmarks (XCCDF, OVAL, CPE)
#   /opt/ciscat/license/license.xml           CIS-CAT Pro license
#   /opt/ciscat/etc/os-library.json           benchmarks per OS, active flags
#   /opt/ciscat/tailoring/exclusions/*        tailoring CSVs
#   /var/ossec/etc/lists/ciscat-exclusions, ciscat-schedule, ciscat-targets
#                                             exclusions, schedules, benchmark groups
#   wazuh-dashboard-plugins_wazuh_*.zip       the dashboard plugin of this release (checked)
#   other dashboard plugins changed from the wazuh-dashboard package (custom plugins)
# Never: API passwords, the bridge API settings, the signing keys, agent status or history.
# Output: out/ciscat-prod-2.3.1-<date>.tar.gz (+ .sha256), with align-prod.sh to run on the
# other master. The archive holds licensed CIS content: keep it inside the organization.
set -eu
VERSION=2.3.1
PLUGIN_SHA=35d4b89a0e8a5b75aa8befa3f71b3eb7164b6f6e8d41ff8962f59bf88e05a8c4
R=${CISCAT_TEST_ROOT:-}  # tests only: a fake root
[ -z "$R" ] || PLUGIN_SHA=${CISCAT_TEST_PLUGIN_SHA:-$PLUGIN_SHA}
HERE=$(cd "$(dirname "$0")" && pwd)
DASH=$R/usr/share/wazuh-dashboard
say() { printf '%s\n' "$*"; }
stop() { say "STOP: $*"; exit 1; }

NO_PLUGIN=""
for a in "$@"; do
    case "$a" in
        --no-plugin) NO_PLUGIN=1 ;;
        *) sed -n 2,21p "$0"; exit 2 ;;
    esac
done

say "== CIS-CAT bridge $VERSION: capture of this master"
[ "$(id -u)" = 0 ] || stop "run as root"
case "$HERE" in
    /root|/root/*|/home/*|/tmp|/tmp/*|/var/tmp|/var/tmp/*|/dev/shm|/dev/shm/*)
        [ -n "$R" ] || stop "unpack the kit in a root-only folder (e.g. /opt/ciscat/install/capture), not in $HERE" ;;
esac
for t in sha256sum tar gzip; do command -v $t >/dev/null || stop "$t missing"; done
(cd "$HERE" && sha256sum -c --quiet SHA256SUMS) || stop "a file of the kit is damaged (SHA256SUMS)"
[ -x "$R/var/ossec/bin/wazuh-control" ] || stop "no Wazuh manager on this host"
SRC=$(cat "$R/opt/ciscat/VERSION" 2>/dev/null || true)
[ "$SRC" = "$VERSION" ] || stop "bridge on this master: '${SRC:-none}', expected $VERSION"

umask 077  # licensed benchmarks and the exclusions of every host: root only
STAMP=$(date +%Y%m%d-%H%M)
OUT=$HERE/out
NAME=ciscat-prod-$VERSION
install -d -m 0700 "$OUT"
W=$(mktemp -d "$OUT/.capture.XXXXXX")
trap 'rm -rf "$W"' EXIT
B=$W/$NAME
mkdir -p "$B/root/opt/ciscat/benchmarks" "$B/root/opt/ciscat/license" "$B/root/opt/ciscat/etc" \
    "$B/root/opt/ciscat/tailoring/exclusions" "$B/root/var/ossec/etc/lists"

say "== CIS benchmarks (originals)"
n=0
for f in "$R"/opt/ciscat/benchmarks/*; do
    [ -f "$f" ] && [ ! -L "$f" ] || continue
    cp -p "$f" "$B/root/opt/ciscat/benchmarks/" && n=$((n + 1))
done
[ "$n" -gt 0 ] || stop "no benchmark in /opt/ciscat/benchmarks"
say "   $n file(s): $(ls "$B/root/opt/ciscat/benchmarks" | grep -ci 'xccdf' || true) XCCDF, $(ls "$B/root/opt/ciscat/benchmarks" | grep -ci 'oval' || true) OVAL, $(ls "$B/root/opt/ciscat/benchmarks" | grep -ci 'cpe' || true) CPE"

say "== CIS-CAT Pro license"
[ -s "$R/opt/ciscat/license/license.xml" ] || stop "no /opt/ciscat/license/license.xml"
cp -p "$R/opt/ciscat/license/license.xml" "$B/root/opt/ciscat/license/"
say "   license.xml"

say "== CIS-CAT configuration"
[ -s "$R/opt/ciscat/etc/os-library.json" ] || stop "no /opt/ciscat/etc/os-library.json"
cp -p "$R/opt/ciscat/etc/os-library.json" "$B/root/opt/ciscat/etc/"
say "   os-library.json"
t=0
for f in "$R"/opt/ciscat/tailoring/exclusions/*; do
    [ -f "$f" ] && [ ! -L "$f" ] || continue
    cp -p "$f" "$B/root/opt/ciscat/tailoring/exclusions/" && t=$((t + 1))
done
say "   tailoring: $t file(s)"
LISTS=""
for l in ciscat-exclusions ciscat-schedule ciscat-targets; do
    f=$R/var/ossec/etc/lists/$l
    [ -f "$f" ] && [ ! -L "$f" ] || continue
    cp -p "$f" "$B/root/var/ossec/etc/lists/" && LISTS="$LISTS $l"
done
say "   lists:${LISTS:- none}"

say "== dashboard"
DASHBOARD=no; DASH_VERSION=""; PLUGIN_NAME=""; CUSTOM=""
pkg_tool() {
    if command -v rpm >/dev/null 2>&1 && rpm -q wazuh-dashboard >/dev/null 2>&1; then echo rpm
    elif command -v dpkg >/dev/null 2>&1 && dpkg -s wazuh-dashboard >/dev/null 2>&1; then echo dpkg
    else echo none; fi
}
if [ -d "$DASH/plugins" ]; then
    DASHBOARD=yes
    TOOL=$(pkg_tool)
    case "$TOOL" in
        rpm) DASH_VERSION=$(rpm -q --qf '%{VERSION}-%{RELEASE}' wazuh-dashboard); rpm -V wazuh-dashboard > "$W/verify" 2>/dev/null || true ;;
        dpkg) DASH_VERSION=$(dpkg-query -W -f '${Version}' wazuh-dashboard); dpkg -V wazuh-dashboard > "$W/verify" 2>/dev/null || true ;;
        *) stop "the wazuh-dashboard package is not known to rpm or dpkg: cannot tell the custom plugins" ;;
    esac
    say "   wazuh-dashboard $DASH_VERSION"
    # plugin folders with files changed (size or digest) or missing, and folders of no package
    awk '($1 == "missing" || $1 ~ /[S5]/) { print $NF }' "$W/verify" \
        | sed -n 's#^/usr/share/wazuh-dashboard/plugins/\([^/]*\)/.*#\1#p' > "$W/changed"
    for d in "$DASH"/plugins/*/; do
        [ -d "$d" ] || continue
        p=$(basename "$d")
        case "$TOOL" in
            rpm) rpm -qf "${d%/}" >/dev/null 2>&1 || echo "$p" >> "$W/changed" ;;
            dpkg) dpkg -S "${d%/}" >/dev/null 2>&1 || echo "$p" >> "$W/changed" ;;
        esac
    done
    for p in $(sort -u "$W/changed"); do
        [ "$p" != wazuh ] || continue  # the Wazuh plugin travels as its release zip
        [ -d "$DASH/plugins/$p" ] || continue
        mkdir -p "$B/dashboard-plugins"
        tar -czf "$B/dashboard-plugins/$p.tgz" -C "$DASH/plugins" --owner=0 --group=0 "$p"
        CUSTOM="$CUSTOM $p"
    done
    say "   custom plugins besides wazuh:${CUSTOM:- none}"
    [ -f "$DASH/plugins/wazuh/server/lib/reporting/sca-report.js" ] \
        || say "   WARNING: the Wazuh plugin of this dashboard is not a bridge build"
fi
if [ -z "$NO_PLUGIN" ]; then
    # the browser may add .zip or " (1)" to the name of the zip
    { ls -d "$HERE"/wazuh-dashboard-plugins_wazuh_* 2>/dev/null || true
      find "$R/opt/ciscat/install" -maxdepth 4 -type f -name 'wazuh-dashboard-plugins_wazuh_*' 2>/dev/null || true
    } > "$W/candidates"
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        if [ "$(sha256sum "$f" | cut -d' ' -f1)" = "$PLUGIN_SHA" ]; then
            PLUGIN_NAME=$(basename "$f" | sed 's/ ([0-9]*)//; s/\.zip\.zip$/.zip/')
            case "$PLUGIN_NAME" in *.zip) ;; *) PLUGIN_NAME=$PLUGIN_NAME.zip ;; esac
            cp "$f" "$B/$PLUGIN_NAME"
            break
        fi
    done < "$W/candidates"
    [ -n "$PLUGIN_NAME" ] || stop "no dashboard plugin zip with sha256 $PLUGIN_SHA in $HERE or /opt/ciscat/install: put it next to capture-ittest.sh (or --no-plugin)"
    say "   plugin zip: $PLUGIN_NAME (sha256 verified)"
else
    say "   --no-plugin: the bundle leaves the Wazuh plugin of the other master as it is"
fi

say "== bundle"
for f in "$HERE/align-prod.sh" "$HERE/pci-keep.py" "$HERE/ciscat-master-$VERSION.zip"; do
    [ -f "$f" ] || stop "$(basename "$f") missing from the kit"
    cp "$f" "$B/"
done
cat > "$B/ittest-info.txt" <<EOF
version=$VERSION
captured=$(date '+%F %T')
bridge=$SRC
dashboard=$DASHBOARD
dashboard_version=$DASH_VERSION
plugin_zip=$PLUGIN_NAME
plugin_sha256=$([ -n "$PLUGIN_NAME" ] && echo "$PLUGIN_SHA" || true)
custom_plugins=$(echo $CUSTOM)
lists=$(echo $LISTS)
benchmarks=$n
EOF
# nothing secret may travel: keys, API password and settings stay on each master
bad=$(find "$B" \( -name 'ciscat-manifest*' -o -name '*.pem' -o -name '.ciscat_api_pass' \
    -o -name 'ciscat-orchestrator.conf' \) -print | head -5)
[ -z "$bad" ] || stop "secret file in the bundle: $bad"
(cd "$B" && find . -type f ! -name SHA256SUMS -exec sha256sum {} + | sort -k2 > SHA256SUMS)
TAR=$OUT/$NAME-$STAMP.tar.gz
tar -czf "$TAR" -C "$W" --owner=0 --group=0 "$NAME"
(cd "$OUT" && sha256sum "$(basename "$TAR")" > "$(basename "$TAR").sha256")
say ""
say "RESULT: OK - $TAR ($(du -h "$TAR" | cut -f1)), checksum in $(basename "$TAR").sha256"
say "On the other master, as root:"
say "  install -d -m 0700 /opt/ciscat/install/bundle && tar -xzf $(basename "$TAR") -C /opt/ciscat/install/bundle"
say "  cd /opt/ciscat/install/bundle/$NAME && sh align-prod.sh"
