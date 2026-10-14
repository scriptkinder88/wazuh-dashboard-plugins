#!/bin/sh
# CIS-CAT bridge 2.3.1: makes this Wazuh master (production) the same as the master the bundle
# was captured from (capture-ittest.sh), for everything CIS-CAT, keeping this site's PCI DSS
# reporting as it is. Run as root, in the unpacked bundle (a root-only folder, e.g.
# /opt/ciscat/install/bundle/ciscat-prod-2.3.1):
#   sh align-prod.sh [--no-dashboard-plugins]   on the Wazuh master (with or without the dashboard)
#   sh align-prod.sh --dashboard-only           on a separate Wazuh dashboard host
#
# What the PCI DSS dashboard and PDF reports are made of, and what happens to each:
#   rule.pci_dss of the alerts, from the rules (/var/ossec/etc/rules, /var/ossec/ruleset) and
#     the <ruleset> of ossec.conf                         not touched, checked at the end
#   requirement texts of the PDF report (server/integration-files/pci-requirements-pdfmake.js)
#     and of the module (common/compliance-requirements/pci-requirements.js) in the Wazuh plugin
#                                                         this site's copies put back
#   report logo and the other custom images, in the Wazuh plugin folder
#     (public/assets/custom/images, wiped by a plugin reinstall)  this site's copies put back
#   report header and footer, customization.* settings (data/wazuh/config/wazuh.yml)
#                                                         not touched, checked at the end
#   dashboards and visualizations (saved objects, in the indexer)   not touched
# It stops before changing anything when the Wazuh plugin of this dashboard has other local
# changes (e.g. a module page edited in the plugin bundles), or a custom plugin of the bundle
# would replace a different one: --no-dashboard-plugins then aligns everything else and leaves
# every dashboard plugin as it is.
#
# Steps: checks (nothing changed) -> backup in /opt/ciscat/backup/prod-before-<date> -> files
# of the other master (CIS benchmarks XCCDF/OVAL/CPE, license, os-library.json, tailoring CSVs,
# lists ciscat-exclusions/-schedule/-targets) -> custom dashboard plugins -> master setup
# (bridge, Active Response, bridge API user, signing key of this master, Wazuh plugin, agents
# into the group of their OS) and groups published -> PCI DSS files of this site put back ->
# check that every protected file is as before. The keys stay this master's own.
set -eu
VERSION=2.3.1
R=${CISCAT_TEST_ROOT:-}  # tests only: a fake root
HERE=$(cd "$(dirname "$0")" && pwd)
DASH=$R/usr/share/wazuh-dashboard
WZ=$DASH/plugins/wazuh
FLEET=$R/opt/ciscat/bin/ciscat-fleet.py
# this site's PCI DSS layer inside the Wazuh plugin folder (paths relative to it)
PCI_FILES="server/integration-files/pci-requirements-pdfmake.js common/compliance-requirements/pci-requirements.js"
CUSTOM_IMAGES=public/assets/custom
say() { printf '%s\n' "$*"; }
stop() { say "STOP: $*"; exit 1; }
own() { [ -n "$R" ] || chown "$@"; }  # tests run without the wazuh users
restart_dashboard() { [ -n "$R" ] || systemctl restart wazuh-dashboard; say "   wazuh-dashboard restarted"; }

KEEP_PLUGINS=""; DASH_ONLY=""
for a in "$@"; do
    case "$a" in
        --no-dashboard-plugins) KEEP_PLUGINS=1 ;;
        --dashboard-only) DASH_ONLY=1 ;;
        *) sed -n 2,34p "$0"; exit 2 ;;
    esac
done
[ -z "$KEEP_PLUGINS" ] || [ -z "$DASH_ONLY" ] || stop "--dashboard-only and --no-dashboard-plugins: nothing to do"
info() { sed -n "s/^$1=//p" "$HERE/ittest-info.txt" | head -1; }

say "== CIS-CAT bridge $VERSION: alignment of this host - checks (nothing changed yet)"
[ "$(id -u)" = 0 ] || stop "run as root"
case "$HERE" in
    /root|/root/*|/home/*|/tmp|/tmp/*|/var/tmp|/var/tmp/*|/dev/shm|/dev/shm/*)
        [ -n "$R" ] || stop "unpack the bundle in a root-only folder (e.g. /opt/ciscat/install/bundle), not in $HERE" ;;
esac
case "$(stat -c '%U %a' "$HERE")" in
    "root "*[2367][0-7]|"root "*[0-7][2367]) stop "$HERE is writable by group or others: chmod 700 $HERE" ;;
    "root "*) ;;
    *) stop "$HERE is not owned by root: chown -R root:root $HERE" ;;
esac
for t in unzip sha256sum python3 tar cmp diff; do command -v $t >/dev/null || stop "$t missing"; done
(cd "$HERE" && sha256sum -c --quiet SHA256SUMS) || stop "a file of the bundle is damaged (SHA256SUMS)"
[ "$(info version)" = "$VERSION" ] || stop "bundle of version '$(info version)', this script is $VERSION"
say "   bundle verified ($(grep -c . "$HERE/SHA256SUMS") files, captured $(info captured))"
if [ -z "$DASH_ONLY" ]; then
    [ -x "$R/var/ossec/bin/wazuh-control" ] || stop "no Wazuh manager on this host (on a dashboard host: --dashboard-only)"
    [ -d "$R/var/ossec/etc/lists" ] || stop "no /var/ossec/etc/lists"
fi

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
PLUGIN_ZIP=""
[ -z "$(info plugin_zip)" ] || PLUGIN_ZIP=$HERE/$(info plugin_zip)
CUSTOM=$(info custom_plugins)
INSTALL_CUSTOM=""
REPLACE_WAZUH=""
DASHBOARD=""
[ -d "$DASH/plugins" ] && DASHBOARD=1
if [ -z "$DASHBOARD" ]; then
    [ -z "$DASH_ONLY" ] || stop "no Wazuh dashboard on this host"
    say "   no dashboard on this host: on the dashboard host, with this bundle: sh align-prod.sh --dashboard-only"
elif [ -n "$KEEP_PLUGINS" ]; then
    say "   --no-dashboard-plugins: every dashboard plugin stays as it is"
else
    if command -v rpm >/dev/null 2>&1 && rpm -q wazuh-dashboard >/dev/null 2>&1; then
        TOOL=rpm; DASH_VERSION=$(rpm -q --qf '%{VERSION}-%{RELEASE}' wazuh-dashboard)
        rpm -V wazuh-dashboard > "$W/verify" 2>/dev/null || true
    elif command -v dpkg >/dev/null 2>&1 && dpkg -s wazuh-dashboard >/dev/null 2>&1; then
        TOOL=dpkg; DASH_VERSION=$(dpkg-query -W -f '${Version}' wazuh-dashboard)
        dpkg -V wazuh-dashboard > "$W/verify" 2>/dev/null || true
    else
        stop "the wazuh-dashboard package is not known to rpm or dpkg: its plugins cannot be checked (--no-dashboard-plugins)"
    fi
    say "   wazuh-dashboard $DASH_VERSION (other master: $(info dashboard_version))"
    awk '($1 == "missing" || $1 ~ /[S5]/) { print $NF }' "$W/verify" > "$W/changed"
    if [ -n "$PLUGIN_ZIP" ] && [ ! -d "$WZ" ]; then
        say "   Wazuh plugin: not installed here, installed"
        REPLACE_WAZUH=1
    elif [ -n "$PLUGIN_ZIP" ]; then
        # local changes to the Wazuh plugin, apart from this site's PCI DSS layer (put back)
        grep '^/usr/share/wazuh-dashboard/plugins/wazuh/' "$W/changed" \
            | grep -Ev "^/usr/share/wazuh-dashboard/plugins/wazuh/($CUSTOM_IMAGES/|server/integration-files/pci-requirements-pdfmake\.js\$|common/compliance-requirements/pci-requirements\.js\$)" \
            > "$W/wazuh-other" || true
        if [ -f "$WZ/server/lib/reporting/sca-report.js" ]; then
            say "   Wazuh plugin: an earlier bridge build, replaced"
        elif [ -s "$W/wazuh-other" ]; then
            say "   the Wazuh plugin of this dashboard differs from the wazuh-dashboard package in $(grep -c . "$W/wazuh-other") other file(s), e.g.:"
            { grep -i 'report\|pci' "$W/wazuh-other" || true; cat "$W/wazuh-other"; } | awk '!s[$0]++' | head -15 | sed 's/^/     /'
            stop "the Wazuh plugin of this dashboard has local changes that cannot be carried over (only the PCI DSS requirement texts and the custom images can). Nothing was changed. To align everything else and keep the dashboard plugins as they are: sh align-prod.sh --no-dashboard-plugins"
        else
            say "   Wazuh plugin: as in the wazuh-dashboard package, replaced"
        fi
        REPLACE_WAZUH=1
        for f in $PCI_FILES; do
            if grep -qx "/usr/share/wazuh-dashboard/plugins/wazuh/$f" "$W/changed"; then
                say "   PCI DSS requirement texts customized here: $f (kept)"
            fi
        done
        n=$(find "$WZ/$CUSTOM_IMAGES" -type f 2>/dev/null | grep -c . || true)
        [ "$n" -eq 0 ] || say "   custom images (report logo...): $n file(s) (kept)"
    fi
    for p in $CUSTOM; do
        [ "$DASH_VERSION" = "$(info dashboard_version)" ] \
            || stop "custom plugin $p was captured on wazuh-dashboard $(info dashboard_version), this one is $DASH_VERSION (--no-dashboard-plugins)"
        mkdir -p "$W/plugins"
        tar -xzf "$HERE/dashboard-plugins/$p.tgz" -C "$W/plugins"
        [ -d "$W/plugins/$p" ] || stop "dashboard-plugins/$p.tgz does not hold the folder $p"
        if [ -d "$DASH/plugins/$p" ] && diff -rq "$W/plugins/$p" "$DASH/plugins/$p" >/dev/null 2>&1; then
            say "   custom plugin $p: already the same"
            continue
        fi
        if [ -d "$DASH/plugins/$p" ]; then
            changed=""
            grep -q "^/usr/share/wazuh-dashboard/plugins/$p/" "$W/changed" && changed=1
            case "$TOOL" in
                rpm) rpm -qf "$DASH/plugins/$p" >/dev/null 2>&1 || changed=1 ;;
                dpkg) dpkg -S "$DASH/plugins/$p" >/dev/null 2>&1 || changed=1 ;;
            esac
            [ -z "$changed" ] || stop "plugin $p of this dashboard has its own changes, different from the other master's: nothing was changed (--no-dashboard-plugins)"
        fi
        INSTALL_CUSTOM="$INSTALL_CUSTOM $p"
        say "   custom plugin $p: installed from the other master"
    done
fi
[ -z "$DASH_ONLY" ] || [ -n "$REPLACE_WAZUH$INSTALL_CUSTOM" ] || stop "nothing to install on this dashboard"

# files that must stay as they are: PCI DSS mapping (rules, decoders, <ruleset>), dashboard
# settings (wazuh.yml), dashboard configuration, this site's PCI DSS layer of the Wazuh plugin,
# agent groups not managed by the bridge
protected() {
    for d in "$DASH/data/wazuh/config" "$R/etc/wazuh-dashboard" "$WZ/$CUSTOM_IMAGES" \
            "$R/var/ossec/etc/rules" "$R/var/ossec/etc/decoders" "$R/var/ossec/ruleset/rules" \
            "$R/var/ossec/ruleset/decoders" "$R/var/ossec/etc/shared"; do
        [ -d "$d" ] && find "$d" -type f
    done | grep -v -e '/ciscat_rules\.xml$' -e '/shared/ciscat-' -e '/shared/ar\.conf$' -e '/merged\.mg$' \
        | sort | while IFS= read -r f; do sha256sum "$f"; done
    for f in $PCI_FILES; do
        [ -f "$WZ/$f" ] && sha256sum "$WZ/$f"
    done
    if [ -f "$R/var/ossec/etc/ossec.conf" ]; then
        echo "$(sed -n '/<ruleset>/,/<\/ruleset>/p' "$R/var/ossec/etc/ossec.conf" | sha256sum | cut -d' ' -f1)  $R/var/ossec/etc/ossec.conf <ruleset>"
    fi
    return 0
}

STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP=$R/opt/ciscat/backup/prod-before-$STAMP
say "== saved in /opt/ciscat/backup/prod-before-$STAMP"
install -d -m 0755 "$R/opt/ciscat"
install -d -m 0700 "$R/opt/ciscat/backup" "$BACKUP"
protected > "$BACKUP/protected.sha256"
set --
if [ -z "$DASH_ONLY" ]; then
    for p in opt/ciscat/etc opt/ciscat/benchmarks opt/ciscat/license opt/ciscat/tailoring var/ossec/etc/ossec.conf; do
        [ -e "$R/$p" ] && set -- "$@" "$p"
    done
    for l in "$R"/var/ossec/etc/lists/ciscat-*; do
        [ -f "$l" ] && set -- "$@" "var/ossec/etc/lists/$(basename "$l")"
    done
fi
for p in usr/share/wazuh-dashboard/data/wazuh/config etc/wazuh-dashboard; do
    [ -e "$R/$p" ] && set -- "$@" "$p"
done
[ -z "$REPLACE_WAZUH" ] || [ ! -d "$WZ" ] || set -- "$@" usr/share/wazuh-dashboard/plugins/wazuh
for p in $INSTALL_CUSTOM; do
    [ -d "$DASH/plugins/$p" ] && set -- "$@" "usr/share/wazuh-dashboard/plugins/$p"
done
[ $# -eq 0 ] || tar -czf "$BACKUP/files.tgz" -C "${R:-/}" "$@"
say "   $# item(s) and the checksums of $(grep -c . "$BACKUP/protected.sha256" || true) protected file(s)"
if [ -n "$REPLACE_WAZUH" ]; then
    # this site's PCI DSS layer of the Wazuh plugin, to put back after the new plugin
    K=$BACKUP/pci-keep
    install -d -m 0700 "$K"
    for f in $PCI_FILES; do
        [ -f "$WZ/$f" ] || continue
        mkdir -p "$K/$(dirname "$f")" && cp -p "$WZ/$f" "$K/$f"
    done
    [ ! -d "$WZ/$CUSTOM_IMAGES" ] || { mkdir -p "$K/$(dirname "$CUSTOM_IMAGES")" && cp -pR "$WZ/$CUSTOM_IMAGES" "$K/$CUSTOM_IMAGES"; }
    say "   PCI DSS layer of the Wazuh plugin: $BACKUP/pci-keep"
fi

if [ -z "$DASH_ONLY" ]; then
    # same set of files as the other master: the ones it does not have are moved to the backup
    put_dir() {  # <bundle dir> <target dir> <mode>
        install -d -m 0750 -o root -g root "$2"
        for f in "$2"/*; do
            [ -f "$f" ] || continue
            [ -f "$1/$(basename "$f")" ] && continue
            install -d -m 0700 "$BACKUP/removed$(dirname "${f#$R}")"
            mv "$f" "$BACKUP/removed${f#$R}"
            say "   moved to the backup: ${f#$R}"
        done
        n=0
        for f in "$1"/*; do
            [ -f "$f" ] || continue
            install -m "$3" -o root -g root "$f" "$2/" && n=$((n + 1))
        done
        say "   ${2#$R}: $n file(s)"
    }
    say "== files of the other master"
    S=$HERE/root
    put_dir "$S/opt/ciscat/benchmarks" "$R/opt/ciscat/benchmarks" 0640
    install -d -m 0700 -o root -g root "$R/opt/ciscat/license"
    install -m 0600 -o root -g root "$S/opt/ciscat/license/license.xml" "$R/opt/ciscat/license/license.xml"
    say "   /opt/ciscat/license/license.xml"
    install -d -m 0750 -o root -g root "$R/opt/ciscat/etc"
    install -m 0640 -o root -g root "$S/opt/ciscat/etc/os-library.json" "$R/opt/ciscat/etc/os-library.json"
    say "   /opt/ciscat/etc/os-library.json"
    install -d -m 0750 -o root -g root "$R/opt/ciscat/tailoring"
    put_dir "$S/opt/ciscat/tailoring/exclusions" "$R/opt/ciscat/tailoring/exclusions" 0640
    for l in ciscat-exclusions ciscat-schedule ciscat-targets; do
        if [ -f "$S/var/ossec/etc/lists/$l" ]; then
            install -m 0660 "$S/var/ossec/etc/lists/$l" "$R/var/ossec/etc/lists/$l"
            own wazuh:wazuh "$R/var/ossec/etc/lists/$l"
            say "   /var/ossec/etc/lists/$l"
        elif [ -f "$R/var/ossec/etc/lists/$l" ]; then
            install -d -m 0700 "$BACKUP/removed/var/ossec/etc/lists"
            mv "$R/var/ossec/etc/lists/$l" "$BACKUP/removed/var/ossec/etc/lists/"
            say "   moved to the backup: /var/ossec/etc/lists/$l (the other master has none)"
        fi
    done
fi

for p in $INSTALL_CUSTOM; do
    say "== dashboard plugin $p"
    rm -rf "${DASH:?}/plugins/$p"
    tar -xzf "$HERE/dashboard-plugins/$p.tgz" -C "$DASH/plugins"
    own -R wazuh-dashboard:wazuh-dashboard "$DASH/plugins/$p"
    say "   installed"
done

say "== master package in /opt/ciscat/install/$VERSION"
DEST=$R/opt/ciscat/install/$VERSION
install -d -m 0700 -o root -g root "$R/opt/ciscat/install" "$DEST"
(cd "$DEST" && unzip -o -q "$HERE/ciscat-master-$VERSION.zip")
chown -R root:root "$DEST" && chmod -R go-w "$DEST"
[ -z "$REPLACE_WAZUH" ] || install -m 0640 -o root -g root "$PLUGIN_ZIP" "$DEST/master/"

if [ -z "$DASH_ONLY" ]; then
    SETUP_ARGS="--auto-assign"
    [ -n "$REPLACE_WAZUH" ] || SETUP_ARGS="$SETUP_ARGS --no-dashboard"
    say "== master setup ($SETUP_ARGS)"
    (cd "$DEST/master" && sh ciscat-master-setup.sh $SETUP_ARGS) || stop "master setup failed (see above); what was replaced is in $BACKUP"
    say "== groups published to the agents"
    "$FLEET" apply || stop "ciscat-fleet.py apply failed (see above)"
    "$FLEET" key
else
    say "== Wazuh plugin"
    (cd "$DEST/master" && sh "ciscat-bridge-install-$VERSION.sh" --plugin-file "$DEST/master/$(basename "$PLUGIN_ZIP")" \
        --plugin-sha256 "$(info plugin_sha256)") || stop "plugin installation failed (see above); what was replaced is in $BACKUP"
fi

if [ -n "$REPLACE_WAZUH" ]; then
    say "== PCI DSS layer of this site put back into the Wazuh plugin"
    K=$BACKUP/pci-keep
    for f in $PCI_FILES; do
        [ -f "$K/$f" ] || continue
        if [ ! -f "$WZ/$f" ]; then
            say "   WARNING: the new plugin has no $f: this site's copy not put back"
        elif cmp -s "$K/$f" "$WZ/$f"; then
            say "   $f: the same"
        else
            cp -p "$K/$f" "$WZ/$f" && own wazuh-dashboard:wazuh-dashboard "$WZ/$f"
            say "   $f: this site's version put back"
        fi
    done
    if [ -d "$K/$CUSTOM_IMAGES" ]; then
        mkdir -p "$WZ/$CUSTOM_IMAGES"
        cp -pR "$K/$CUSTOM_IMAGES/." "$WZ/$CUSTOM_IMAGES/"
        own -R wazuh-dashboard:wazuh-dashboard "$WZ/public/assets/custom"
        say "   custom images (report logo...): $(find "$K/$CUSTOM_IMAGES" -type f | grep -c . || true) file(s) put back"
    fi
fi
[ -z "$REPLACE_WAZUH$INSTALL_CUSTOM" ] || restart_dashboard

say "== PCI DSS mapping, dashboard settings, PCI DSS layer, rules and other groups: as before?"
protected > "$W/all-after"
# a file the new Wazuh plugin adds (none here before) is not a change of this site's layer
awk -v wz="$WZ/" 'NR == FNR { p = $0; sub(/^[0-9a-f]+  /, "", p); seen[p] = 1; next }
    { p = $0; sub(/^[0-9a-f]+  /, "", p); if (index(p, wz) == 1 && !(p in seen)) next; print }' \
    "$BACKUP/protected.sha256" "$W/all-after" > "$W/after"
if cmp -s "$BACKUP/protected.sha256" "$W/after"; then
    say "   unchanged: $(grep -c . "$W/after" || true) file(s)"
    RESULT="OK"
else
    say "   CHANGED (the copies before are in $BACKUP):"
    diff "$BACKUP/protected.sha256" "$W/after" | sed -n 's/^[<>] [0-9a-f]*  //p' | sort -u | sed "s#^$R#     #"
    RESULT="CHECK - a protected file changed (see above)"
fi
say ""
[ -n "$DASH_ONLY" ] || say "Keys: this master's own (above); the agents take it from their group files at their first run (alert 100953 shows its sha256)."
say "Backup: $BACKUP"
say "RESULT: $RESULT - CIS-CAT bridge $VERSION, this host aligned to the other master"
[ "$RESULT" = OK ]
