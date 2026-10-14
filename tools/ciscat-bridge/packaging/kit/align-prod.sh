#!/bin/sh
# CIS-CAT bridge 2.3.1: makes this Wazuh master (production) the same as the master the bundle
# was captured from (capture-ittest.sh), for everything CIS-CAT. Run as root, in the unpacked
# bundle (a root-only folder, e.g. /opt/ciscat/install/bundle/ciscat-prod-2.3.1):
#   sh align-prod.sh [--no-dashboard-plugins]
#
# 1. checks, changing nothing: the bundle (SHA256SUMS), the Wazuh manager and, when the dashboard
#    runs here, its plugins. It stops when the Wazuh plugin of this dashboard has local changes
#    (e.g. a customized PCI DSS report) that the plugin of the bundle would replace, or when a
#    custom plugin of the bundle would replace a different plugin of this dashboard.
#    --no-dashboard-plugins aligns everything else and leaves every dashboard plugin as it is.
# 2. saves what it replaces in /opt/ciscat/backup/prod-before-<date>
# 3. puts the files of the other master in place: CIS benchmarks (XCCDF, OVAL, CPE), license,
#    os-library.json, tailoring CSVs, the lists ciscat-exclusions, ciscat-schedule,
#    ciscat-targets; the custom dashboard plugins
# 4. runs the master setup (bridge, Active Response, API user of the bridge, signing key of this
#    master, Wazuh plugin, agents into the group of their OS) and publishes the groups
# 5. checks that the dashboard settings (wazuh.yml: report header, footer, logos), the
#    dashboard configuration, the Wazuh rules and decoders and the agent groups not managed by
#    the bridge are as before
# The keys stay this master's own: the agents take the key from their master.
set -eu
VERSION=2.3.1
R=${CISCAT_TEST_ROOT:-}  # tests only: a fake root
HERE=$(cd "$(dirname "$0")" && pwd)
DASH=$R/usr/share/wazuh-dashboard
FLEET=$R/opt/ciscat/bin/ciscat-fleet.py
say() { printf '%s\n' "$*"; }
stop() { say "STOP: $*"; exit 1; }
own() { [ -n "$R" ] || chown "$@"; }  # tests run without the wazuh users

KEEP_PLUGINS=""
for a in "$@"; do
    case "$a" in
        --no-dashboard-plugins) KEEP_PLUGINS=1 ;;
        *) sed -n 2,23p "$0"; exit 2 ;;
    esac
done
info() { sed -n "s/^$1=//p" "$HERE/ittest-info.txt" | head -1; }

say "== CIS-CAT bridge $VERSION: alignment of this master - checks (nothing changed yet)"
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
for t in unzip sha256sum python3 tar; do command -v $t >/dev/null || stop "$t missing"; done
(cd "$HERE" && sha256sum -c --quiet SHA256SUMS) || stop "a file of the bundle is damaged (SHA256SUMS)"
[ "$(info version)" = "$VERSION" ] || stop "bundle of version '$(info version)', this script is $VERSION"
say "   bundle verified ($(grep -c . "$HERE/SHA256SUMS") files, captured $(info captured))"
[ -x "$R/var/ossec/bin/wazuh-control" ] || stop "no Wazuh manager on this host"
[ -d "$R/var/ossec/etc/lists" ] || stop "no /var/ossec/etc/lists"

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
PLUGIN_ZIP=""
[ -z "$(info plugin_zip)" ] || PLUGIN_ZIP=$HERE/$(info plugin_zip)
CUSTOM=$(info custom_plugins)
INSTALL_CUSTOM=""
DASHBOARD=""
[ -d "$DASH/plugins" ] && DASHBOARD=1
if [ -z "$DASHBOARD" ]; then
    say "   no dashboard on this host: dashboard plugins left out (install them on the dashboard host)"
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
    # the Wazuh plugin makes the PCI DSS reports: never replace local changes to it
    if [ -n "$PLUGIN_ZIP" ] && [ -d "$DASH/plugins/wazuh" ]; then
        grep '^/usr/share/wazuh-dashboard/plugins/wazuh/' "$W/changed" > "$W/wazuh-changed" || true
        if [ -f "$DASH/plugins/wazuh/server/lib/reporting/sca-report.js" ]; then
            say "   Wazuh plugin: an earlier bridge build, replaced (saved first)"
        elif [ -s "$W/wazuh-changed" ]; then
            say "   the Wazuh plugin of this dashboard differs from the wazuh-dashboard package in $(grep -c . "$W/wazuh-changed") file(s), e.g.:"
            { grep -i 'report\|pci' "$W/wazuh-changed" || true; cat "$W/wazuh-changed"; } | awk '!s[$0]++' | head -15 | sed 's/^/     /'
            stop "the Wazuh plugin of this dashboard has local changes (the PCI DSS report customization?) that the plugin of this bundle would replace. Nothing was changed. To align everything else and keep the dashboard plugins as they are: sh align-prod.sh --no-dashboard-plugins"
        else
            say "   Wazuh plugin: as in the wazuh-dashboard package, replaced by $(basename "$PLUGIN_ZIP")"
        fi
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

# files that must stay as they are: dashboard settings (wazuh.yml, logos), dashboard
# configuration, Wazuh rules and decoders, agent groups not managed by the bridge
protected() {
    for d in "$DASH/data/wazuh/config" "$R/etc/wazuh-dashboard" "$R/var/ossec/etc/rules" \
            "$R/var/ossec/etc/decoders" "$R/var/ossec/etc/shared"; do
        [ -d "$d" ] && find "$d" -type f
    done | grep -v -e '/ciscat_rules\.xml$' -e '/shared/ciscat-' -e '/shared/ar\.conf$' -e '/merged\.mg$' \
        | sort | while IFS= read -r f; do sha256sum "$f"; done
}

STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP=$R/opt/ciscat/backup/prod-before-$STAMP
say "== saved in /opt/ciscat/backup/prod-before-$STAMP"
install -d -m 0755 "$R/opt/ciscat"
install -d -m 0700 "$R/opt/ciscat/backup" "$BACKUP"
protected > "$BACKUP/protected.sha256"
set --
for p in opt/ciscat/etc opt/ciscat/benchmarks opt/ciscat/license opt/ciscat/tailoring \
        var/ossec/etc/ossec.conf usr/share/wazuh-dashboard/data/wazuh/config etc/wazuh-dashboard; do
    [ -e "$R/$p" ] && set -- "$@" "$p"
done
for l in "$R"/var/ossec/etc/lists/ciscat-*; do
    [ -f "$l" ] && set -- "$@" "var/ossec/etc/lists/$(basename "$l")"
done
for p in $INSTALL_CUSTOM; do
    [ -d "$DASH/plugins/$p" ] && set -- "$@" "usr/share/wazuh-dashboard/plugins/$p"
done
[ $# -eq 0 ] || tar -czf "$BACKUP/files.tgz" -C "${R:-/}" "$@"
say "   $# item(s) and the checksums of $(grep -c . "$BACKUP/protected.sha256" || true) protected file(s)"

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
SETUP_ARGS="--auto-assign"
if [ -n "$DASHBOARD" ] && [ -z "$KEEP_PLUGINS" ] && [ -n "$PLUGIN_ZIP" ]; then
    install -m 0640 -o root -g root "$PLUGIN_ZIP" "$DEST/master/"
else
    SETUP_ARGS="$SETUP_ARGS --no-dashboard"
fi

say "== master setup ($SETUP_ARGS)"
(cd "$DEST/master" && sh ciscat-master-setup.sh $SETUP_ARGS) || stop "master setup failed (see above); what was replaced is in $BACKUP"
if [ -n "$INSTALL_CUSTOM" ] && case "$SETUP_ARGS" in *--no-dashboard*) true ;; *) false ;; esac; then
    [ -n "$R" ] || systemctl restart wazuh-dashboard
    say "   wazuh-dashboard restarted (custom plugins)"
fi

say "== groups published to the agents"
"$FLEET" apply || stop "ciscat-fleet.py apply failed (see above)"
"$FLEET" key

say "== dashboard settings, PCI DSS reports, rules and other groups: as before?"
protected > "$W/after"
if cmp -s "$BACKUP/protected.sha256" "$W/after"; then
    say "   unchanged: $(grep -c . "$W/after" || true) file(s)"
    RESULT="OK"
else
    say "   CHANGED (the copies before are in $BACKUP/files.tgz for the dashboard files):"
    diff "$BACKUP/protected.sha256" "$W/after" | sed -n 's/^[<>] [0-9a-f]*  //p' | sort -u | sed "s#^$R#     #"
    RESULT="CHECK - a protected file changed (see above)"
fi
say ""
say "Keys: this master's own (above); the agents take it from their group files at their first run"
say "(alert 100953 shows its sha256). Backup: $BACKUP"
say "RESULT: $RESULT - CIS-CAT bridge $VERSION, this master aligned to the other one"
[ "$RESULT" = OK ]
