#!/bin/sh
# install-linux-agent.sh - CIS-CAT bridge @VERSION@, Linux agent preparation (shell only).
# Run as root on each Linux agent (RHEL, Oracle Linux, Rocky, Debian...):
#   sh install-linux-agent.sh [--pubkey <file>]
# The master's public key (manifests must be signed with it) comes from the master with the group
# files, and the agent keeps the first one it receives. To pin it at install time instead, put
# ciscat-manifest.pub (master: /opt/ciscat/etc) next to this script or give --pubkey <file>.
# What it does (and only this):
#   1. CIS-CAT Pro in /opt/ciscat/Assessor: installs or updates it from the package when the
#      package carries it (full agent package), else checks it; /opt/ciscat owned by root
#   2. exit.on.invalid.signature=false in the Assessor settings (the custom benchmark is unsigned)
#   3. installs ciscat-bootstrap.sh (SHA-256 checked, root:wazuh 0750) in active-response/bin and,
#      when given, the master's public key in /var/lib/wazuh-ciscat; everything else comes from
#      the manager at each run
#   4. moves the files of earlier versions to /var/lib/wazuh-ciscat/backup-<date>
#   5. SELinux: default labels (restorecon) on /opt/ciscat and /var/lib/wazuh-ciscat
# Prints RESULT: OK, or STOP / WARNING lines.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
PUBKEY="$HERE/ciscat-manifest.pub"
case "${1:-}" in
    --pubkey) PUBKEY=${2:-}; [ -s "$PUBKEY" ] || { echo "STOP: $PUBKEY not found"; exit 1; } ;;
    "") ;;
    *) echo "usage: sh $0 [--pubkey <ciscat-manifest.pub>]"; exit 2 ;;
esac
SHA=@BOOTSTRAP_SHA@
BIN=/var/ossec/active-response/bin
ASSESSOR=/opt/ciscat/Assessor
DATA=/var/lib/wazuh-ciscat
STAMP=$(date +%Y%m%d%H%M)
BACKUP=$DATA/backup-$STAMP
WARN=0
say() { printf '%s\n' "$*"; }
warn() { WARN=$((WARN + 1)); say "WARNING: $*"; }
stop() { say "STOP: $*"; exit 1; }

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
[ -d "$BIN" ] || stop "$BIN not found: install the Wazuh agent first"
getent group wazuh >/dev/null || stop "group wazuh not found (Wazuh agent?)"
for t in sha256sum base64 flock awk; do command -v $t >/dev/null || warn "tool missing: $t"; done
command -v openssl >/dev/null || stop "openssl missing: the agent could not verify the master's signed manifests"
if [ -s "$PUBKEY" ]; then
    openssl pkey -pubin -in "$PUBKEY" -noout 2>/dev/null || stop "$PUBKEY is not a public key"
else
    PUBKEY=""
fi

say "== 1. CIS-CAT Pro Assessor"
# a full agent package carries the Assessor (Assessor/ + ASSESSOR_VERSION, no license): install it,
# or update it when the version differs; the license and a failed update are kept/rolled back
if [ -x "$HERE/Assessor/Assessor-CLI.sh" ] && [ -s "$HERE/ASSESSOR_VERSION" ]; then
    new_ver=$(tr -d ' \r\n' < "$HERE/ASSESSOR_VERSION")
    cur_ver=$(tr -d ' \r\n' 2>/dev/null < "$ASSESSOR/.bridge-assessor-version")
    if [ "$new_ver" = "$cur_ver" ] && [ -x "$ASSESSOR/Assessor-CLI.sh" ]; then
        say "   Assessor $new_ver already installed"
    else
        say "   installing Assessor $new_ver (was: ${cur_ver:-none})"
        mkdir -p /opt/ciscat
        rm -rf "$ASSESSOR.new"
        cp -a "$HERE/Assessor" "$ASSESSOR.new" || stop "cannot copy the Assessor to $ASSESSOR.new"
        old_dir=""
        if [ -d "$ASSESSOR" ]; then
            mkdir -p "$BACKUP" && chmod 700 "$BACKUP"
            old_dir="$BACKUP/Assessor"
            [ -e "$old_dir" ] && old_dir="$BACKUP/Assessor.$(date +%H%M%S).$$"
            mv "$ASSESSOR" "$old_dir" || stop "cannot move the old Assessor to $old_dir"
            # the license and the files CIS-CAT does not ship stay
            if [ -d "$old_dir/license" ] && ! ls "$ASSESSOR.new/license"/* >/dev/null 2>&1; then
                cp -a "$old_dir/license" "$ASSESSOR.new/"
            fi
        fi
        mv "$ASSESSOR.new" "$ASSESSOR"
        chmod +x "$ASSESSOR/Assessor-CLI.sh" "$ASSESSOR"/jre/bin/* 2>/dev/null
        if "$ASSESSOR/jre/bin/java" -version >/dev/null 2>&1; then
            printf '%s\n' "$new_ver" > "$ASSESSOR/.bridge-assessor-version"
            say "   Assessor $new_ver installed${old_dir:+ (previous one in $old_dir)}"
        else
            rm -rf "$ASSESSOR"
            [ -n "$old_dir" ] && mv "$old_dir" "$ASSESSOR"
            stop "the new Assessor does not start (java): previous one restored"
        fi
    fi
fi
if [ -x "$ASSESSOR/Assessor-CLI.sh" ]; then
    say "   present: $ASSESSOR/Assessor-CLI.sh"
    say "   JRE: $("$ASSESSOR/jre/bin/java" -version 2>&1 | head -1)"
    mkdir -p "$ASSESSOR/benchmarks"
    lp=$(sed -n 's/^[[:space:]]*ciscat\.license\.filepath[[:space:]]*=[[:space:]]*//p' "$ASSESSOR/config/assessor-cli.properties" 2>/dev/null | tail -1)
    lic=""
    if [ -n "$lp" ]; then [ -s "$lp" ] && lic=$lp
    else for f in "$ASSESSOR"/license/*; do [ -s "$f" ] && lic=$f && break; done; fi
    if [ -n "$lic" ]; then say "   license: $lic"
    else warn "CIS-CAT Pro license not found ($ASSESSOR/license, or ciscat.license.filepath): the assessments will stop until it is there"; fi
else
    warn "CIS-CAT Pro not found: install it in $ASSESSOR (Assessor-CLI.sh executable)"
fi
# what root runs must not be replaceable by another user: /opt/ciscat and the Assessor
if [ -d /opt/ciscat ]; then
    owner=$(stat -c '%U:%G %a' /opt/ciscat)
    chown root:root /opt/ciscat && chmod 755 /opt/ciscat
    [ -d "$ASSESSOR" ] && chown -R root:root "$ASSESSOR" && chmod 700 "$ASSESSOR"
    say "   /opt/ciscat was $owner, now $(stat -c '%U:%G %a' /opt/ciscat); Assessor root only"
fi

say "== 2. Assessor settings"
P=$ASSESSOR/config/assessor-cli.properties
if [ -f "$P" ]; then
    if grep -Eq '^[[:space:]]*exit\.on\.invalid\.signature[[:space:]]*=[[:space:]]*false[[:space:]]*$' "$P"; then
        say "   exit.on.invalid.signature=false already set"
    else
        cp -p "$P" "$P.bak-$STAMP"
        sed -i '/^[[:space:]]*exit\.on\.invalid\.signature[[:space:]]*=/d' "$P"
        echo "exit.on.invalid.signature=false" >> "$P"
        say "   exit.on.invalid.signature=false set (previous file: $P.bak-$STAMP)"
    fi
elif [ -x "$ASSESSOR/Assessor-CLI.sh" ]; then
    warn "$P not found: set exit.on.invalid.signature=false there"
fi

say "== 3. ciscat-bootstrap.sh"
mkdir -p "$DATA" && chown root:root "$DATA" && chmod 700 "$DATA"
T=$(mktemp)
base64 -d > "$T" <<'PAYLOAD'
@BOOTSTRAP_B64@
PAYLOAD
[ "$(sha256sum "$T" | cut -d' ' -f1)" = "$SHA" ] || { rm -f "$T"; stop "checksum mismatch: nothing installed"; }
if [ -f "$BIN/ciscat-bootstrap.sh" ]; then
    mkdir -p "$BACKUP" && chmod 700 "$BACKUP" && cp -p "$BIN/ciscat-bootstrap.sh" "$BACKUP/"
fi
install -o root -g wazuh -m 0750 "$T" "$BIN/ciscat-bootstrap.sh"; rm -f "$T"
say "   $BIN/ciscat-bootstrap.sh  $SHA"
if [ -n "$PUBKEY" ]; then
    install -o root -g root -m 0644 "$PUBKEY" "$DATA/ciscat-manifest.pub"
    say "   master's public key: $DATA/ciscat-manifest.pub  sha256 $(sha256sum "$DATA/ciscat-manifest.pub" | cut -d' ' -f1)"
    say "   (compare with the sha256 that ciscat-master-setup.sh printed for ciscat-manifest.pub)"
elif [ -s "$DATA/ciscat-manifest.pub" ]; then
    say "   master's public key kept: $DATA/ciscat-manifest.pub  sha256 $(sha256sum "$DATA/ciscat-manifest.pub" | cut -d' ' -f1)"
else
    say "   master's public key: received from the master at the first run, then kept"
fi

say "== 4. files of earlier versions"
for f in ciscat-sca-refresh.sh ciscat-sca-setup.sh ciscat-sca-setup.cmd ciscat-bootstrap-linux0 ciscat-refresh-linux0; do
    if [ -e "$BIN/$f" ] || [ -L "$BIN/$f" ]; then
        mkdir -p "$BACKUP" && chmod 700 "$BACKUP" && mv "$BIN/$f" "$BACKUP/" && say "   moved to $BACKUP: $f"
    fi
done
C=$DATA/reports-cache
for d in "$C/L1" "$C/-" "$C/Server" "$C"/\(*\); do
    [ -d "$d" ] && mkdir -p "$BACKUP" && mv "$d" "$BACKUP/" && say "   moved to $BACKUP: $(basename "$d")"
done
if grep -A3 '<wodle name="cis-cat">' /var/ossec/etc/ossec.conf 2>/dev/null | grep -q '<disabled>no</disabled>'; then
    warn "the Wazuh cis-cat wodle is enabled in /var/ossec/etc/ossec.conf: disable it, the bridge runs CIS-CAT"
fi

say "== 5. SELinux"
if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
    say "   $(getenforce 2>/dev/null); wazuh-execd runs as: $(ps -eZ 2>/dev/null | awk '/wazuh-execd/ {print $1; exit}')"
    # folders moved from a home directory keep its label (user_home_t): give them the default
    # labels of /opt, /var/lib and /var/ossec
    if command -v restorecon >/dev/null 2>&1; then
        for p in /opt/ciscat "$DATA" "$BIN/ciscat-bootstrap.sh" "$BIN/ciscat-refresh.sh"; do
            [ -e "$p" ] && restorecon -R "$p" 2>/dev/null
        done
        say "   labels: $(ls -Zd /opt/ciscat 2>/dev/null | awk '{print $(NF-1)}') /opt/ciscat, $(ls -Zd "$DATA" 2>/dev/null | awk '{print $(NF-1)}') $DATA"
    else
        warn "restorecon not found: check the SELinux labels of /opt/ciscat and $DATA"
    fi
    ps -eZ 2>/dev/null | grep wazuh-execd | grep -q unconfined_service_t || \
        warn "wazuh-execd is not unconfined_service_t: CIS-CAT may be blocked by SELinux (check ausearch -m avc)"
else
    say "   SELinux not enabled"
fi

say ""
if [ "$WARN" -gt 0 ]; then say "RESULT: DONE WITH $WARN WARNING(S) (see above)"; else say "RESULT: OK - agent ready for the CIS-CAT bridge @VERSION@"; fi
