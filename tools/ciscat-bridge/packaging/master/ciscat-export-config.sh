#!/bin/sh
# ciscat-export-config.sh - CIS-CAT bridge @VERSION@: export from a configured master what
# another master needs: the CIS benchmarks (original xccdf, oval, cpe files of
# /opt/ciscat/benchmarks), os-library.json, the exclusions, the schedules, the benchmark groups
# and the tailoring CSVs. No password, token, API setting or signing key is exported. Run as root:
#   sh ciscat-export-config.sh            -> ciscat-config-<date>.tgz and .tgz.sha256 here
# The CIS benchmarks are licensed: keep the archive inside the organization (never in a repository).
set -u
umask 077  # licensed benchmarks and the exclusions of every host: root only
[ "$(id -u)" = 0 ] || { echo "STOP: run as root"; exit 1; }
STAMP=$(date +%Y%m%d%H%M)
OUT=$(pwd)/ciscat-config-$STAMP.tgz
X=$(mktemp -d)
mkdir -p "$X/benchmarks" "$X/etc" "$X/lists" "$X/tailoring"
n=0
for f in /opt/ciscat/benchmarks/*; do
    [ -f "$f" ] && [ ! -L "$f" ] && cp -p "$f" "$X/benchmarks/" && n=$((n + 1))
done
[ -f /opt/ciscat/etc/os-library.json ] && cp -p /opt/ciscat/etc/os-library.json "$X/etc/"
for l in ciscat-exclusions ciscat-schedule ciscat-targets; do
    [ -f "/var/ossec/etc/lists/$l" ] && cp -p "/var/ossec/etc/lists/$l" "$X/lists/"
done
for f in /opt/ciscat/tailoring/exclusions/*; do
    [ -f "$f" ] && cp -p "$f" "$X/tailoring/"
done
M=$(mktemp)
{
    echo "exported $(date '+%F %T') from $(hostname) - bridge $(cat /opt/ciscat/VERSION 2>/dev/null)"
    (cd "$X" && find . -type f | sort | while read -r f; do sha256sum "$f"; done)
} > "$M"
mv "$M" "$X/MANIFEST"
tar -czf "$OUT" -C "$X" --owner=0 --group=0 . && rm -rf "$X"
(cd "$(dirname "$OUT")" && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256")
echo "benchmarks: $n file(s); lists: $(tar -tzf "$OUT" | grep -c '^./lists/.')"
echo "RESULT: OK - $OUT ($(du -h "$OUT" | cut -f1)), checksum in $(basename "$OUT").sha256"
echo "On the new master: sh ciscat-master-setup.sh --import $(basename "$OUT") [--with-targets]"
