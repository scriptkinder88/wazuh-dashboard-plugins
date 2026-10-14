#!/bin/sh
# CIS-CAT bridge 2.3.1: the capture kit, to copy to the configured (test) master.
#   sh build-capture-kit.sh <ciscat-master-2.3.1.zip> [<dashboard plugin zip>]
# Output: release-2.3.1/ciscat-capture-kit-2.3.1.zip (+ .sha256) with capture-ittest.sh,
# align-prod.sh, the master package and, when given, the plugin zip.
set -eu
VERSION=2.3.1
HERE=$(cd "$(dirname "$0")" && pwd)
[ $# -ge 1 ] && [ -f "$1" ] || { sed -n 2,5p "$0"; exit 2; }
[ "$(basename "$1")" = "ciscat-master-$VERSION.zip" ] || { echo "STOP: $1 is not ciscat-master-$VERSION.zip"; exit 1; }
OUT=$HERE/release-$VERSION
mkdir -p "$OUT"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
K=$W/ciscat-capture-kit-$VERSION
mkdir -p "$K"
cp "$HERE/capture-ittest.sh" "$HERE/align-prod.sh" "$HERE/README-capture.txt" "$1" "$K/"
[ $# -lt 2 ] || cp "$2" "$K/"
(cd "$K" && sha256sum capture-ittest.sh align-prod.sh README-capture.txt "$(basename "$1")" > SHA256SUMS)
rm -f "$OUT/ciscat-capture-kit-$VERSION.zip"
(cd "$W" && python3 -m zipfile -c "$OUT/ciscat-capture-kit-$VERSION.zip" "ciscat-capture-kit-$VERSION")
(cd "$OUT" && sha256sum "ciscat-capture-kit-$VERSION.zip" > "ciscat-capture-kit-$VERSION.zip.sha256")
echo "RESULT: OK - $OUT/ciscat-capture-kit-$VERSION.zip"
