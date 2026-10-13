#!/bin/sh
# CIS-CAT bridge 2.3.1: builds the release packages for Wazuh 4.14.7, the agent packages with
# CIS-CAT Pro Assessor, from the Assessor downloads of the CIS WorkBench (as downloaded).
#
#   sh build-full-packages.sh <Windows Assessor .zip> <Linux Assessor .zip|.tar.gz> [output folder]
#
# The license, benchmarks, reports and logs of the downloads are left out; the build stops if a
# license or benchmark file is still found in a package. Run it on an internal host: the
# packages contain licensed CIS software and stay in the internal release store (Satellite).
set -eu
PLUGIN=wazuh-dashboard-plugins_wazuh_4.14.7-01_f7ccb4e866af66c6ee2377d672bc6619336a1b02.zip
PLUGIN_SHA=35d4b89a0e8a5b75aa8befa3f71b3eb7164b6f6e8d41ff8962f59bf88e05a8c4
HERE=$(cd "$(dirname "$0")" && pwd)
[ $# -ge 2 ] || { sed -n 2,9p "$0"; exit 2; }
WIN=$1; LIN=$2; OUT=${3:-$HERE/release-2.3.1}
# either order: the downloads are recognised by their names
lower() { printf '%s' "$1" | tr 'A-Z' 'a-z'; }
case "$(lower "$(basename "$WIN")")" in *linux*)
    case "$(lower "$(basename "$LIN")")" in *windows*)
        T=$WIN; WIN=$LIN; LIN=$T
        echo "(Windows Assessor: $(basename "$WIN"); Linux Assessor: $(basename "$LIN"))" ;;
    esac ;;
esac
# Linux, or Windows with MobaXterm / Cygwin: the file modes of the packages are set by the build,
# not read from the disk
command -v python3 >/dev/null || { echo "STOP: python3 is needed"; exit 1; }
for f in "$WIN" "$LIN"; do [ -e "$f" ] || { echo "STOP: $f not found"; exit 1; }; done

echo "== self-test of the build (fake Assessors, no CIS content), $(python3 --version 2>&1) on $(uname -s)"
TEST_LOG=$(cd "$HERE/ciscat-bridge" && python3 -m unittest tests.test_packaging 2>&1) || {
    printf '%s\n' "$TEST_LOG" | tail -30
    echo "STOP: the build self-test failed (output above)"; exit 1; }
echo "   OK"

# the master's public keys next to the downloads (from /opt/ciscat/etc on the master): pinned
KEYS=$(cd "$(dirname "$WIN")" && pwd)
set --
if [ -f "$KEYS/ciscat-manifest.pub" ] && [ -f "$KEYS/ciscat-manifest.pub.xml" ]; then
    set -- --master-keys "$KEYS"
    echo "== master key pinned in the packages: $KEYS/ciscat-manifest.pub{,.xml}"
fi

echo "== build"
umask 077
python3 "$HERE/ciscat-bridge/packaging/build.py" --plugin "$PLUGIN" --plugin-sha256 "$PLUGIN_SHA" \
    --out "$OUT" --assessor-windows "$WIN" --assessor-linux "$LIN" "$@"

echo "== check"
cd "$OUT"
sha256sum -c SHA256SUMS
# the package contents, read back with python (no unzip needed)
python3 - ciscat-agent-windows-*-assessor-*.zip ciscat-agent-linux-*-assessor-*.tar.gz <<'PY' || { echo "STOP: licensed files in a package (listed above)"; exit 1; }
import re, sys, tarfile, zipfile
bad_re = re.compile(r"/Assessor/(license|benchmarks)/|license\.xml$|\.lic$|/CIS_[^/]*\.(xml|zip)$"
                    r"|-(xccdf|oval|cpe-dictionary|cpe-oval)\.xml$", re.I)
failed = False
for p in sys.argv[1:]:
    if p.endswith(".zip"):
        with zipfile.ZipFile(p) as z:
            names = [n for n in z.namelist() if not n.endswith("/")]
    else:
        with tarfile.open(p) as t:
            names = [m.name for m in t.getmembers() if m.isfile()]
    bad = [n for n in names if bad_re.search(n)]
    print("   {0}: {1} Assessor files, licensed files: {2}".format(
        p, len([n for n in names if "/Assessor/" in n]), len(bad)))
    for n in bad[:20]:
        print("      " + n)
    failed = failed or bool(bad)
sys.exit(1 if failed else 0)
PY
echo
echo "RESULT: OK - packages in $OUT"
echo "Final packages: the Linux one is unpacked in / (tar -xzpf <file> -C /), the Windows one in"
echo "C:\\ (Expand-Archive -Path <file> -DestinationPath C:\\ -Force); nothing else to run."
echo "Satellite (file repository), for each package and SHA256SUMS:"
echo "  hammer repository upload-content --organization <org> --product <product> --name <repo> --path $OUT/<file>"
