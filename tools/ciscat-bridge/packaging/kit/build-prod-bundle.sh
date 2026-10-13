#!/bin/sh
# CIS-CAT bridge 2.3.1: the single bundle for a Wazuh master (production), in one go.
#
#   sh build-prod-bundle.sh <Windows Assessor .zip> <Linux Assessor .zip|.tar.gz>
#
# Next to the two downloads (same folder) it also takes, when there:
#   wazuh-dashboard-plugins_wazuh_4.14.7-01_<commit>.zip   the dashboard plugin of this release
#   license.xml                                            the CIS-CAT Pro license
#   ciscat-config-<date>.tgz (+ .sha256)                   configuration exported from another
#                                                          master (ciscat-export-config.sh)
# Do not put the master's key files there: the agents take the key from their master.
# Output: release-2.3.1/ciscat-prod-2.3.1.tar.gz, to unpack on the master and run install-prod.sh.
set -eu
PLUGIN_SHA=35d4b89a0e8a5b75aa8befa3f71b3eb7164b6f6e8d41ff8962f59bf88e05a8c4
HERE=$(cd "$(dirname "$0")" && pwd)
[ $# -ge 2 ] || { sed -n 2,14p "$0"; exit 2; }
EXTRAS=$(cd "$(dirname "$1")" && pwd)
for k in ciscat-manifest.pub ciscat-manifest.pub.xml; do
    [ ! -f "$EXTRAS/$k" ] || { echo "STOP: $EXTRAS/$k: remove it, the agents take the key from the master"; exit 1; }
done
sh "$HERE/build-full-packages.sh" "$1" "$2"
# the two downloads in the order build-full-packages.sh used
WIN=$1; LIN=$2
case "$(printf '%s' "$(basename "$WIN")" | tr 'A-Z' 'a-z')" in *linux*) WIN=$2; LIN=$1 ;; esac
echo "== production bundle"
python3 "$HERE/prod_bundle.py" --windows "$WIN" --linux "$LIN" --release "$HERE/release-2.3.1" \
    --extras "$EXTRAS" --version 2.3.1 --plugin-sha256 "$PLUGIN_SHA" \
    --out "$HERE/release-2.3.1/ciscat-prod-2.3.1.tar.gz"
echo
echo "RESULT: OK - on the master, as root:"
echo "  install -d -m 0700 /opt/ciscat/install/bundle && tar -xzf ciscat-prod-2.3.1.tar.gz -C /opt/ciscat/install/bundle"
echo "  cd /opt/ciscat/install/bundle/ciscat-prod-2.3.1 && sh install-prod.sh"
