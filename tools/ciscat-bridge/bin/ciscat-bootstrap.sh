#!/bin/sh
# ============================================================================
# ciscat-bootstrap.sh  (AGENT side, Linux shell variant)
#
# Installs the manager-distributed CIS-CAT package on the agent, verifying
# integrity via the SHA256 manifest before copying each file to its
# destination. Python-free: works on legacy RHEL 7 (and any Linux).
#
# Model: the manager publishes, for each OS (benchmark) of a group, its files and
# ciscat-manifest-<os>.csv into the shared folder of the group. Wazuh merges
# the files of the agent's groups into its shared dir, so an agent with several
# benchmarks gets one manifest each. This script reads every manifest (or the
# group-wide ciscat-manifest.csv of older managers), checks each file's sha256,
# and installs it to the 'dest' path recorded in the manifest. Only files that
# verify are installed; a mismatch is refused.
#
# Manifest format (one file per line, after two comment lines):
#   name;sha256;dest
# 'name' is a plain file name of the shared folder, and 'dest' must lie in
# the Assessor's benchmarks folder or in /var/lib/wazuh-ciscat, or be the
# refresh script in active-response/bin: any other line is refused, so the
# shared folder cannot have files written elsewhere as root.
#
# Trigger: PUT /active-response {"command":"!ciscat-bootstrap.sh"}
# Runs as root via the Wazuh active-response mechanism.
# ============================================================================
set -u
# Under execd, stdout is a pipe that execd closes after launch: a later echo
# would raise SIGPIPE and kill the script (manual runs have a tty and never
# see this). Ignore SIGPIPE and write to stdout only when it is a terminal.
trap '' PIPE

# Overridable for tests only; execd runs the script with the defaults.
AGENT_SHARED="${CISCAT_AGENT_SHARED:-/var/ossec/etc/shared}"   # merged group files land here
DATA_ROOT="${CISCAT_DATA_DIR:-/var/lib/wazuh-ciscat}"
ASSESSOR_BENCH="${CISCAT_PATH:-/opt/ciscat/Assessor}/benchmarks"
REFRESH_DEST="${CISCAT_AR_BIN:-/var/ossec/active-response/bin}/ciscat-refresh.sh"
LOG_TAG="ciscat-bootstrap"

# Resolve the Wazuh root from this script's location (active-response/bin -> root)
_LOCAL=$(dirname "$0"); cd "$_LOCAL" 2>/dev/null; cd ../../ 2>/dev/null; WROOT=$(pwd)
AR_LOG="${CISCAT_AR_LOG:-${WROOT}/logs/active-responses.log}"

log() {
    [ -t 1 ] && echo "[+] $(date '+%Y-%m-%dT%H:%M:%S') ${LOG_TAG}: $1"
    # the Wazuh AR log keeps the execution traceable (like restart.sh)
    [ -w "$AR_LOG" ] 2>/dev/null && echo "$(date '+%Y/%m/%d %H:%M:%S') $0 ${LOG_TAG}: $1" >> "$AR_LOG" 2>/dev/null
    return 0
}
fail() { log "ERROR: $1"; exit 1; }

# dest_allowed <path>: the only places a manifest may install to.
dest_allowed() {
    case "$1" in
        *..*) return 1 ;;
        "$ASSESSOR_BENCH"/?*|"$DATA_ROOT"/?*|"$REFRESH_DEST") return 0 ;;
    esac
    return 1
}

# Wazuh AR protocol: execd writes the alert as one JSON line on stdin and waits for this script
# to exit. The line is read (and not used: this is a maintenance action), so execd never waits
# on a full pipe; a terminal (manual run) is not read.
[ -t 0 ] || IFS= read -r _alert || true

log "invoked (bootstrap start)"

# The agent unpacks the files of its groups into the shared folder itself.
SRC_DIR="$AGENT_SHARED"
MANIFESTS=""
for m in "$AGENT_SHARED"/ciscat-manifest-*.csv; do
    [ -f "$m" ] && MANIFESTS="$MANIFESTS $m"
done
[ -n "$MANIFESTS" ] || MANIFESTS="${AGENT_SHARED}/ciscat-manifest.csv"
for m in $MANIFESTS; do
    [ -f "$m" ] || fail "manifest not found in ${AGENT_SHARED} (group sync pending?)"
done

mkdir -p "$DATA_ROOT" 2>/dev/null
chmod 700 "$DATA_ROOT" 2>/dev/null

installed=0
refused=0
missing=0

install_manifest() {
log "using manifest: $1"
# Read the manifest, skipping comment lines (#) and the header.
while IFS=';' read -r name expected dest; do
    # skip comments / blanks / header
    case "$name" in
        \#*|"") continue ;;
        name)   continue ;;
    esac
    [ -n "$expected" ] || continue
    [ -n "$dest" ] || { log "no dest for $name, skipping"; continue; }
    case "$name" in
        */*|..*)
            log "REFUSED (not a plain file name): $name"
            refused=$((refused + 1))
            continue
            ;;
    esac
    if ! dest_allowed "${dest%:gz}"; then
        log "REFUSED (destination not allowed): $name -> $dest"
        refused=$((refused + 1))
        continue
    fi

    src="${SRC_DIR}/${name}"
    if [ ! -f "$src" ]; then
        log "MISSING in shared: $name"
        missing=$((missing + 1))
        continue
    fi

    actual=$(sha256sum "$src" | awk '{print $1}')
    if [ "$actual" != "$expected" ]; then
        log "REFUSED (sha256 mismatch): $name"
        log "  expected=$expected"
        log "  actual  =$actual"
        refused=$((refused + 1))
        continue
    fi

    # integrity OK: install to destination.
    # A dest ending in ':gz' means the shared file is gzip-compressed and must
    # be decompressed to the real path (large XML files travel compressed).
    case "$dest" in
        *:gz)
            real_dest=${dest%:gz}
            dest_dir=$(dirname "$real_dest")
            mkdir -p "$dest_dir" 2>/dev/null
            if gunzip -c "$src" > "$real_dest" 2>/dev/null; then
                chmod 640 "$real_dest"
                log "installed (gunzip): $name -> $real_dest"
                installed=$((installed + 1))
            else
                log "REFUSED (gunzip failed): $name"
                refused=$((refused + 1))
            fi
            continue
            ;;
    esac

    dest_dir=$(dirname "$dest")
    mkdir -p "$dest_dir" 2>/dev/null
    cp "$src" "$dest" || { log "copy failed: $name -> $dest"; refused=$((refused + 1)); continue; }

    # make shell scripts executable; data files stay non-exec
    case "$dest" in
        *.sh) chmod 750 "$dest" ;;
        *)    chmod 640 "$dest" ;;
    esac
    log "installed: $name -> $dest"
    installed=$((installed + 1))
done < "$1"
}

for m in $MANIFESTS; do
    install_manifest "$m"
done

log "bootstrap done: installed=${installed} refused=${refused} missing=${missing}"

# Non-zero exit if anything was refused (integrity failure) so the AR log flags it.
[ "$refused" -eq 0 ] || exit 2
exit 0
