#!/bin/sh
# ============================================================================
# ciscat-bootstrap.sh  (AGENT side, Linux shell variant)
#
# Installs the manager-distributed CIS-CAT package on the agent, verifying
# integrity via the SHA256 manifest before copying each file to its
# destination. Python-free: works on legacy RHEL 7 (and any Linux).
#
# Model: the manager publishes files + ciscat-manifest.csv into the group
# shared folder (os-rhel7). Wazuh merges the group config; the individual
# files land in the agent's shared dir. This script reads the manifest,
# checks each file's sha256, and installs it to the 'dest' path recorded in
# the manifest. Only files that verify are installed; a mismatch is refused.
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
AR_LOG="${WROOT}/logs/active-responses.log"

log() {
    _line="[+] $(date '+%Y-%m-%dT%H:%M:%S') ${LOG_TAG}: $1"
    echo "$_line"
    # also append to the Wazuh AR log so the execution is traceable (like restart.sh)
    [ -w "$AR_LOG" ] 2>/dev/null && echo "$(date '+%Y/%m/%d %H:%M:%S') $0 ${LOG_TAG}: $1" >> "$AR_LOG" 2>/dev/null
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

# NOTE on Wazuh AR: execd invokes this script and passes a JSON object on stdin
# with an "add"/"delete" command. We do not use those parameters (this is a
# maintenance-style AR). We deliberately do NOT read stdin: a blocking read
# (execd keeps the pipe open) delays the script and execd may terminate it
# before it completes. Ignoring stdin lets the script run to completion.

log "invoked (bootstrap start)"

# The manifest can arrive in the agent shared root or in a group subdir,
# depending on how the merge lands. Find it.
MANIFEST=""
for cand in \
    "${AGENT_SHARED}/ciscat-manifest.csv" \
    "${AGENT_SHARED}/os-rhel7/ciscat-manifest.csv"; do
    [ -f "$cand" ] && { MANIFEST="$cand"; break; }
done
[ -n "$MANIFEST" ] || fail "manifest not found in ${AGENT_SHARED} (group sync pending?)"
SRC_DIR=$(dirname "$MANIFEST")
log "using manifest: $MANIFEST"

mkdir -p "$DATA_ROOT" 2>/dev/null
chmod 700 "$DATA_ROOT" 2>/dev/null

installed=0
refused=0
missing=0

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
done < "$MANIFEST"

log "bootstrap done: installed=${installed} refused=${refused} missing=${missing}"

# Non-zero exit if anything was refused (integrity failure) so the AR log flags it.
[ "$refused" -eq 0 ] || exit 2
exit 0
