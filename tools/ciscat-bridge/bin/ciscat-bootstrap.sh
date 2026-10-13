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
ASSESSOR_LICENSE="${CISCAT_PATH:-/opt/ciscat/Assessor}/license/license.xml"
REFRESH_DEST="${CISCAT_AR_BIN:-/var/ossec/active-response/bin}/ciscat-refresh.sh"
LOG_TAG="ciscat-bootstrap"
# the master's public key, put here (root only) by the agent installer: every manifest must be
# signed with the matching private key, which never leaves the master
PUBKEY="${CISCAT_PUBKEY:-${DATA_ROOT}/ciscat-manifest.pub}"
STAGE="${DATA_ROOT}/staging"

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
        "$ASSESSOR_BENCH"/?*|"$DATA_ROOT"/?*|"$REFRESH_DEST"|"$ASSESSOR_LICENSE") return 0 ;;
    esac
    return 1
}

# Wazuh AR protocol: execd writes the alert as one JSON line on stdin and waits for this script
# to exit. The line is read (and not used: this is a maintenance action), so execd never waits
# on a full pipe; a terminal (manual run) is not read.
[ -t 0 ] || IFS= read -r _alert || true

log "invoked (bootstrap start)"

mkdir -p "$DATA_ROOT" 2>/dev/null
chmod 700 "$DATA_ROOT" 2>/dev/null

# A final agent package lays down the Assessor with the list of its files (ciscat-assessor.sha256,
# next to this script). At the first run with a new list the Assessor is checked against it:
# a file that differs stops the assessments (ciscat-refresh.sh runs only an Assessor checked
# here), files that are not in the list (left by an earlier Assessor version) are moved aside,
# and the Assessor is made root's only. The license, benchmarks, reports, logs and settings are
# written on the agent and not checked.
ASSESSOR_DIR="${CISCAT_PATH:-/opt/ciscat/Assessor}"
ASSESSOR_LIST="${CISCAT_AR_BIN:-/var/ossec/active-response/bin}/ciscat-assessor.sha256"
ASSESSOR_CHECKED="${DATA_ROOT}/assessor-checked"
check_assessor() {
    [ -f "$ASSESSOR_LIST" ] || return 0
    list_sha=$(sha256sum "$ASSESSOR_LIST" | awk '{print $1}')
    [ "$(cat "$ASSESSOR_CHECKED" 2>/dev/null)" = "$list_sha" ] && return 0
    rm -f "$ASSESSOR_CHECKED"
    [ -d "$ASSESSOR_DIR" ] || fail "${ASSESSOR_DIR} not found: unpack the agent package"
    chown -R root:root "$ASSESSOR_DIR" 2>/dev/null
    chmod 700 "$ASSESSOR_DIR"
    work="${DATA_ROOT}/assessor-check.$$"
    mkdir -m 700 "$work" || fail "cannot create ${work}"
    grep -v '^#' "$ASSESSOR_LIST" | tr -d '\r' > "${work}/list"
    ( cd "$ASSESSOR_DIR" && sha256sum -c "${work}/list" 2>/dev/null ) | \
        grep -v ': OK$' | sed 's/: [A-Z].*$//' > "${work}/bad"
    if [ -s "${work}/bad" ]; then
        head -20 "${work}/bad" | while IFS= read -r f; do
            log "REFUSED (Assessor file differs from the package): ${f}"
        done
        nbad=$(wc -l < "${work}/bad" | tr -d ' ')
        rm -rf "$work"
        fail "the Assessor in ${ASSESSOR_DIR} is not the one of the agent package (${nbad} file(s)): assessments stopped"
    fi
    sed 's/^[0-9a-fA-F]*  //' "${work}/list" | sort > "${work}/want"
    ( cd "$ASSESSOR_DIR" && find . -type f | sed 's#^\./##' ) | \
        grep -Ev '^(license|benchmarks|reports|logs|config)/|^\.bridge-' | sort > "${work}/have"
    moved=0
    backup="${DATA_ROOT}/backup-assessor-$(date +%Y%m%d%H%M%S)"
    comm -23 "${work}/have" "${work}/want" > "${work}/extra"
    while IFS= read -r f; do
        mkdir -p "${backup}/$(dirname "$f")" && mv -f "${ASSESSOR_DIR}/${f}" "${backup}/${f}" && \
            moved=$((moved + 1))
    done < "${work}/extra"
    [ "$moved" -gt 0 ] && log "moved ${moved} file(s) of an earlier Assessor to ${backup}"
    echo "$list_sha" > "$ASSESSOR_CHECKED"
    chmod 600 "$ASSESSOR_CHECKED"
    log "Assessor checked against the agent package: $(wc -l < "${work}/want") file(s) OK"
    rm -rf "$work"
}
check_assessor

# The agent unpacks the files of its groups into the shared folder itself (writable by the
# wazuh user): everything is copied to a root-only staging folder first, and checked there.
MANIFESTS=""
for m in "$AGENT_SHARED"/ciscat-manifest-*.csv; do
    [ -f "$m" ] && MANIFESTS="$MANIFESTS $m"
done
[ -n "$MANIFESTS" ] || fail "no ciscat-manifest-*.csv in ${AGENT_SHARED} (group sync pending?)"
command -v openssl >/dev/null 2>&1 || fail "openssl not found: manifests cannot be verified"


# The master's public key comes with the group files. Without a key of its own (installed with
# --pubkey) the agent keeps the first valid one it receives (trust on first use); from then on
# only the kept key counts, and a different key in the group is ignored. New master key: reinstall
# with --pubkey, or delete the kept key.
SHARED_KEY="$AGENT_SHARED/ciscat-manifest.pub"
key_sha() { openssl dgst -sha256 "$1" 2>/dev/null | sed 's/.*= *//'; }
if [ -f "$SHARED_KEY" ] && [ ! -L "$SHARED_KEY" ]; then
    if [ ! -s "$PUBKEY" ]; then
        tmp="${PUBKEY}.new.$$"
        if cat "$SHARED_KEY" > "$tmp" 2>/dev/null && \
           openssl pkey -pubin -in "$tmp" -noout >/dev/null 2>&1 && \
           chmod 644 "$tmp" && mv -f "$tmp" "$PUBKEY"; then
            log "master's public key received and kept: ${PUBKEY} sha256 $(key_sha "$PUBKEY")"
        else
            rm -f "$tmp"
            log "WARNING: ${SHARED_KEY} is not a public key: not kept"
        fi
    elif ! cmp -s "$SHARED_KEY" "$PUBKEY"; then
        log "WARNING: the group's public key (sha256 $(key_sha "$SHARED_KEY")) differs from the kept one (sha256 $(key_sha "$PUBKEY")): ignored"
    fi
fi
[ -s "$PUBKEY" ] || fail "public key ${PUBKEY} not found and none received from the master yet"
rm -rf "$STAGE"
mkdir -m 700 "$STAGE" || fail "cannot create ${STAGE}"
trap 'rm -rf "$STAGE"' EXIT
SRC_DIR="$STAGE"

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
    real="${dest%:gz}"; real="${real%:b64}"
    if ! dest_allowed "$real"; then
        log "REFUSED (destination not allowed): $name -> $dest"
        refused=$((refused + 1))
        continue
    fi

    if [ ! -f "${AGENT_SHARED}/${name}" ]; then
        log "MISSING in shared: $name"
        missing=$((missing + 1))
        continue
    fi
    src="${SRC_DIR}/${name}"
    cp "${AGENT_SHARED}/${name}" "$src" 2>/dev/null || { log "REFUSED (cannot stage): $name"; refused=$((refused + 1)); continue; }

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
        *:b64)
            # base64 text (the license): decoded byte for byte
            real_dest=${dest%:b64}
            mkdir -p "$(dirname "$real_dest")" 2>/dev/null
            if tr -d ' \r\n' < "$src" | base64 -d > "${real_dest}.new" 2>/dev/null && [ -s "${real_dest}.new" ]; then
                chmod 640 "${real_dest}.new" && mv -f "${real_dest}.new" "$real_dest"
                log "installed (base64): $name -> $real_dest"
                installed=$((installed + 1))
            else
                rm -f "${real_dest}.new"
                log "REFUSED (base64 decoding failed): $name"
                refused=$((refused + 1))
            fi
            continue
            ;;
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

# verify_manifest <manifest in shared>: copies it and its .sig to the staging folder, checks the
# signature there and prints the staged copy (empty when refused)
verify_manifest() {
    base=$(basename "$1")
    cp "$1" "${STAGE}/${base}" 2>/dev/null || return 1
    [ -f "${1}.sig" ] || { log "REFUSED (no signature ${base}.sig): ${base}"; return 1; }
    tr -d ' \r\n' < "${1}.sig" | base64 -d > "${STAGE}/${base}.sig.bin" 2>/dev/null || return 1
    if openssl dgst -sha256 -verify "$PUBKEY" -signature "${STAGE}/${base}.sig.bin" \
            "${STAGE}/${base}" >/dev/null 2>&1; then
        echo "${STAGE}/${base}"
    else
        log "REFUSED (signature not valid for the master's key): ${base}"
        return 1
    fi
}

for m in $MANIFESTS; do
    if staged=$(verify_manifest "$m") && [ -n "$staged" ]; then
        log "signature OK: $(basename "$m")"
        install_manifest "$staged"
    else
        refused=$((refused + 1))
    fi
done

log "bootstrap done: installed=${installed} refused=${refused} missing=${missing}"

# Non-zero exit if anything was refused (integrity failure) so the AR log flags it.
[ "$refused" -eq 0 ] || exit 2
exit 0
