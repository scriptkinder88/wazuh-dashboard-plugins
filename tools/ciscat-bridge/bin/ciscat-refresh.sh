#!/bin/sh
# ============================================================================
# ciscat-refresh.sh - run CIS-CAT Pro Assessor with the tailored custom XCCDF
# and flatten the results for the Wazuh SCA policy. Pure shell (RHEL 7 has no
# Python 3). Config comes from /var/lib/wazuh-ciscat/refresh.conf (group-sync).
#
# Pilot findings baked in (do not remove):
#  - JAVA_TOOL_OPTIONS VFORK: Java 21 spawn helper fails on the RHEL 7 kernel
#    (exit 127 "Failed to exec spawn helper"); VFORK is the documented fallback.
#  - CLI direct invocation (-b/-p with the profile NAME): the -cfg config-XML
#    mode exits silently in Assessor v4.64.
#  - exit.on.invalid.signature=false must be set in assessor-cli.properties
#    (custom tailored XCCDF is unsigned) - provisioned as agent baseline.
#  - ccpa-temp-* dirs MUST be purged before each run: the Assessor recursively
#    copies leftover temp dirs into new ones (exponential disk growth).
#  - The Assessor writes an ARF report into <assessor>/reports; -rd is not
#    reliable in this build, so we read from the default reports dir.
# ============================================================================
set -u
# Under execd, stdout is a pipe that execd closes after launch: a later echo
# would raise SIGPIPE and kill the script (manual runs have a tty and never
# see this). Ignore SIGPIPE and write to stdout only when it is a terminal.
trap '' PIPE

CISCAT_PATH="/opt/ciscat/Assessor"
DATA_DIR="/var/lib/wazuh-ciscat"
CONF="${DATA_DIR}/refresh.conf"
CACHE_DIR="${DATA_DIR}/reports-cache"
LOG_DIR="${DATA_DIR}/logs"
AR_LOG="/var/ossec/logs/active-responses.log"

mkdir -p "$CACHE_DIR" "$LOG_DIR" 2>/dev/null
RUN_LOG="${LOG_DIR}/refresh_$(date +%Y%m%d_%H%M%S).log"

log() {
    line="[+] $(date +%Y-%m-%dT%H:%M:%S) $1"
    [ -t 1 ] && echo "$line"
    echo "$line" >> "$RUN_LOG" 2>/dev/null
    echo "$(date '+%Y/%m/%d %H:%M:%S') ciscat-refresh: $1" >> "$AR_LOG" 2>/dev/null
}
fail() { log "ERROR: $1"; exit 1; }

[ -r "$CONF" ] || fail "config not found: $CONF"
. "$CONF"
: "${BENCHMARK_FILE:?}" ; : "${PROFILE_LIST:?}" ; : "${SPLAY_MAX_SEC:=0}"

# Splay policy: an Active Response trigger is on-demand by definition, so it
# NEVER splays (execd invokes us via the *-linux0 symlink, detectable from $0).
# Scheduled runs (systemd timer calling ciscat-refresh.sh directly) splay per
# SPLAY_MAX_SEC; --no-splay also skips. Same behaviour in testing and steady
# state: trigger = immediate, schedule = splayed.
case "$(basename "$0")" in *linux0) set -- --no-splay ;; esac
if [ "${1:-}" != "--no-splay" ] && [ "$SPLAY_MAX_SEC" -gt 0 ] 2>/dev/null; then
    delay=$(( $(od -An -N2 -tu2 /dev/urandom | tr -d ' ') % SPLAY_MAX_SEC ))
    log "splay: sleeping ${delay}s before assessment"
    sleep "$delay"
fi

bench_path="${CISCAT_PATH}/benchmarks/${BENCHMARK_FILE}"
[ -r "$bench_path" ] || fail "benchmark not found: $bench_path"

# Fleet-wide script: the Java 21 spawn helper fails only on EL7-era kernels
# (3.10.x) with exit 127 "Failed to exec spawn helper". Apply the documented
# VFORK fallback ONLY there; modern kernels (Debian 12, RHEL 8+) use the
# default mechanism.
case "$(uname -r)" in
    3.10.*) export JAVA_TOOL_OPTIONS="-Djdk.lang.Process.launchMechanism=VFORK" ;;
esac

exit_code=0
# PROFILE_LIST entries are ';'-separated because profile NAMES contain spaces
# (e.g. "TAILORED L1 - Server (host)"); default word-splitting would break them.
old_ifs=$IFS
IFS=';'
for entry in $PROFILE_LIST; do
    IFS=$old_ifs
    [ -n "$entry" ] || continue
    P_KEY=${entry%%|*}
    P_NAME=${entry#*|}
    profile_dir="${CACHE_DIR}/${P_KEY}"
    mkdir -p "$profile_dir" 2>/dev/null

    # Purge Assessor temp leftovers (exponential-growth trap) and old reports.
    rm -rf "${CISCAT_PATH}/scripts"/ccpa-temp-* "${CISCAT_PATH}"/ccpa-temp-* 2>/dev/null
    rm -f "${CISCAT_PATH}/reports"/*-ARF.xml 2>/dev/null

    log "Running CIS-CAT profile: ${P_NAME}"
    ( cd "$CISCAT_PATH" && ./Assessor-CLI.sh -b "benchmarks/${BENCHMARK_FILE}" \
        -p "$P_NAME" -nts >> "$RUN_LOG" 2>&1 )
    rc=$?
    [ "$rc" -ne 0 ] && { log "WARNING: Assessor exited ${rc} for profile: ${P_NAME}"; exit_code=1; }

    # The Assessor writes <hostname>-...-ARF.xml into its reports dir.
    report=$(ls -1t "${CISCAT_PATH}/reports"/*-ARF.xml 2>/dev/null | head -1)
    if [ -z "$report" ]; then
        log "ERROR: no ARF report produced for profile: ${P_NAME}"
        exit_code=1
        continue
    fi

    # Flatten: ARF rule-result idref + result -> "N.N.N:result" (lowercase).
    # Same short-rule-id format as the Windows pilot; the SCA policy matches
    # lines like ^1\.1\.1\.2:pass$
    flat_tmp="${profile_dir}/.results.txt.tmp"
    grep -oE '<xccdf:rule-result idref="[^"]*"|<xccdf:result>[^<]*</xccdf:result>' "$report" \
      | sed -e 's/<xccdf:rule-result idref="//' -e 's/"$//' \
            -e 's/<xccdf:result>//' -e 's|</xccdf:result>||' \
      | paste - - \
      | awk '{print $1"|"$2}' \
      | sed -E 's/^.*_rule_([0-9]+(\.[0-9]+)*)_[^|]*\|/\1:/' \
      | tr 'A-Z' 'a-z' | sort > "$flat_tmp"

    n=$(grep -c ':' "$flat_tmp" 2>/dev/null || echo 0)
    if [ "$n" -eq 0 ]; then
        log "ERROR: flatten produced 0 lines for profile: ${P_NAME}"
        rm -f "$flat_tmp"
        exit_code=1
        continue
    fi
    mv -f "$flat_tmp" "${profile_dir}/results.txt"
    chmod 640 "${profile_dir}/results.txt" 2>/dev/null
    log "flatten OK: ${n} results -> ${profile_dir}/results.txt"

    # Keep the raw report for audit, then purge Assessor temp again.
    cp -f "$report" "${profile_dir}/last-ARF.xml" 2>/dev/null
    rm -rf "${CISCAT_PATH}/scripts"/ccpa-temp-* "${CISCAT_PATH}"/ccpa-temp-* 2>/dev/null
    IFS=';'
done
IFS=$old_ifs

log "refresh completed (exit ${exit_code})"
exit "$exit_code"
