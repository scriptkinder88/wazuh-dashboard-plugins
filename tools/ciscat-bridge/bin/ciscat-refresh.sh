#!/bin/sh
# ============================================================================
# ciscat-refresh.sh - run CIS-CAT Pro Assessor with the tailored custom XCCDF
# and flatten the results for the Wazuh SCA policy. Pure shell (RHEL 7 has no
# Python 3). Each benchmark of the agent has its settings in
# /var/lib/wazuh-ciscat/conf.d/<os>.conf (installed by ciscat-bootstrap.sh from
# its OS group) and its results in reports-cache/<os>/<profile>/results.txt;
# they run one after the other. A conf.d file whose OS group the agent left is
# removed and its results withdrawn. Without conf.d, the single refresh.conf of
# older managers is used (results in reports-cache/<profile>/results.txt).
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

# Under execd (Active Response, no argument and stdin not a terminal): execd writes the alert as
# one JSON line on stdin, then waits until this script exits and closes its stdout (Wazuh
# os_execd/execd.c: fgets, then waitpid), and runs no other Active Response meanwhile. An
# assessment takes minutes: read the line, start the assessment detached with nothing inherited,
# and return at once.
if [ $# -eq 0 ] && [ ! -t 0 ]; then
    IFS= read -r _alert || true
    if command -v setsid >/dev/null 2>&1; then
        setsid sh "$0" --foreground </dev/null >/dev/null 2>&1 &
    else
        nohup sh "$0" --foreground </dev/null >/dev/null 2>&1 &
    fi
    exit 0
fi

# Overridable for tests only; execd runs the script with the defaults.
CISCAT_PATH="${CISCAT_PATH:-/opt/ciscat/Assessor}"
DATA_DIR="${CISCAT_DATA_DIR:-/var/lib/wazuh-ciscat}"
CONF="${DATA_DIR}/refresh.conf"
CONF_DIR="${DATA_DIR}/conf.d"
AGENT_SHARED="${CISCAT_AGENT_SHARED:-/var/ossec/etc/shared}"
CACHE_DIR="${DATA_DIR}/reports-cache"
LOG_DIR="${DATA_DIR}/logs"
AR_LOG="${CISCAT_AR_LOG:-/var/ossec/logs/active-responses.log}"

mkdir -p "$CACHE_DIR" "$LOG_DIR" 2>/dev/null
RUN_LOG="${LOG_DIR}/refresh_$(date +%Y%m%d_%H%M%S).log"
# one log per run: the newest LOG_KEEP are kept (this run's included)
LOG_KEEP=30
ls -1t "$LOG_DIR"/refresh_*.log 2>/dev/null | tail -n +"$LOG_KEEP" |
    while IFS= read -r old; do rm -f "$old"; done

log() {
    line="[+] $(date +%Y-%m-%dT%H:%M:%S) $1"
    [ -t 1 ] && echo "$line"
    echo "$line" >> "$RUN_LOG" 2>/dev/null
    echo "$(date '+%Y/%m/%d %H:%M:%S') ciscat-refresh: $1" >> "$AR_LOG" 2>/dev/null
}
fail() { log "ERROR: $1"; exit 1; }

# flatten_arf <ARF report> <output>: sorted "N.N.N:result" lines. Each <rule-result> must hold
# exactly one <result>; otherwise the report is refused (status 1) rather than results being
# paired with the wrong rules. Records are split on '<', so line breaks and attribute order
# inside the elements do not matter.
flatten_arf() {
    awk 'BEGIN { RS = "<"; bad = 0; open = 0 }
    {
        tag = $0; sub(/[ \t\r\n>\/].*/, "", tag); sub(/^xccdf:/, "", tag)
        if (tag == "rule-result") {
            if (open) bad = 1
            open = 1; results = 0; id = ""
            if (match($0, /idref="[^"]*"/)) id = substr($0, RSTART + 7, RLENGTH - 8)
        } else if (tag == "result" && open) {
            results++
            val = $0; sub(/^[^>]*>/, "", val); gsub(/[ \t\r\n]/, "", val)
        } else if ($0 ~ /^\/(xccdf:)?rule-result[ \t\r\n]*>/) {
            if (!open || results != 1) bad = 1
            else if (match(id, /_rule_[0-9]+(\.[0-9]+)*_/))
                print substr(id, RSTART + 6, RLENGTH - 7) ":" tolower(val)
            open = 0
        }
    }
    END { exit (bad || open) }' "$1" > "$2.unsorted" || { rm -f "$2.unsorted"; return 1; }
    sort "$2.unsorted" > "$2"
    rc=$?
    rm -f "$2.unsorted"
    return $rc
}

# CIS-CAT Pro itself is licensed software provisioned on each agent, never
# distributed by the manager. Without it, stop here: withdraw the previous
# results so SCA stops reporting them as current (the policy requires the
# flatten file), and log the message the manager rule ciscat_rules.xml alerts on.
if [ ! -x "${CISCAT_PATH}/Assessor-CLI.sh" ]; then
    for old in "$CACHE_DIR"/*/results.txt "$CACHE_DIR"/*/*/results.txt; do
        [ -f "$old" ] && mv -f "$old" "${old}.stale" 2>/dev/null
    done
    fail "CIS-CAT Pro not found on $(hostname): ${CISCAT_PATH}/Assessor-CLI.sh is missing. Assessment stopped; previous results withdrawn from SCA."
fi

# CIS-CAT Pro needs its license: the file named by ciscat.license.filepath in its settings, else a
# file in its license folder. Without it the Assessor would fail on every benchmark.
license_ok() {
    lp=$(sed -n 's/^[[:space:]]*ciscat\.license\.filepath[[:space:]]*=[[:space:]]*//p' \
        "${CISCAT_PATH}/config/assessor-cli.properties" 2>/dev/null | tail -1 | tr -d '\r')
    if [ -n "$lp" ]; then [ -s "$lp" ]; return; fi
    for f in "${CISCAT_PATH}"/license/*; do [ -s "$f" ] && return 0; done
    return 1
}
if ! license_ok; then
    for old in "$CACHE_DIR"/*/results.txt "$CACHE_DIR"/*/*/results.txt; do
        [ -f "$old" ] && mv -f "$old" "${old}.stale" 2>/dev/null
    done
    fail "CIS-CAT Pro not found on $(hostname): no license (${CISCAT_PATH}/license, or ciscat.license.filepath in its settings). Assessment stopped; previous results withdrawn from SCA."
fi

# read_conf <file>: the settings of one benchmark. The file comes from the manager: it is read
# as data (KEY="value" lines, known keys only), never sourced, so nothing in it runs as root.
read_conf() {
    BENCHMARK_FILE=""; PROFILE_LIST=""; SPLAY_MAX_SEC=0
    name=$(basename "$1")
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in ''|\#*) continue ;; esac
        key=${line%%=*}
        val=${line#*=}
        case "$val" in
            \"*\") val=${val#\"}; val=${val%\"} ;;
            *) fail "${name}: value of ${key} is not quoted" ;;
        esac
        case "$val" in *\"*) fail "${name}: quote inside the value of ${key}" ;; esac
        case "$key" in
            BENCHMARK_FILE) BENCHMARK_FILE=$val ;;
            PROFILE_LIST)   PROFILE_LIST=$val ;;
            SPLAY_MAX_SEC)  SPLAY_MAX_SEC=$val ;;
            *) log "${name}: unknown key ignored: ${key}" ;;
        esac
    done < "$1"
    [ -n "$BENCHMARK_FILE" ] || fail "${name}: BENCHMARK_FILE missing"
    [ -n "$PROFILE_LIST" ] || fail "${name}: PROFILE_LIST missing"
    case "$BENCHMARK_FILE" in */*|..*) fail "${name}: BENCHMARK_FILE must be a file name" ;; esac
    case "$SPLAY_MAX_SEC" in ''|*[!0-9]*) fail "${name}: SPLAY_MAX_SEC must be a number" ;; esac
}

# The benchmarks of this agent: conf.d/<os>.conf whose OS group still sends its settings.
KEYS=""
for c in "$CONF_DIR"/*.conf; do
    [ -f "$c" ] || continue
    k=$(basename "$c" .conf)
    case "$k" in ''|*[!a-z0-9_]*) log "ignored (not an OS key): $c"; continue ;; esac
    if [ -f "${AGENT_SHARED}/ciscat-refresh-${k}.conf" ]; then
        KEYS="$KEYS $k"
    else
        rm -f "$c"
        for old in "$CACHE_DIR/$k"/*/results.txt; do
            [ -f "$old" ] && mv -f "$old" "${old}.stale" 2>/dev/null
        done
        log "benchmark ${k} no longer applies to this agent: settings removed, results withdrawn"
    fi
done
if [ -z "$KEYS" ]; then
    [ -r "$CONF" ] || fail "no benchmark for this agent: no ${CONF_DIR}/*.conf and no ${CONF}"
    KEYS="-"  # the single refresh.conf of an older manager
fi
conf_of() { if [ "$1" = "-" ]; then echo "$CONF"; else echo "${CONF_DIR}/$1.conf"; fi; }

# every settings file is checked before any assessment starts; the longest splay applies
splay=0
for k in $KEYS; do
    read_conf "$(conf_of "$k")"
    [ "$SPLAY_MAX_SEC" -gt "$splay" ] && splay=$SPLAY_MAX_SEC
done
SPLAY_MAX_SEC=$splay

# Splay only when asked (--splay, for a local timer calling the script): runs started by the
# master are already spread in waves, and "Run now" must start now.
if [ "${1:-}" = "--splay" ] && [ "$SPLAY_MAX_SEC" -gt 0 ] 2>/dev/null; then
    delay=$(( $(od -An -N2 -tu2 /dev/urandom | tr -d ' ') % SPLAY_MAX_SEC ))
    log "splay: sleeping ${delay}s before assessment"
    sleep "$delay"
fi

# One assessment at a time (a scheduled run and an Active Response one): both would purge the
# Assessor's temporary and report folders under each other.
if command -v flock >/dev/null 2>&1; then
    exec 9>"${DATA_DIR}/refresh.lock"
    flock -n 9 || fail "another CIS-CAT assessment is running on $(hostname); this run is skipped"
fi

# Fleet-wide script: the Java 21 spawn helper fails only on EL7-era kernels
# (3.10.x) with exit 127 "Failed to exec spawn helper". Apply the documented
# VFORK fallback ONLY there; modern kernels (Debian 12, RHEL 8+) use the
# default mechanism.
case "$(uname -r)" in
    3.10.*) export JAVA_TOOL_OPTIONS="-Djdk.lang.Process.launchMechanism=VFORK" ;;
esac

exit_code=0
for k in $KEYS; do
    read_conf "$(conf_of "$k")"
    if [ "$k" = "-" ]; then
        results_dir=$CACHE_DIR
    else
        results_dir="${CACHE_DIR}/${k}"
        log "benchmark: ${k}"
    fi
    bench_path="${CISCAT_PATH}/benchmarks/${BENCHMARK_FILE}"
    if [ ! -r "$bench_path" ]; then
        log "ERROR: benchmark not found: $bench_path"
        exit_code=1
        continue
    fi
    # PROFILE_LIST entries are ';'-separated because profile NAMES contain spaces
    # (e.g. "TAILORED L1 - Server (host)"); default word-splitting would break them.
    old_ifs=$IFS
    IFS=';'
    for entry in $PROFILE_LIST; do
        IFS=$old_ifs
        [ -n "$entry" ] || continue
        P_KEY=${entry%%|*}
        P_NAME=${entry#*|}
        case "$P_KEY" in
            ''|*/*|..*)
                log "ERROR: profile key is not a folder name: ${P_KEY}"
                exit_code=1; IFS=';'; continue ;;
        esac
        profile_dir="${results_dir}/${P_KEY}"
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
        # Same short-rule-id format as on Windows; the SCA policy matches
        # lines like ^1\.1\.1\.2:pass$
        flat_tmp="${profile_dir}/.results.txt.tmp"
        if ! flatten_arf "$report" "$flat_tmp"; then
            log "ERROR: ARF report not understood (a rule-result without exactly one result): ${report}"
            rm -f "$flat_tmp"
            exit_code=1
            continue
        fi

        n=$(grep -c ':' "$flat_tmp" 2>/dev/null)
        n=${n:-0}
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
done

log "refresh completed (exit ${exit_code})"
exit "$exit_code"
