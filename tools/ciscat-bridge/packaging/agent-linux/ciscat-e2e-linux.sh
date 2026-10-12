#!/bin/sh
# ciscat-e2e-linux.sh - end-to-end check of the CIS-CAT bridge on a Linux agent (shell only).
# Run as root on the agent:
#   sh ciscat-e2e-linux.sh pre      before the run
#   sh ciscat-e2e-linux.sh watch    right after "run" on the master (follows the run live)
#   sh ciscat-e2e-linux.sh post     when watch ends
# Read-only. Prints EXPECT / GOT and PASS, FAIL or WAIT per check.
STEP=${1:-pre}
WATCH_MIN=${WATCH_MIN:-40}
OSSEC=${E2E_OSSEC:-/var/ossec}
ASSESSOR=${E2E_ASSESSOR:-/opt/ciscat/Assessor}
DATA=${E2E_DATA:-/var/lib/wazuh-ciscat}
SHARED=$OSSEC/etc/shared
BIN=$OSSEC/active-response/bin
ARLOG=$OSSEC/logs/active-responses.log
OLOG=$OSSEC/logs/ossec.log
BOOTSTRAP_SHA=@BOOTSTRAP_SHA@
NP=0; NF=0; NW=0

check() { # check <code> <title> <expect> <got> <ok 0/1> [wait]
    if [ "$5" = 0 ]; then s=PASS; NP=$((NP + 1))
    elif [ -n "${6:-}" ]; then s=WAIT; NW=$((NW + 1))
    else s=FAIL; NF=$((NF + 1)); fi
    printf '[%s] %s %s\n        EXPECT: %s\n        GOT:    %s\n' "$s" "$1" "$2" "$3" "$4"
}
info() { printf '[INFO] %s %s\n' "$1" "$2"; }
sha() { [ -f "$1" ] && sha256sum "$1" | cut -d' ' -f1 || echo missing; }
# the benchmarks of this agent: one ciscat-refresh-<os>.conf per OS group in the shared folder
oses() { for f in "$SHARED"/ciscat-refresh-*.conf; do [ -f "$f" ] && basename "$f" .conf | sed 's/^ciscat-refresh-//'; done; }
conf_val() { sed -n "s/^$2=\"\(.*\)\"$/\1/p" "$1" | head -1; }

pre() {
    echo "== host $(hostname)  $(cat /etc/redhat-release 2>/dev/null || uname -sr)  $(date '+%F %T')"
    st=$(systemctl is-active wazuh-agent 2>/dev/null || echo unknown)
    check L1 "Wazuh agent service" "active" "$st" "$([ "$st" = active ]; echo $?)"
    info L1 "$($OSSEC/bin/wazuh-control info 2>/dev/null | grep -E 'VERSION' | tr '\n' ' ')"
    for pair in "ciscat-bootstrap-linux0 ciscat-bootstrap.sh" "ciscat-refresh-linux0 ciscat-refresh.sh"; do
        set -- $pair
        line=$(grep "^$1 " "$SHARED/ar.conf" 2>/dev/null)
        check L2 "the master maps $1" "$1 - $2 - 0" "${line:-missing in shared/ar.conf}" \
            "$(echo "$line" | grep -q " - $2 - "; echo $?)"
    done
    got=$(sha "$BIN/ciscat-bootstrap.sh")
    check L3 "ciscat-bootstrap.sh in active-response/bin (@VERSION@)" "$BOOTSTRAP_SHA" "$got" "$([ "$got" = "$BOOTSTRAP_SHA" ]; echo $?)"
    perm=$(stat -c '%a %U:%G' "$BIN/ciscat-bootstrap.sh" 2>/dev/null)
    check L3 "its owner and mode" "750 root:wazuh" "${perm:-missing}" "$([ "$perm" = "750 root:wazuh" ]; echo $?)"
    k="$DATA/ciscat-manifest.pub"
    check L3 "master's public key (manifests must be signed with it)" "$k" \
        "$([ -s "$k" ] && echo "sha256 $(sha256sum "$k" | cut -d' ' -f1)" || echo "missing: reinstall with --pubkey")" \
        "$([ -s "$k" ] && command -v openssl >/dev/null; echo $?)"
    own=$(stat -c '%U' /opt/ciscat "$ASSESSOR" 2>/dev/null | sort -u | tr '\n' ' ')
    check L4 "/opt/ciscat and the Assessor owned by root (root runs them)" "root" "${own:-missing}" \
        "$([ "$own" = "root " ]; echo $?)"
    check L4 "CIS-CAT Pro Assessor" "$ASSESSOR/Assessor-CLI.sh executable" \
        "$([ -x "$ASSESSOR/Assessor-CLI.sh" ] && echo present || echo missing)" "$([ -x "$ASSESSOR/Assessor-CLI.sh" ]; echo $?)"
    info L4 "JRE: $("$ASSESSOR/jre/bin/java" -version 2>&1 | head -1)"
    lp=$(sed -n 's/^[[:space:]]*ciscat\.license\.filepath[[:space:]]*=[[:space:]]*//p' "$ASSESSOR/config/assessor-cli.properties" 2>/dev/null | tail -1)
    lic=""
    if [ -n "$lp" ]; then [ -s "$lp" ] && lic=$lp
    else for f in "$ASSESSOR"/license/*; do [ -s "$f" ] && lic=$f && break; done; fi
    check L4 "CIS-CAT Pro license" "a license file ($ASSESSOR/license or ciscat.license.filepath)" "${lic:-not found}" "$([ -n "$lic" ]; echo $?)"
    sig=$(grep -E '^\s*exit\.on\.invalid\.signature\s*=' "$ASSESSOR/config/assessor-cli.properties" 2>/dev/null)
    check L5 "custom benchmark accepted unsigned" "exit.on.invalid.signature=false" "${sig:-not set}" \
        "$(echo "$sig" | grep -q 'false'; echo $?)"
    list=$(oses | tr '\n' ' ')
    check L6 "benchmarks published for this agent" "one ciscat-refresh-<os>.conf per OS group" "${list:-none}" "$([ -n "$list" ]; echo $?)"
    for k in $(oses); do
        c="$SHARED/ciscat-refresh-$k.conf"
        info L6 "$k: BENCHMARK_FILE=$(conf_val "$c" BENCHMARK_FILE) PROFILE_LIST=$(conf_val "$c" PROFILE_LIST)"
        m="$SHARED/ciscat-manifest-$k.csv"
        if [ -f "$m" ]; then
            bad=$(grep -v '^#' "$m" | while IFS=';' read -r name expected dest; do
                [ -n "$name" ] || continue
                [ "$(sha "$SHARED/$name")" = "$expected" ] || printf '%s ' "$name"
            done)
            check L7 "files of $k as published by the master" "every sha256 of ciscat-manifest-$k.csv equal" \
                "${bad:-all equal}" "$([ -z "$bad" ]; echo $?)"
        else
            check L7 "manifest of $k" "$m" "missing" 1
        fi
    done
    win=$(ls "$SHARED"/ciscat-params-*.txt 2>/dev/null | xargs -r -n1 basename | tr '\n' ' ')
    check L8 "no Windows benchmark sent to this Linux agent" "no ciscat-params-*.txt in shared" "${win:-none}" "$([ -z "$win" ]; echo $?)"
    pols=$(sed -n 's:.*<policy>[[:space:]]*\([^<]*\)</policy>.*:\1:p' "$SHARED/agent.conf" 2>/dev/null | tr '\n' ' ')
    check L9 "SCA policies loaded from the groups" "one .yml per benchmark" "${pols:-none}" "$([ -n "$pols" ]; echo $?)"
    for p in $pols; do
        f="$SHARED/$(basename "$p")"
        flat=$(sed -n "s/.*'f:\([^' ]*\).*/\1/p" "$f" 2>/dev/null | head -1)
        case "$flat" in /var/lib/wazuh-ciscat/reports-cache/*/*/results.txt) ok=0 ;; *) ok=1 ;; esac
        check L10 "policy $(basename "$p") reads its per-OS results file" \
            "/var/lib/wazuh-ciscat/reports-cache/<os>/<profile>/results.txt" "${flat:-policy file missing}" "$ok"
    done
    ls -1 "$DATA/conf.d" 2>/dev/null | sed 's/^/[INFO] L11 installed settings: /'
    find "$DATA/reports-cache" -name results.txt 2>/dev/null | while read -r r; do
        info L12 "results now: $r  $(date -r "$r" '+%F %T')  $(wc -l < "$r") lines"
    done
    for t in flock sha256sum setsid awk; do command -v $t >/dev/null || info L13 "MISSING tool: $t"; done
}

watch() {
    echo "== following the AR log and the processes for up to $WATCH_MIN min (Ctrl+C to stop)"
    seen=$(wc -l < "$ARLOG" 2>/dev/null || echo 0)
    t0=$(date +%s); started=""
    while [ $(( $(date +%s) - t0 )) -lt $((WATCH_MIN * 60)) ]; do
        now=$(wc -l < "$ARLOG" 2>/dev/null || echo 0)
        if [ "$now" -gt "$seen" ]; then
            new=$(sed -n "$((seen + 1)),${now}p" "$ARLOG" | grep -i ciscat)
            [ -n "$new" ] && echo "$new" | sed 's/^/  log> /'
            echo "$new" | grep -q 'ciscat-bootstrap\|ciscat-refresh' && started=1
            seen=$now
            echo "$new" | grep -q 'refresh completed\|another CIS-CAT assessment is running' && {
                echo "== the run ended: now 'post'"; return; }
        fi
        el=$(( $(date +%s) - t0 ))
        procs=$(ps -eo pid,etime,args 2>/dev/null | grep -E 'Assessor|ciscat-refresh|ciscat-bootstrap' | grep -v grep | awk '{print $1"("$2") "$3" "$4}' | tr '\n' ';')
        printf '  %4ss  running: %s\n' "$el" "${procs:-none}"
        if [ -z "$started" ] && [ "$el" -ge 180 ]; then
            echo "[FAIL] no ciscat Active Response ran on this agent within 3 minutes"
            echo "       check shared/ar.conf (L2) and these ossec.log lines:"
            tail -n 400 "$OLOG" | grep -iE 'execd|active.response|ciscat' | tail -15 | sed 's/^/         /'
            return
        fi
        sleep 15
    done
    echo "== stopped after $WATCH_MIN min: run 'post'"
}

post() {
    run=$(grep -i ciscat "$ARLOG" 2>/dev/null | awk '/ciscat-bootstrap: invoked/ {buf=""} {buf=buf $0 "\n"} END {printf "%s", buf}')
    first=$(echo "$run" | head -1)
    check P1 "the Active Response ran the bootstrap" "a 'ciscat-bootstrap: invoked' line" "${first:-no ciscat run in the AR log}" \
        "$(echo "$first" | grep -q 'invoked'; echo $?)"
    [ -n "$run" ] || return
    for pat in "bootstrap done: installed=" "benchmark: " "Running CIS-CAT profile" "flatten OK" "refresh completed (exit 0)"; do
        hit=$(echo "$run" | grep -F "$pat" | tail -1)
        check P2 "step: $pat" "$pat" "${hit:-not in this run}" "$([ -n "$hit" ]; echo $?)"
    done
    echo "$run" | grep -E 'ERROR|WARNING|REFUSED|MISSING' | sed 's/^/[INFO] P2 /'
    t=$(date -d "$(echo "$first" | awk '{print $1" "$2}' | tr '/' '-')" +%s 2>/dev/null || echo 0)
    for k in $(oses); do
        for r in "$DATA/reports-cache/$k"/*/results.txt; do
            [ -f "$r" ] || { check P3 "results of $k" "$DATA/reports-cache/$k/<profile>/results.txt" "missing" 1; continue; }
            m=$(date -r "$r" +%s); n=$(wc -l < "$r")
            pass=$(grep -c ':pass$' "$r"); fail=$(grep -c ':fail$' "$r")
            check P3 "results of $k written by this run" "after $(date -d "@$t" '+%F %T')" \
                "$(date -r "$r" '+%F %T')  pass=$pass fail=$fail" "$([ "$m" -ge "$t" ] && [ "$n" -gt 0 ]; echo $?)"
        done
    done
    log=$(ls -1t "$DATA"/logs/refresh_*.log 2>/dev/null | head -1)
    [ -n "$log" ] && info P3 "assessment log: $log (last lines below)" && tail -5 "$log" | sed 's/^/         /'
    sca=$(tail -n 2000 "$OLOG" 2>/dev/null | grep -E 'sca: INFO: (Evaluation finished|Security Configuration Assessment scan finished|Starting evaluation)' | tail -6)
    last=$(echo "$sca" | tail -1)
    lt=$(date -d "$(echo "$last" | awk '{print $1" "$2}' | tr '/' '-')" +%s 2>/dev/null || echo 0)
    check P4 "SCA re-read the results after the run" "an SCA scan in ossec.log after the run" \
        "$([ "$lt" -ge "$t" ] && [ "$t" -gt 0 ] && echo "$last" || echo "no SCA scan since the run (every 1h with the bridge; restart the agent to scan now)")" \
        "$([ "$lt" -ge "$t" ] && [ "$t" -gt 0 ]; echo $?)" wait
}

case "$STEP" in
    pre) pre ;; watch) watch ;; post) post ;;
    *) echo "usage: sh $0 pre|watch|post"; exit 2 ;;
esac
printf '\nSUMMARY: PASS=%s FAIL=%s WAIT=%s\n' "$NP" "$NF" "$NW"
[ "$NF" -eq 0 ]
