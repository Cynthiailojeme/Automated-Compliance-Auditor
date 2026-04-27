#!/usr/bin/env bash

# -----------------------------------------------------------------------------
# STRICT MODE
# -----------------------------------------------------------------------------
# -e  : exit immediately if any command fails (prevents silent failures)
# -u  : treat unset variables as errors (catches typos in variable names)
# -o pipefail : if any command in a pipe fails, the whole pipe fails
#               e.g. "docker inspect ... | grep ..." fails if docker fails,
#               not just if grep fails
# -----------------------------------------------------------------------------
set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================
# These variables control script behaviour. All can be overridden at runtime
# by setting them as environment variables before calling the script.
# Example: DISK_THRESHOLD=75 ./audit.sh
# =============================================================================

# Directory where this script lives — used to build relative paths reliably
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Where to write report files. Defaults to a 'reports/' folder one level up
# from the script. Override with: REPORT_DIR=/tmp/myreports ./audit.sh
REPORT_DIR="${REPORT_DIR:-${SCRIPT_DIR}/../reports}"

# Where Prometheus node-exporter reads textfile metrics from.
# Must match the --collector.textfile.directory flag in node-exporter's config.
METRICS_DIR="${METRICS_DIR:-/var/lib/node_exporter/textfile_collector}"

# Comma-separated list of trusted Docker image registries (C04 check).
# Any container image NOT starting with one of these prefixes will FAIL C04.
# Override with: TRUSTED_REGISTRIES="ghcr.io/myorg,gcr.io/myproject" ./audit.sh
TRUSTED_REGISTRIES="${TRUSTED_REGISTRIES:-docker.io/myorg,ghcr.io/myorg,123456789.dkr.ecr.us-east-1.amazonaws.com}"

# Maximum allowed disk usage percentage before C06 triggers a FAIL.
# Default is 80 — meaning any filesystem at 80% or above will be flagged.
DISK_THRESHOLD="${DISK_THRESHOLD:-80}"

# Timestamp used to name report files uniquely per run (ISO 8601 UTC format)
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"

# Full file paths for all three output artefacts
REPORT_FILE="${REPORT_DIR}/report_${TIMESTAMP}.json"
METRICS_FILE="${METRICS_DIR}/compliance.prom"
HUMAN_REPORT="${REPORT_DIR}/report_${TIMESTAMP}.txt"

# =============================================================================
# TERMINAL COLOUR CODES
# =============================================================================
# ANSI escape codes for coloured terminal output.
# These are only used in echo -e statements — they have no effect in files.
# RESET must be appended after every colour to stop it bleeding into next text.
# =============================================================================
RED='\033[0;31m'      # Used for FAIL markers (x)
GREEN='\033[0;32m'    # Used for PASS markers (tick)
YELLOW='\033[1;33m'   # Used for failure detail lines
CYAN='\033[0;36m'     # Used for headers and dividers
BOLD='\033[1m'        # Used for section titles and summary labels
RESET='\033[0m'       # Resets colour back to terminal default

# =============================================================================
# SETUP
# =============================================================================
# Create the reports directory if it does not already exist.
# The -p flag means: create parent directories too, and do not error if exists.
# =============================================================================
mkdir -p "${REPORT_DIR}"

# =============================================================================
# RESULT TRACKING
# =============================================================================
# PASS and FAIL are counters incremented by the record() function each time
# a check completes. RESULTS is an array that accumulates JSON objects — one
# per check — which are later combined into the final JSON report.
# =============================================================================
PASS=0
FAIL=0
declare -a RESULTS=()

# =============================================================================
# record() — CENTRAL RESULT HANDLER
# =============================================================================
# Every check function calls record() exactly once when it finishes.
# This function is responsible for:
#   1. Printing the PASS/FAIL result to the terminal with colour
#   2. Printing the failure detail line if there is one
#   3. Incrementing the PASS or FAIL counter
#   4. Appending a JSON object to the RESULTS array for the report
#
# Parameters:
#   $1 rule_id    — e.g. "C01"
#   $2 rule_name  — human-readable rule description
#   $3 status     — either "PASS" or "FAIL"
#   $4 detail     — explanation of the failure (empty string for PASS)
# =============================================================================
record() {
    local rule_id="$1" rule_name="$2" status="$3" detail="$4"

    if [[ "$status" == "PASS" ]]; then
        # || true prevents set -e from killing the script when PASS is still 0
        # because ((0++)) evaluates to 0, which Bash treats as a false/failure
        ((PASS++)) || true
        echo -e "  ${GREEN}tick${RESET} [${rule_id}] ${rule_name}"
    else
        ((FAIL++)) || true
        echo -e "  ${RED}fail${RESET} [${rule_id}] ${rule_name}"
        # Only print the detail line if detail is non-empty
        [[ -n "$detail" ]] && echo -e "       ${YELLOW}-> ${detail}${RESET}"
    fi

    # Escape the detail string so it is safe to embed inside a JSON value:
    # - backslashes become \\
    # - double quotes become \"
    # - newlines are replaced with \n literals
    local escaped_detail
    escaped_detail="$(echo "$detail" | sed 's/\\/\\\\/g; s/"/\\"/g; s/$/\\n/g' | tr -d '\n' | sed 's/\\n$//')"

    # Append a JSON object for this check to the RESULTS array.
    # This is assembled into the full JSON report at the end of the script.
    RESULTS+=("{\"id\":\"${rule_id}\",\"name\":\"${rule_name}\",\"status\":\"${status}\",\"detail\":\"${escaped_detail}\"}")
}

# =============================================================================
# running_containers() — HELPER: LIST ALL RUNNING CONTAINER IDs
# =============================================================================
# Returns a newline-separated list of short container IDs currently running.
# Every check function iterates over this list to inspect each container.
#
# 'docker ps -q' prints only the container ID column (no headers, no names).
# '2>/dev/null' silences any Docker daemon errors.
# '|| true' prevents set -e from exiting if docker ps returns a non-zero code
# =============================================================================
running_containers() {
    docker ps -q 2>/dev/null || true
}

# =============================================================================
# AUDIT HEADER
# =============================================================================
echo -e "\n${BOLD}${CYAN}Infrastructure Compliance Audit${RESET}"
echo -e "${CYAN}$(printf '=%.0s' {1..50})${RESET}"
echo -e "Started: $(date -u)\n"

# =============================================================================
# C01 — NO CONTAINERS RUNNING AS ROOT
# =============================================================================
# WHY: A container running as UID 0 (root) means that if the container is
# compromised, the attacker already has root-level access. Combined with any
# kernel exploit or volume misconfiguration, this can escalate to host root.
#
# HOW: We inspect .Config.User for each container. An empty string means no
# USER was set in the Dockerfile — Docker defaults that to root (UID 0).
# We flag empty, "0", and "root" as failures.
# =============================================================================
check_c01() {
    local offenders=()

    for cid in $(running_containers); do
        local user
        user="$(docker inspect --format '{{.Config.User}}' "$cid" 2>/dev/null)"
        local name
        name="$(docker inspect --format '{{.Name}}' "$cid" | tr -d '/')"

        if [[ -z "$user" || "$user" == "0" || "$user" == "root" ]]; then
            offenders+=("$name")
        fi
    done

    if [[ ${#offenders[@]} -eq 0 ]]; then
        record "C01" "No containers running as root" "PASS" ""
    else
        record "C01" "No containers running as root" "FAIL" "Running as root: ${offenders[*]}"
    fi
}

# =============================================================================
# C02 — ALL CONTAINERS HAVE HEALTH CHECKS DEFINED
# =============================================================================
# WHY: Without a HEALTHCHECK, Docker reports a container as "running" even
# if the application inside has crashed or is unresponsive. Orchestrators
# use health status to decide when to restart or replace containers.
#
# HOW: .Config.Healthcheck is <nil> when no HEALTHCHECK instruction exists
# in the Dockerfile and none was passed via --health-cmd at runtime.
# =============================================================================
check_c02() {
    local offenders=()

    for cid in $(running_containers); do
        local health
        health="$(docker inspect --format '{{.Config.Healthcheck}}' "$cid" 2>/dev/null)"
        local name
        name="$(docker inspect --format '{{.Name}}' "$cid" | tr -d '/')"

        if [[ -z "$health" || "$health" == "<nil>" ]]; then
            offenders+=("$name")
        fi
    done

    if [[ ${#offenders[@]} -eq 0 ]]; then
        record "C02" "All containers have health checks" "PASS" ""
    else
        record "C02" "All containers have health checks" "FAIL" "Missing healthcheck: ${offenders[*]}"
    fi
}

# =============================================================================
# C03 — NO UNEXPECTED EXPOSED PORTS
# =============================================================================
# WHY: Every exposed port is a potential attack surface. Only standard HTTP/S
# ports should be publicly reachable. A developer who casually exposes port
# 5432 (Postgres) or 6379 (Redis) creates a direct path to the data layer.
#
# HOW: We iterate all ports in .NetworkSettings.Ports per container. The port
# number is extracted from the "port/protocol" format (e.g. "3306/tcp" -> 3306)
# and checked against the allowed list. Anything not on the list is flagged.
# =============================================================================
check_c03() {
    local allowed_ports=(80 443 8080 8443)
    local offenders=()

    for cid in $(running_containers); do
        local name
        name="$(docker inspect --format '{{.Name}}' "$cid" | tr -d '/')"

        local ports
        ports="$(docker inspect --format '{{range $p,$conf := .NetworkSettings.Ports}}{{$p}} {{end}}' "$cid" 2>/dev/null)"

        for port_proto in $ports; do
            local port="${port_proto%/*}"
            local allowed=false

            for ap in "${allowed_ports[@]}"; do
                [[ "$port" == "$ap" ]] && allowed=true && break
            done

            if ! $allowed; then
                offenders+=("${name}:${port_proto}")
            fi
        done
    done

    if [[ ${#offenders[@]} -eq 0 ]]; then
        record "C03" "No unexpected exposed ports" "PASS" ""
    else
        record "C03" "No unexpected exposed ports" "FAIL" "Unexpected ports: ${offenders[*]}"
    fi
}

# =============================================================================
# C04 — ALL IMAGES PULLED FROM TRUSTED REGISTRIES
# =============================================================================
# WHY: Public images from unknown sources can contain malware or backdoors.
# Supply chain attacks on Docker Hub are documented and ongoing. Only images
# from your controlled registries should run in production.
#
# HOW: .Config.Image returns the full image reference (e.g. "prom/prometheus:latest").
# We check if it starts with any of the prefixes in TRUSTED_REGISTRIES.
# =============================================================================
check_c04() {
    local offenders=()

    # Split the comma-separated TRUSTED_REGISTRIES string into an array
    IFS=',' read -ra TRUSTED <<< "$TRUSTED_REGISTRIES"

    for cid in $(running_containers); do
        local image
        image="$(docker inspect --format '{{.Config.Image}}' "$cid" 2>/dev/null)"
        local name
        name="$(docker inspect --format '{{.Name}}' "$cid" | tr -d '/')"
        local trusted=false

        for reg in "${TRUSTED[@]}"; do
            [[ "$image" == "${reg}"* ]] && trusted=true && break
        done

        $trusted || offenders+=("${name} (${image})")
    done

    if [[ ${#offenders[@]} -eq 0 ]]; then
        record "C04" "All images from trusted registries" "PASS" ""
    else
        record "C04" "All images from trusted registries" "FAIL" "Untrusted images: ${offenders[*]}"
    fi
}

# =============================================================================
# C05 — NO SECRETS IN PLAIN TEXT ENVIRONMENT VARIABLES
# =============================================================================
# WHY: Environment variables are not encrypted. They appear in 'docker inspect'
# output, CI/CD logs, crash dumps, and /proc/self/environ. Credentials passed
# this way are routinely leaked through misconfigured logging pipelines.
#
# HOW: We read all env vars from .Config.Env and grep for variable names that
# commonly hold sensitive values. A match means the variable exists AND has a
# non-empty value. Empty variables are not flagged.
# =============================================================================
check_c05() {
    local secret_patterns=(PASSWORD SECRET TOKEN API_KEY PRIVATE_KEY DATABASE_URL)
    local offenders=()

    for cid in $(running_containers); do
        local name
        name="$(docker inspect --format '{{.Name}}' "$cid" | tr -d '/')"

        local envs
        envs="$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$cid" 2>/dev/null)"

        for pattern in "${secret_patterns[@]}"; do
            # -i = case-insensitive, -E = extended regex
            # ^${pattern}=.+ means the variable name matches AND has a value
            if echo "$envs" | grep -qiE "^${pattern}=.+"; then
                offenders+=("${name} (${pattern})")
            fi
        done
    done

    if [[ ${#offenders[@]} -eq 0 ]]; then
        record "C05" "No secrets in plain text env vars" "PASS" ""
    else
        record "C05" "No secrets in plain text env vars" "FAIL" "Suspected secrets: ${offenders[*]}"
    fi
}

# =============================================================================
# C06 — DISK USAGE BELOW THRESHOLD
# =============================================================================
# WHY: A full disk causes Docker to stop writing logs, databases to corrupt
# state, and applications to throw unhandled write errors. An 80% threshold
# gives enough runway to investigate before it becomes a production incident.
#
# HOW: 'df -h --output=pcent,target' lists percentage used and mount point
# for every filesystem. We parse the percentage, strip the % sign, and compare
# against DISK_THRESHOLD numerically.
#
# NOTE: This uses 'while read ... done < <(...)' instead of a for-loop because
# it reads multi-word lines (percent + path) which word-splitting would break.
# =============================================================================
check_c06() {
    local offenders=()

    while IFS= read -r line; do
        local usage mount
        usage="$(echo "$line" | awk '{print $5}' | tr -d '%')"
        mount="$(echo "$line" | awk '{print $6}')"

        if [[ "$usage" -ge "$DISK_THRESHOLD" ]]; then
            offenders+=("${mount} at ${usage}%")
        fi
    done < <(df -h --output=pcent,target 2>/dev/null | tail -n +2)

    if [[ ${#offenders[@]} -eq 0 ]]; then
        record "C06" "Disk usage below ${DISK_THRESHOLD}%" "PASS" ""
    else
        record "C06" "Disk usage below ${DISK_THRESHOLD}%" "FAIL" "Over threshold: ${offenders[*]}"
    fi
}

# =============================================================================
# C07 — ALL CONTAINERS HAVE CPU LIMITS
# =============================================================================
# WHY: An unconstrained container can consume all CPU on the host, starving
# every other container. One runaway process can cause a host-wide outage
# without a CPU ceiling set.
#
# HOW: .HostConfig.NanoCpus stores the CPU limit in nanocores (1 CPU = 1e9).
# A value of 0 means no limit was set. Any container with 0 is flagged.
# =============================================================================
check_c07() {
    local offenders=()

    for cid in $(running_containers); do
        local cpu_limit
        # NanoCpus: 0 = unlimited, any positive number = limit is set
        cpu_limit="$(docker inspect --format '{{.HostConfig.NanoCpus}}' "$cid" 2>/dev/null)"
        local name
        name="$(docker inspect --format '{{.Name}}' "$cid" | tr -d '/')"

        if [[ -z "$cpu_limit" || "$cpu_limit" == "0" ]]; then
            offenders+=("$name")
        fi
    done

    if [[ ${#offenders[@]} -eq 0 ]]; then
        record "C07" "All containers have CPU limits" "PASS" ""
    else
        record "C07" "All containers have CPU limits" "FAIL" "No CPU limit: ${offenders[*]}"
    fi
}

# =============================================================================
# C08 — ALL CONTAINERS HAVE MEMORY LIMITS
# =============================================================================
# WHY: Without a memory limit, the Linux OOM killer decides what to kill when
# the host runs out of memory — and it may kill a healthy database instead of
# the leaking container. Memory limits make failures predictable and isolated.
#
# HOW: .HostConfig.Memory stores the memory limit in bytes.
# 0 means unlimited. Any container with 0 is flagged.
# =============================================================================
check_c08() {
    local offenders=()

    for cid in $(running_containers); do
        local mem_limit
        # Memory: 0 = unlimited, positive value = bytes limit is set
        mem_limit="$(docker inspect --format '{{.HostConfig.Memory}}' "$cid" 2>/dev/null)"
        local name
        name="$(docker inspect --format '{{.Name}}' "$cid" | tr -d '/')"

        if [[ -z "$mem_limit" || "$mem_limit" == "0" ]]; then
            offenders+=("$name")
        fi
    done

    if [[ ${#offenders[@]} -eq 0 ]]; then
        record "C08" "All containers have memory limits" "PASS" ""
    else
        record "C08" "All containers have memory limits" "FAIL" "No memory limit: ${offenders[*]}"
    fi
}

# =============================================================================
# C09 — NO CONTAINERS RUNNING IN PRIVILEGED MODE
# =============================================================================
# WHY: --privileged completely removes container isolation. A privileged
# container can mount host filesystems, load kernel modules, and access all
# block devices — effectively giving the container full root on the host.
# There is almost never a legitimate reason for a production workload to be
# privileged.
#
# HOW: .HostConfig.Privileged is a boolean. If it returns "true" — FAIL.
# =============================================================================
check_c09() {
    local offenders=()

    for cid in $(running_containers); do
        local priv
        # Returns "true" or "false"
        priv="$(docker inspect --format '{{.HostConfig.Privileged}}' "$cid" 2>/dev/null)"
        local name
        name="$(docker inspect --format '{{.Name}}' "$cid" | tr -d '/')"

        if [[ "$priv" == "true" ]]; then
            offenders+=("$name")
        fi
    done

    if [[ ${#offenders[@]} -eq 0 ]]; then
        record "C09" "No privileged containers" "PASS" ""
    else
        record "C09" "No privileged containers" "FAIL" "Privileged: ${offenders[*]}"
    fi
}

# =============================================================================
# C10 — CONTAINERS USE READ-ONLY ROOT FILESYSTEM
# =============================================================================
# WHY: A writable root filesystem lets an attacker who gains code execution
# persist changes — replacing binaries, planting backdoors, modifying config.
# A read-only root filesystem means nothing survives a container restart.
# Legitimate write paths (logs, uploads) should use explicit volume mounts.
#
# HOW: .HostConfig.ReadonlyRootfs is a boolean set by the --read-only flag.
# If it is not "true", the container has a writable root — FAIL.
# =============================================================================
check_c10() {
    local offenders=()

    for cid in $(running_containers); do
        local ro
        # Returns "true" if --read-only was set, "false" otherwise
        ro="$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$cid" 2>/dev/null)"
        local name
        name="$(docker inspect --format '{{.Name}}' "$cid" | tr -d '/')"

        if [[ "$ro" != "true" ]]; then
            offenders+=("$name")
        fi
    done

    if [[ ${#offenders[@]} -eq 0 ]]; then
        record "C10" "Containers use read-only root filesystem" "PASS" ""
    else
        record "C10" "Containers use read-only root filesystem" "FAIL" "Writable root fs: ${offenders[*]}"
    fi
}

# =============================================================================
# C11 — NO CONTAINERS USING HOST NETWORK MODE
# =============================================================================
# WHY: --network host removes the network namespace entirely. The container
# shares the host's network stack, can bind to any host interface, and can
# reach services on 127.0.0.1 — including the Docker socket and cloud metadata
# endpoints. Docker bridge networking exists to prevent exactly this.
#
# HOW: .HostConfig.NetworkMode returns "host" when host networking is active.
# Any other value ("bridge", "monitoring", a named network) is acceptable.
# =============================================================================
check_c11() {
    local offenders=()

    for cid in $(running_containers); do
        local netmode
        # Common values: "bridge", "host", "none", or a custom named network
        netmode="$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$cid" 2>/dev/null)"
        local name
        name="$(docker inspect --format '{{.Name}}' "$cid" | tr -d '/')"

        if [[ "$netmode" == "host" ]]; then
            offenders+=("$name")
        fi
    done

    if [[ ${#offenders[@]} -eq 0 ]]; then
        record "C11" "No containers using host network mode" "PASS" ""
    else
        record "C11" "No containers using host network mode" "FAIL" "Host network mode: ${offenders[*]}"
    fi
}

# =============================================================================
# C12 — DOCKER DAEMON NOT EXPOSED ON TCP PORT 2375
# =============================================================================
# WHY: Port 2375 is the Docker daemon's unauthenticated TCP interface.
# Anyone who can reach it has full control of the Docker engine. This port is
# actively scanned on the internet. The Docker socket should only be accessible
# via /var/run/docker.sock or over mutual TLS on port 2376.
#
# HOW: 'ss -tlnp' lists all TCP listening sockets with process info.
# We grep for ':2375' — if found, the daemon is exposed unencrypted — FAIL.
# This is a host-level check, not a per-container check.
# =============================================================================
check_c12() {
    # ss -tlnp: t=TCP, l=listening, n=numeric ports, p=show process
    if ss -tlnp 2>/dev/null | grep -q ':2375'; then
        record "C12" "Docker daemon not exposed on TCP 2375" "FAIL" \
            "Port 2375 is open — unauthenticated Docker API access possible"
    else
        record "C12" "Docker daemon not exposed on TCP 2375" "PASS" ""
    fi
}

# =============================================================================
# C13 — NO CONTAINERS SHARING HOST PID NAMESPACE
# =============================================================================
# WHY: --pid host gives the container visibility into every process on the
# host — their /proc entries, environment variables, and open file descriptors.
# A container with host PID access can signal host processes and read memory
# it has no legitimate reason to touch. PID namespace isolation is a core
# container security boundary.
#
# HOW: .HostConfig.PidMode returns "host" when host PID sharing is active.
# An empty string means properly isolated, which is acceptable.
# =============================================================================
check_c13() {
    local offenders=()

    for cid in $(running_containers); do
        local pidmode
        # "host" = sharing host PID namespace, "" = properly isolated
        pidmode="$(docker inspect --format '{{.HostConfig.PidMode}}' "$cid" 2>/dev/null)"
        local name
        name="$(docker inspect --format '{{.Name}}' "$cid" | tr -d '/')"

        if [[ "$pidmode" == "host" ]]; then
            offenders+=("$name")
        fi
    done

    if [[ ${#offenders[@]} -eq 0 ]]; then
        record "C13" "No containers sharing host PID namespace" "PASS" ""
    else
        record "C13" "No containers sharing host PID namespace" "FAIL" "Host PID namespace: ${offenders[*]}"
    fi
}

# =============================================================================
# C14 — CONTAINER IMAGES NOT OLDER THAN 90 DAYS
# =============================================================================
# WHY: Stale images accumulate unpatched CVEs in the OS packages, language
# runtime, and baked-in dependencies. A 90-day rebuild cadence is a minimum
# baseline. If CI/CD is healthy, images should never reach this threshold.
#
# HOW: .Created returns the container's creation timestamp in RFC3339 format.
# We convert both the creation date and the 90-days-ago cutoff to Unix epoch
# seconds, then compare them numerically.
# 'date -d' works on Linux; 'date -v-90d' is the macOS/BSD fallback.
# =============================================================================
check_c14() {
    local offenders=()

    # Calculate Unix timestamp for exactly 90 days ago
    # 'date -d' is GNU/Linux syntax; 'date -v-90d' is BSD/macOS fallback
    local cutoff
    cutoff="$(date -d '90 days ago' +%s 2>/dev/null || date -v-90d +%s 2>/dev/null || echo 0)"

    for cid in $(running_containers); do
        # .Created format: "2026-01-15T10:30:00.123456789Z"
        # Take first 19 characters and replace T with space to get a parseable date
        local created
        created="$(docker inspect --format '{{.Created}}' "$cid" 2>/dev/null | cut -c1-19 | tr 'T' ' ')"

        # Convert creation date string to Unix epoch
        # Fallback to far-future epoch so unknown dates do not trigger false FAILs
        local created_epoch
        created_epoch="$(date -d "$created" +%s 2>/dev/null \
            || date -j -f '%Y-%m-%d %H:%M:%S' "$created" +%s 2>/dev/null \
            || echo 9999999999)"

        local name
        name="$(docker inspect --format '{{.Name}}' "$cid" | tr -d '/')"

        # If the image was created before the cutoff date — it is stale
        if [[ "$created_epoch" -lt "$cutoff" ]]; then
            offenders+=("$name")
        fi
    done

    if [[ ${#offenders[@]} -eq 0 ]]; then
        record "C14" "No images older than 90 days" "PASS" ""
    else
        record "C14" "No images older than 90 days" "FAIL" "Stale images: ${offenders[*]}"
    fi
}

# =============================================================================
# C15 — DOCKER CONTENT TRUST IS ENABLED
# =============================================================================
# WHY: Docker Content Trust (DCT) uses cryptographic signatures to verify that
# pulled images have not been tampered with. Without it, 'docker pull' fetches
# whatever the registry returns for a tag — even a silently overwritten image.
# Setting DOCKER_CONTENT_TRUST=1 makes Docker reject unsigned images at pull
# time, closing the most direct supply chain attack vector.
#
# HOW: This is a host environment check, not a container-level check.
# We read the DOCKER_CONTENT_TRUST environment variable. If it is not "1",
# content trust is disabled or was never configured — FAIL.
# =============================================================================
check_c15() {
    # ${DOCKER_CONTENT_TRUST:-0} defaults to "0" if the variable is unset,
    # which correctly triggers a FAIL when DCT has never been configured
    if [[ "${DOCKER_CONTENT_TRUST:-0}" == "1" ]]; then
        record "C15" "Docker Content Trust is enabled" "PASS" ""
    else
        record "C15" "Docker Content Trust is enabled" "FAIL" \
            "DOCKER_CONTENT_TRUST is not set to 1"
    fi
}

# =============================================================================
# RUN ALL CHECKS
# =============================================================================
# Each check is called sequentially. The order matches the rulebook (C01-C15).
# Adding a new rule means: write a check_cNN() function above, then add the
# call here. Nothing else in the script needs to change.
# =============================================================================
check_c01; check_c02; check_c03; check_c04; check_c05
check_c06; check_c07; check_c08; check_c09; check_c10
check_c11; check_c12; check_c13; check_c14; check_c15

# =============================================================================
# SCORE CALCULATION
# =============================================================================
# TOTAL = PASS + FAIL (always equals 15 for this ruleset)
# SCORE = percentage of checks passed, rounded down to nearest integer
# Integer arithmetic in Bash truncates — (7 * 100) / 15 = 46 (not 46.67)
# Guard against division by zero with the TOTAL > 0 conditional
# =============================================================================
TOTAL=$((PASS + FAIL))
SCORE=$(( TOTAL > 0 ? (PASS * 100) / TOTAL : 0 ))

# =============================================================================
# TERMINAL SUMMARY
# =============================================================================
echo -e "\n${BOLD}Summary${RESET}"
echo -e "  Total checks : ${TOTAL}"
echo -e "  Passed       : ${GREEN}${PASS}${RESET}"
echo -e "  Failed       : ${RED}${FAIL}${RESET}"
echo -e "  Score        : ${BOLD}${SCORE}%${RESET}\n"

# =============================================================================
# WRITE HUMAN-READABLE TEXT REPORT
# =============================================================================
# The { ... } > file construct redirects everything inside the block to the
# file in one operation. python3 is used to parse each JSON result object
# and extract individual fields cleanly without a jq dependency.
# =============================================================================
{
    echo "COMPLIANCE AUDIT REPORT"
    echo "========================"
    echo "Timestamp : $(date -u)"
    echo "Host      : $(hostname)"
    echo "Score     : ${SCORE}% (${PASS}/${TOTAL})"
    echo ""
    for result in "${RESULTS[@]}"; do
        id="$(echo "$result"     | python3 -c "import sys,json; r=json.load(sys.stdin); print(r['id'])")"
        name="$(echo "$result"   | python3 -c "import sys,json; r=json.load(sys.stdin); print(r['name'])")"
        status="$(echo "$result" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r['status'])")"
        detail="$(echo "$result" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r['detail'])")"
        echo "[${status}] ${id}: ${name}"
        [[ -n "$detail" ]] && echo "       Detail: ${detail}"
    done
} > "${HUMAN_REPORT}"

# =============================================================================
# WRITE JSON REPORT
# =============================================================================
# The JSON report is a single object containing audit metadata and a 'checks'
# array with one entry per rule. The RESULTS array was built incrementally by
# record() — here we join its elements with commas using printf and sed.
#
# 'printf '%s,' "${RESULTS[@]}"' prints each element followed by a comma.
# The trailing comma on the last element is removed by 'sed s/,$//'
# This avoids the need for jq or any external JSON library.
# =============================================================================
EPOCH_TS="$(date +%s)"
RESULTS_JSON="$(printf '%s,' "${RESULTS[@]}" | sed 's/,$//')"

cat > "${REPORT_FILE}" <<JSON
{
  "timestamp": "${TIMESTAMP}",
  "epoch": ${EPOCH_TS},
  "host": "$(hostname)",
  "score_percent": ${SCORE},
  "total": ${TOTAL},
  "passed": ${PASS},
  "failed": ${FAIL},
  "checks": [${RESULTS_JSON}]
}
JSON

echo -e "JSON report  : ${REPORT_FILE}"
echo -e "Text report  : ${HUMAN_REPORT}"

# =============================================================================
# WRITE PROMETHEUS METRICS FILE
# =============================================================================
# Prometheus uses a pull model — node-exporter scrapes this file periodically
# and exposes its contents as metrics on port 9100. Grafana then queries
# Prometheus to display the compliance dashboard.
#
# Each metric block follows the Prometheus exposition format:
#   # HELP <name> <description>
#   # TYPE <name> <type>
#   <name> <value>
#
# 'gauge' type is correct here because these values can go up or down between
# audit runs (unlike 'counter' which only increases monotonically).
#
# We only write the file if the directory is writable — on developer machines
# the node-exporter path may not exist, so we skip it gracefully rather than
# failing the entire audit.
# =============================================================================
mkdir -p "${METRICS_DIR}" 2>/dev/null || true

if [[ -w "${METRICS_DIR}" ]] || mkdir -p "${METRICS_DIR}" 2>/dev/null; then
    cat > "${METRICS_FILE}" <<PROM
# HELP compliance_checks_total Total number of compliance checks run
# TYPE compliance_checks_total gauge
compliance_checks_total ${TOTAL}

# HELP compliant_checks Number of checks that passed
# TYPE compliant_checks gauge
compliant_checks ${PASS}

# HELP failed_checks Number of checks that failed
# TYPE failed_checks gauge
failed_checks ${FAIL}

# HELP compliance_score_percent Compliance score as a percentage
# TYPE compliance_score_percent gauge
compliance_score_percent ${SCORE}

# HELP last_audit_timestamp Unix timestamp of the last completed audit
# TYPE last_audit_timestamp gauge
last_audit_timestamp ${EPOCH_TS}
PROM
    echo -e "Metrics      : ${METRICS_FILE}"
fi

# =============================================================================
# EXIT CODE
# =============================================================================
# Exit 0 = fully compliant (all checks passed) — safe for CI/CD green builds
# Exit 1 = one or more failures — CI/CD pipeline will mark the run as failed
#
# This makes the script composable in pipelines:
#   ./audit.sh && deploy.sh || notify_team.sh
# =============================================================================
[[ "$FAIL" -eq 0 ]] && exit 0 || exit 1