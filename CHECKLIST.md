# Compliance Checklist

15 rules checked on every audit run against running Docker containers and the host system.

| ID  | Rule                                  | Scope      | Severity | Rationale |
|-----|---------------------------------------|------------|----------|-----------|
| C01 | No containers running as root         | Container  | HIGH     | Root inside a container maps to root on the host if namespace isolation is bypassed. Use a non-root UID in the Dockerfile USER instruction. |
| C02 | All containers have health checks     | Container  | MEDIUM   | Without a HEALTHCHECK, orchestrators cannot detect silent failures. The container appears running while serving errors. |
| C03 | No unexpected exposed ports           | Network    | HIGH     | Every exposed port is an attack surface. Only ports 80, 443, 8080, and 8443 are permitted by default. Override ALLOWED_PORTS to adjust. |
| C04 | Images from trusted registries only   | Container  | HIGH     | Pulling from arbitrary registries risks supply chain attacks. Allowlist is set via TRUSTED_REGISTRIES env var. |
| C05 | No secrets in plain text env vars     | Container  | CRITICAL | Environment variables are readable by any process in the container, visible in docker inspect output, and frequently appear in logs. Use Secrets Manager or mounted secret files instead. |
| C06 | Disk usage below threshold            | Host       | MEDIUM   | Full disks cause silent write failures, log loss, and application crashes. Default threshold is 80%. Set DISK_THRESHOLD to adjust. |
| C07 | All containers have CPU limits        | Container  | MEDIUM   | Without CPU limits a single runaway container can starve all others on the host. |
| C08 | All containers have memory limits     | Container  | MEDIUM   | Unbounded memory leads to OOM kills that take down unrelated containers. The kernel kills the largest consumer first. |
| C09 | No privileged containers              | Container  | CRITICAL | Privileged mode disables almost all container isolation. A process inside has full access to the host kernel and all devices. |
| C10 | Read-only root filesystem             | Container  | MEDIUM   | A writable root filesystem lets an attacker persist malware across restarts. Use volumes for paths that genuinely need writes. |
| C11 | No host network mode                  | Network    | HIGH     | Host networking bypasses Docker's network namespace, giving the container direct access to all host interfaces and listening ports. |
| C12 | Docker API not exposed on TCP 2375    | Host       | CRITICAL | An unauthenticated Docker socket on TCP 2375 is equivalent to root access to the host. Use the Unix socket only, or TLS on 2376. |
| C13 | No host PID namespace                 | Container  | HIGH     | Sharing the host PID namespace lets the container see and signal all host processes, enabling privilege escalation. |
| C14 | Images not older than 90 days         | Container  | MEDIUM   | Stale images accumulate unpatched CVEs. Rebuild and redeploy on a regular cadence. |
| C15 | Docker Content Trust enabled          | Host       | MEDIUM   | Content Trust verifies image signatures before pulling. Prevents tampered images from being deployed even from a trusted registry. Set DOCKER_CONTENT_TRUST=1. |

## Severity Definitions

- CRITICAL: Exploitable remotely or leads to full host compromise. Fix immediately.
- HIGH: Significantly reduces isolation or expands attack surface. Fix within 24 hours.
- MEDIUM: Best practice violation that increases risk over time. Fix within one sprint.

## Configuration

All thresholds and lists are controlled via environment variables:

```
TRUSTED_REGISTRIES   Comma-separated registry prefixes (default: docker.io/myorg,ghcr.io/myorg)
DISK_THRESHOLD       Integer, percent (default: 80)
REPORT_DIR           Path for JSON and text reports (default: ../reports)
METRICS_DIR          Path for .prom file (default: /var/lib/node_exporter/textfile_collector)
```
