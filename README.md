# Automated Compliance Auditor

Capstone Project — SCA DevOps Group 3

A tool that audits running Docker infrastructure against a security and compliance checklist, generates reports, and tracks compliance over time through a live Grafana dashboard.

---

## What it does

- Runs 15 security checks against all running Docker containers and the host system
- Outputs a compliance report in both human-readable and JSON format
- Exposes Prometheus metrics that feed a live Grafana dashboard
- Runs the audit on an hourly schedule so compliance can be tracked over time

---

## Project structure
```bash
Automated-Compliance-Auditor/
├── scripts/
│   └── audit.sh              # Main audit script (15 checks, C01–C15)
├── auditor/
│   └── Dockerfile            # Container image for the auditor service
├── grafana/
│   ├── dashboards/
│   │   └── compliance.json   # Grafana dashboard export
│   └── provisioning/
│       ├── datasources/
│       │   └── prometheus.yml
│       └── dashboards/
│           └── dashboards.yml
├── metrics/
│   └── compliance.prom       # Prometheus textfile metrics (runtime generated)
├── reports/                  # Audit reports (runtime generated, hourly)
├── prometheus.yml            # Prometheus scrape configuration
├── docker-compose.yml        # All services: auditor, prometheus, node-exporter, grafana
└── CHECKLIST.md              # Full compliance rulebook with rationale
```

---

## Compliance rules

15 rules are checked on every audit run across three scopes:

| Scope | Rules |
|---|---|
| Container | C01, C02, C04, C05, C07, C08, C09, C10, C13, C14 |
| Network | C03, C11 |
| Host | C06, C12, C15 |

See [CHECKLIST.md](./CHECKLIST.md) for the full list with severity ratings and rationale.

---

## Prometheus metrics

The audit script writes the following metrics to `metrics/compliance.prom` after every run:

| Metric | Description |
|---|---|
| `compliance_checks_total` | Total number of checks run |
| `compliant_checks` | Number of checks that passed |
| `failed_checks` | Number of checks that failed |
| `compliance_score_percent` | Overall compliance score as a percentage |
| `last_audit_timestamp` | Unix timestamp of the last completed audit |

---

## Getting started

**Prerequisites:** Docker and Docker Compose installed and running.

**Clone the repo:**
```bash
git clone https://github.com/Cynthiailojeme/Automated-Compliance-Auditor
cd Automated-Compliance-Auditor
```

**Start all services:**
```bash
docker compose up -d
```

**Access the tools:**

| Service | URL |
|---|---|
| Grafana dashboard | http://localhost:3000 |
| Prometheus | http://localhost:9090 |
| Node Exporter | http://localhost:9100 |

Grafana login: `admin` / `admin`

---

## Running the audit manually

```bash
docker exec auditor bash /scripts/audit.sh
```

With custom configuration:
```bash
docker exec -e DISK_THRESHOLD=75 -e TRUSTED_REGISTRIES="ghcr.io/myorg" auditor bash /scripts/audit.sh
```

---

## Configuration

All thresholds are controlled via environment variables:

| Variable | Default | Description |
|---|---|---|
| `TRUSTED_REGISTRIES` | `docker.io/myorg,ghcr.io/myorg` | Comma-separated trusted image registry prefixes |
| `DISK_THRESHOLD` | `80` | Maximum allowed disk usage percentage |
| `REPORT_DIR` | `../reports` | Where to write JSON and text reports |
| `METRICS_DIR` | `/var/lib/node_exporter/textfile_collector` | Where to write the Prometheus metrics file |

---

## Audit outputs

Every hourly run produces three outputs:

1. **Terminal output** — colour-coded PASS/FAIL per rule, printed live
2. **JSON report** — machine-readable, saved to `reports/report_<timestamp>.json`
3. **Text report** — human-readable, saved to `reports/report_<timestamp>.txt`

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All 15 checks passed — fully compliant |
| `1` | One or more checks failed — action required |