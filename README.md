# Automated Compliance Auditor

Capstone Project - SCA DevOps Group 3

A tool that audits running Docker infrastructure against a security and 
compliance checklist, generates reports, and tracks compliance over time 
through a live Grafana dashboard.

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
├── .github/
│   └── workflows/
│       └── shellcheck.yml        # GitHub Actions CI pipeline
├── auditor/
│   ├── Dockerfile                # Container image for the auditor service
│   └── crontab                   # Cron schedule - runs audit every hour
├── grafana/
│   ├── dashboards/
│   │   └── compliance.json       # Grafana dashboard export
│   └── provisioning/
│       ├── datasources/
│       │   └── prometheus.yml    # Auto-connects Grafana to Prometheus
│       └── dashboards/
│           └── dashboards.yml    # Auto-loads dashboard JSON on startup
├── images/                       # Screenshots of different work progress
├── metrics/
│   └── compliance.prom           # Prometheus textfile metrics (runtime generated)
├── reports/                      # Audit reports (runtime generated, hourly)
├── scripts/
│   └── audit.sh                  # Main audit script (15 checks, C01-C15)
├── docker-compose.yml            # All services: auditor, prometheus, node-exporter, grafana
├── prometheus.yml                # Prometheus scrape configuration
├── CHECKLIST.md                  # Full compliance rulebook with rationale
└── memo.md                       # AWS security mapping for all 15 checks
```

---

## Compliance rules

15 rules are checked on every audit run across three scopes:

| Scope | Rules |
|---|---|
| Container | C01, C02, C04, C05, C07, C08, C09, C10, C13, C14 |
| Network | C03, C11 |
| Host | C06, C12, C15 |

See [CHECKLIST.md](./CHECKLIST.md) for the full list with severity ratings 
and rationale.

---

## Prometheus metrics

The audit script writes the following metrics to `metrics/compliance.prom` 
after every run:

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

The Docker Compliance Dashboard loads as the home page automatically.
If navigating manually, use the search icon and type "Docker Compliance".

---

## How the pipeline works

Every component connects into a single automated pipeline. Once the stack 
is running, no manual intervention is needed. Here is how data flows from 
the cron job all the way to the Grafana dashboard.

cron (every hour at :00)
-> audit.sh runs inside the auditor container
-> checks all 15 rules against running Docker containers and host
-> reports/report_<timestamp>.json written
-> reports/report_<timestamp>.txt written
-> metrics/compliance.prom updated
-> node-exporter reads compliance.prom
-> Prometheus scrapes node-exporter every 15 seconds
-> Grafana queries Prometheus every 1 minute
-> Dashboard panels update automatically

### Component responsibilities

| Component | Role | Port |
|---|---|---|
| auditor | Runs audit.sh on a cron schedule every hour | - |
| node-exporter | Reads compliance.prom and exposes metrics | 9100 |
| Prometheus | Scrapes node-exporter and stores metrics over time | 9090 |
| Grafana | Queries Prometheus and displays the compliance dashboard | 3000 |

### Cron schedule

The audit is scheduled using a crontab file inside the auditor container:

```bash
0 * * * * bash /scripts/audit.sh >> /reports/cron.log 2>&1
```
This runs the audit at the top of every hour. Output and any errors are
logged to `reports/cron.log` for debugging.

### Verifying the pipeline

**Check cron is running inside the auditor container:**
```bash
docker exec auditor ps aux | grep cron
```

**Manually trigger the audit without waiting for the hour:**
```bash
docker exec auditor bash /scripts/audit.sh
```

**Check the cron log after a scheduled run:**
```bash
cat reports/cron.log
```

**Confirm Prometheus is receiving metrics:**

Open http://localhost:9090 and search for `compliance_score_percent`.
A value should be returned immediately.

**Confirm Grafana is displaying data:**

Open http://localhost:3000. The Docker Compliance Dashboard loads as the 
home page. If navigating manually, use the search icon and type 
"Docker Compliance". All panels should show live data and time series 
panels will show trends across hourly audit runs.

### Volumes and data flow

All components share data through mounted volumes defined in 
`docker-compose.yml`:

| Volume mount | Used by | Purpose |
|---|---|---|
| `./scripts:/scripts` | auditor | Audit script source |
| `./metrics:/metrics` | auditor, node-exporter | compliance.prom shared between writer and reader |
| `./reports:/reports` | auditor | JSON and text report output |
| `./prometheus.yml:/etc/prometheus/prometheus.yml` | Prometheus | Scrape configuration |
| `./grafana/provisioning:/etc/grafana/provisioning` | Grafana | Auto-loads datasource and dashboard |
| `./grafana/dashboards:/etc/grafana/dashboards` | Grafana | Dashboard JSON |

---

## Running the audit manually

```bash
docker exec auditor bash /scripts/audit.sh
```

With custom configuration:
```bash
docker exec -e DISK_THRESHOLD=75 \
  -e TRUSTED_REGISTRIES="ghcr.io/myorg" \
  auditor bash /scripts/audit.sh
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

## CI/CD Pipeline

GitHub Actions runs automatically on every push and pull request.
The workflow lints `scripts/audit.sh` using `shellcheck` to catch syntax
errors and bad practices before they reach the main branch.

Workflow file: `.github/workflows/shellcheck.yml`

---

## AWS Security Mapping

See [memo.md](./memo.md) for the full mapping of each local compliance 
check (C01-C15) to its AWS-native equivalent, including AWS Security Hub, 
Config Rules, GuardDuty, IAM Access Analyzer, Trusted Advisor, and more.

---

## Audit outputs

Every hourly run produces three outputs:

1. **Terminal output** - colour-coded PASS/FAIL per rule, printed live
2. **JSON report** - machine-readable, saved to `reports/report_<timestamp>.json`
3. **Text report** - human-readable, saved to `reports/report_<timestamp>.txt`

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All 15 checks passed - fully compliant |
| `1` | One or more checks failed - action required |