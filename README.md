<<<<<<< HEAD
# Automated-Compliance-Auditor
Capstone Project for SCA DevOps (Group 3)
=======
#!/usr/bin/env bash
# =============================================================================
# audit.sh — Docker Infrastructure Compliance Auditor
# =============================================================================
# PURPOSE:
#   This script inspects every running Docker container and the host system
#   against 15 predefined security and operational rules (C01–C15).
#   Think of it as an automated NAFDAC inspector — it visits each container,
#   asks "are you following the rules?", and returns PASS or FAIL with reasons.
#
# OUTPUTS:
#   1. Terminal output  — colour-coded PASS/FAIL per rule, printed live
#   2. JSON report      — machine-readable, stored in reports/
#   3. Text report      — human-readable, stored in reports/
#   4. Prometheus file  — metrics scraped by node-exporter for Grafana dashboard
#
# USAGE:
#   ./audit.sh
#   TRUSTED_REGISTRIES="ghcr.io/myorg" DISK_THRESHOLD=75 ./audit.sh
#
# EXIT CODES:
#   0 — all 15 checks passed (fully compliant)
#   1 — one or more checks failed (action required)
# =============================================================================
>>>>>>> 8ed42eb (docs: add project README with overview and usage guide)
