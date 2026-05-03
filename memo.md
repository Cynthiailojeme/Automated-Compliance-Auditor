MEMORANDUM

TO: Security Team, Compliance Office, Cloud Engineering  
FROM: Person 8 — The AWS Translator  
DATE: May 2, 2026  
SUBJECT: Mapping Our Security Guard Agency Checks to AWS Cloud Services

---

## 1.0 Purpose

This memo explains how each rule in our compliance checklist — originally 
built to inspect Docker containers like a security guard agency inspecting 
a building — maps directly to equivalent AWS cloud security services. Our 
local project has eight roles working together: Rule Maker, Inspector, 
Report Writer, Live Scoreboard Builder, Dashboard Designer, Automation 
Person, Quality Control Person, and myself, the AWS Translator. My job is 
to show that every safety check we perform locally has a professional, 
production-grade counterpart in AWS. This demonstrates that our skills 
transfer directly to real-world cloud security engineering roles.

---

## 2.0 The Analogy: Our Business on AWS

Think of it this way: right now, our security guard agency inspects one 
building (a Docker host). If our client expands to own hundreds of buildings 
across the country, we cannot send inspectors to every building every hour — 
it does not scale. AWS provides a set of automated tools that act like 
permanent security guards stationed at every building, constantly watching, 
instantly reporting, and never sleeping. The table below shows exactly which 
AWS guard replaces each of our manual inspections.

---

## 3.0 Complete Rule-to-AWS Mapping Table

The following table maps each of the 15 rules defined by Person 1 (C01–C15) 
to their AWS-native equivalents.

| Check ID | Local Rule | Severity | AWS Equivalent | How AWS Does the Same Job |
|---|---|---|---|---|
| C01 | No containers running as root | HIGH | AWS Security Hub + ECS Task Definitions | ECS enforces non-root users via the `user` field in task definitions. Security Hub CIS benchmark check `ECS.2` automatically flags containers running as root. |
| C02 | All containers have health checks | MEDIUM | ECS Health Checks + Elastic Load Balancer | ECS task definitions require health check configuration. ELB target group health checks monitor service availability and automatically remove unhealthy targets from rotation. |
| C03 | No unexpected exposed ports | HIGH | AWS Security Groups + VPC Network ACLs + AWS Config Rule `vpc-sg-open-only-to-authorized-ports` | Security Groups act as virtual firewalls allowing only explicitly permitted ports. Config continuously inspects every security group and flags any port open to 0.0.0.0/0 outside the approved list. |
| C04 | Images from trusted registries only | HIGH | Amazon ECR + AWS Config Rules | Amazon ECR is AWS's managed private registry. Config Rules enforce that ECS tasks only pull from approved ECR repositories, blocking untrusted public image sources entirely. |
| C05 | No secrets in plain text env vars | CRITICAL | AWS Secrets Manager + AWS Systems Manager Parameter Store | Secrets Manager stores credentials encrypted with KMS and rotates them automatically. ECS task definitions reference Secrets Manager ARNs directly, injecting secrets at runtime — never stored as plaintext environment variables. |
| C06 | Disk usage below threshold | MEDIUM | Amazon CloudWatch Alarms + CloudWatch Agent | CloudWatch Agent collects disk usage metrics from EC2 instances and ECS. Alarms trigger SNS notifications or Auto Scaling actions when disk usage exceeds the defined threshold before it becomes critical. |
| C07 | All containers have CPU limits | MEDIUM | ECS Task Definition CPU Limits + AWS Compute Optimizer | ECS task definitions require explicit CPU unit allocation per container. AWS Fargate enforces this by design. Compute Optimizer analyses usage patterns and recommends right-sized CPU allocations to prevent resource starvation. |
| C08 | All containers have memory limits | MEDIUM | ECS Task Definition Memory Limits + AWS Compute Optimizer | ECS enforces hard and soft memory limits per container in the task definition. Containers exceeding their hard limit are stopped and replaced, isolating failures to the offending container only. |
| C09 | No privileged containers | CRITICAL | AWS Security Hub + ECS Task Definitions + GuardDuty | ECS Fargate does not support privileged mode at all. On EC2 launch type, Security Hub CIS checks flag any task definition enabling privileged mode. GuardDuty detects post-exploitation behaviour from any privileged container that slips through. |
| C10 | Read-only root filesystem | MEDIUM | ECS Task Definitions + AWS Security Hub | ECS task definitions support `readonlyRootFilesystem: true` per container. Security Hub evaluates this setting and flags containers where it is not enforced, ensuring attackers cannot persist changes across restarts. |
| C11 | No host network mode | HIGH | ECS Task Networking + VPC | ECS Fargate does not support host network mode — every task gets its own elastic network interface (ENI) by design. On EC2 launch type, Security Hub flags tasks configured with host networking. |
| C12 | Docker API not exposed on TCP 2375 | CRITICAL | AWS Security Groups + VPC + AWS Config Rules | Security Groups block port 2375 at the infrastructure level. Config Rules continuously check that no security group allows inbound traffic on port 2375 and can trigger automatic remediation if found. |
| C13 | No host PID namespace | HIGH | ECS Task Definitions + AWS Security Hub | ECS Fargate does not allow host PID namespace sharing. On EC2 launch type, the `pidMode: host` setting is detectable by Security Hub which raises a critical finding when present. |
| C14 | Images not older than 90 days | MEDIUM | Amazon ECR Image Scanning + Amazon Inspector + AWS Config Rules | ECR Enhanced Scanning uses Amazon Inspector to flag vulnerabilities in images. Config Rules check image creation dates and flag images not rebuilt within the defined window, enforcing a regular rebuild cadence. |
| C15 | Docker Content Trust enabled | MEDIUM | Amazon ECR Image Signing + AWS Signer | ECR supports image signing via AWS Signer. Signed images are verified at deployment time, ensuring only cryptographically verified images are deployed — equivalent to DOCKER_CONTENT_TRUST=1 locally. |

---

## 4.0 AWS Services Reference

| AWS Service | Checks it covers |
|---|---|
| AWS Security Hub | C01, C09, C10, C11, C13 |
| AWS Config Rules | C01, C03, C04, C07, C12, C14 |
| Amazon GuardDuty | Covers overall threat detection across all checks — unusual API calls, credential misuse, suspicious network activity |
| IAM Access Analyzer | Supports C03, C12 — identifies unintended resource exposure and access policy misconfigurations |
| AWS Trusted Advisor | Supports C03, C06, C07, C08 — flags open ports, underutilised resources, and missing resource limits |
| AWS Secrets Manager | C05 |
| Amazon ECR | C04, C14, C15 |
| ECS Task Definitions | C01, C02, C07, C08, C09, C10, C11, C13 |
| Amazon CloudWatch | C06 |
| AWS Signer | C15 |

---

## 5.0 How Each of Our 8 Roles Maps to AWS

Our agency has eight roles. AWS provides managed services for every one.

### 5.1 Person 1 — The Rule Maker → AWS Config Rules + Security Hub Standards
Local: You define 10–15 rules in a document. Everyone references that 
document manually.

AWS Equivalent: Rules become AWS Config managed rules (over 400 pre-built) 
or custom Lambda-backed rules. These are not documents on a shelf — they are 
active, executable checks. AWS Security Hub provides pre-packaged compliance 
standards (CIS AWS Foundations, PCI DSS, NIST 800-53) that correspond to 
industry frameworks. Rule making becomes rule activating.

### 5.2 Person 2 — The Inspector → AWS Config Evaluator + GuardDuty
Local: A Bash script runs docker inspect, docker ps, df -h, and checks each 
container manually on a schedule.

AWS Equivalent: AWS Config continuously runs evaluations against every 
resource in the account. There is no script to execute — Config is the 
permanent inspector. Amazon GuardDuty adds intelligent threat detection using 
machine learning, threat intelligence feeds, and anomaly detection to catch 
active attacks. Our local inspector runs hourly; AWS inspects continuously 
and on every resource configuration change.

### 5.3 Person 3 — The Report Writer → AWS Security Finding Format + Security Hub
Local: The script produces a human-readable report and a JSON file with 
PASS/FAIL per rule.

AWS Equivalent: Every AWS security service publishes findings in the AWS 
Security Finding Format (ASFF) — a standardized JSON schema. Security Hub 
ingests findings from Config, GuardDuty, Inspector, IAM Access Analyzer, 
and Macie into a single normalized report. The human-readable version is 
the Security Hub console — a dashboard showing failed controls with 
remediation instructions. Reports write themselves continuously.

### 5.4 Person 4 — The Live Scoreboard Builder → CloudWatch Metrics + Security Hub Score
Local: A script exposes Prometheus metrics: compliant_checks, failed_checks, 
last_audit_timestamp.

AWS Equivalent: Amazon CloudWatch provides the metrics layer. Security Hub 
publishes a compliance score as a native metric. For teams already using 
Prometheus, Amazon Managed Service for Prometheus ingests CloudWatch metrics 
and serves them to Grafana without a custom exporter.

### 5.5 Person 5 — The Dashboard Designer → Security Hub Console + CloudWatch Dashboards
Local: Grafana dashboard showing compliance trends over time.

AWS Equivalent: AWS Security Hub provides a built-in dashboard with overall 
security score, breakdown by standard, failed controls with severity levels, 
and historical trend charts. CloudWatch Dashboards combine security metrics 
with operational metrics for a unified operations view.

### 5.6 Person 6 — The Automation Person → AWS Config + EventBridge
Local: Cron job triggers the audit script every hour.

AWS Equivalent: There is no cron. AWS Config evaluates resources continuously 
— whenever a resource configuration changes, Config runs the relevant rules 
immediately. Amazon EventBridge replaces cron for scheduled tasks. Remediation 
actions can be fully automated: when Config detects a non-compliant resource, 
an EventBridge rule triggers an SSM Automation runbook to fix it without human 
intervention. Our hourly cron becomes real-time detection with auto-remediation.

### 5.7 Person 7 — The Quality Control Person → CodePipeline + CodeBuild
Local: GitHub Actions runs shellcheck on every push to validate the Bash 
audit script.

AWS Equivalent: AWS CodePipeline with CodeBuild can run shellcheck, cfn-lint, 
checkov, and tfsec on infrastructure-as-code templates. Quality control shifts 
from linting a Bash script to validating that CloudFormation templates and IAM 
policies are secure before deployment. GitHub Actions can also integrate with 
AWS using OIDC federation, allowing the existing CI/CD pipeline to assume AWS 
roles securely.

### 5.8 Person 8 — The AWS Translator → This Memo
Local: Produce a professional memo mapping every local compliance check to 
its AWS equivalent.

AWS Equivalent: This memo is the deliverable. It demonstrates understanding 
of what each local check does and why it matters, which AWS service performs 
the equivalent function, how the AWS implementation provides equal or superior 
protection, and how the entire operational model translates from local 
infrastructure to cloud-native.

---

## 6.0 Operational Equivalence Summary

| Local Component | AWS Equivalent | Key Difference |
|---|---|---|
| Compliance checklist (Person 1) | AWS Config Rules + Security Hub standards | Document → Active, executable rules |
| Bash inspection script (Person 2) | AWS Config + GuardDuty | Hourly cron → Real-time, trigger-based |
| PASS/FAIL report (Person 3) | ASFF + Security Hub | File-based → Streaming, aggregated findings |
| Prometheus metrics (Person 4) | CloudWatch Metrics + Security Hub score | Custom exporter → Native AWS service |
| Grafana dashboard (Person 5) | Security Hub console + CloudWatch Dashboards | Self-hosted → Managed visualization |
| Cron scheduler (Person 6) | EventBridge + AWS Config triggers | Fixed schedule → Event-driven + continuous |
| GitHub Actions + shellcheck (Person 7) | CodePipeline + CodeBuild + cfn-lint | Script linting → Infrastructure-as-code validation |
| AWS memo (Person 8) | This document | Project artifact → Professional deliverable |

---

## 7.0 Concrete Example: A Day in the Life

### Local (Current):
1. Cron triggers at 2:00 PM
2. Bash script inspects all running Docker containers against 15 rules
3. Script finds one container running as root (C01) and one with Docker 
   Content Trust disabled (C15)
4. Script writes JSON report, updates Prometheus metrics
5. Grafana shows compliance dropped from 86% to 73%
6. Someone reads the report the next morning

### AWS (Cloud Equivalent):
1. Developer deploys a new ECS task definition with `user: root` at 2:00 PM
2. AWS Config detects the non-compliant configuration instantly — not at 
   the next cron interval
3. Security Hub ingests the finding, updates the compliance score immediately
4. GuardDuty correlates the configuration weakness with any suspicious 
   activity from that container
5. CloudWatch alarm fires to the on-call Slack channel within minutes
6. An EventBridge rule triggers an SSM Automation runbook to stop the 
   non-compliant task automatically
7. The security team sees the full incident timeline in Security Hub — 
   not hours or days later

---

## 8.0 Conclusion

Every rule in our 15-check compliance checklist (C01–C15) has a direct, 
production-hardened AWS equivalent. Every role in our Security Guard Agency 
translates to existing AWS managed services that scale automatically and 
integrate natively with each other.

Our local project teaches the fundamentals — rule definition, inspection 
automation, reporting, metrics, dashboards, scheduling, and quality control. 
In AWS, these fundamentals are implemented as managed services that run 
continuously, remediate automatically, and scale across thousands of 
resources without manual intervention.

When an interviewer asks if we have cloud experience, this memo demonstrates 
that we understand not just the service names but the why — how each AWS 
service maps to a real security requirement we have already solved locally.

Our security guard agency is ready for the cloud.

---

Prepared by: Person 8 — The AWS Translator  
For: Project Team and Stakeholders