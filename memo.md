# Mapping Local Compliance Checks to AWS Security Services

Our project implements a container security auditing system using Docker. It checks whether containers follow best practices such as not running as root, having health checks, and limiting exposed ports.

This memo outlines how locally implemented compliance checks within our container security audit system can be mapped to AWS-native security services. The goal is to demonstrate how a locally developed solution can transition into a scalable, real-world cloud environment while maintaining security, automation, and compliance standards.

---

## Mapping of Compliance Checks to AWS Services

### 1. Secrets Handling → AWS Secrets Manager

**Requirement:**  
Sensitive information such as API keys, passwords, and database credentials must not be stored in plaintext or hardcoded within applications.

**AWS Implementation:**  
AWS Secrets Manager securely stores and manages secrets, with built-in encryption using AWS Key Management Service (KMS). It supports automatic rotation of credentials and allows applications to retrieve secrets dynamically via API calls. This eliminates exposure risks associated with plaintext storage and aligns with secure credential management practices.

---

### 2. Configuration Checks → AWS Config Rules

**Requirement:**  
System configurations must comply with defined policies, such as enforcing encryption, restricting public access, and maintaining approved resource settings.

**AWS Implementation:**  
AWS Config continuously monitors and evaluates resource configurations against predefined or custom rules. For example, it can detect publicly accessible storage or unencrypted resources. Non-compliant resources can trigger alerts or automated remediation workflows, replacing manual or periodic checks with continuous compliance monitoring.

---

### 3. Threat Detection → Amazon GuardDuty

**Requirement:**  
The system must detect unusual or malicious behavior, including unauthorized access attempts or suspicious network activity.

**AWS Implementation:**  
Amazon GuardDuty provides intelligent threat detection by analyzing logs such as AWS CloudTrail, VPC Flow Logs, and DNS logs. Using machine learning and threat intelligence, it identifies anomalies such as credential compromise, unusual API activity, or communication with known malicious endpoints. This enhances local monitoring capabilities with cloud-native, automated detection.

---

### 4. Access Analysis → IAM Access Analyzer

**Requirement:**  
Access to resources must follow the principle of least privilege, ensuring no unintended or excessive permissions are granted.

**AWS Implementation:**  
IAM Access Analyzer evaluates resource policies and identifies unintended public or cross-account access. It helps validate IAM roles and permissions before deployment and continuously monitors for risky configurations. This replaces manual access reviews with automated and real-time analysis.

---

### 5. Best Practices & Security Posture → AWS Trusted Advisor / Security Hub

**Requirement:**  
The system should adhere to security best practices and maintain an overall compliant posture aligned with industry standards.

**AWS Implementation:**
- **AWS Trusted Advisor** provides recommendations on security, performance, and cost optimization, including checks for open security groups and unused credentials.  
- **AWS Security Hub** aggregates findings from multiple AWS services and presents a centralized view of security posture. It also evaluates compliance against standards such as CIS benchmarks and PCI DSS.

---

## Architecture Summary

In AWS, this system would be deployed using ECS or EKS for container orchestration. Security would be enforced through IAM roles, Secrets Manager, and Security Groups. Monitoring and reporting would be handled by CloudWatch and Managed Grafana, while automation would be achieved using EventBridge and Lambda.

---

## Conclusion

Mapping local compliance checks to AWS security services demonstrates how a container-based audit system can evolve into a cloud-native solution. By leveraging AWS tools, organizations benefit from:

- Continuous monitoring and compliance  
- Automated detection and remediation  
- Centralized visibility across resources  
- Scalable and production-ready security practices  

This project demonstrates how local DevOps practices can scale into a cloud-based production environment. By mapping our security checks to AWS services, we show understanding of cloud architecture, automation, and security best practices.