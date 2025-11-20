# Technologies Used in the AWS BGP Security Monitoring System

This document explains **what each technology is**, **why it’s used**, and **how it works inside this architecture**.  
The goal is to show architectural reasoning, security alignment, and the functional role of every component.

---

# ☁️ AWS Cloud Services

## **AWS Lambda**
**What it is:**  
A serverless compute service that executes code without provisioning servers.

**How it works here:**  
- Runs the BGP validation logic (`bgp_with_ssm.py`).  
- Fetches configuration from SSM Parameter Store at runtime.  
- Applies rule sets (RPKI validity, AS path analysis, malicious ASN detection).  
- Generates CloudWatch logs and sends security scoring metrics.  
- Acts as the central “policy enforcement engine” for BGP risk scoring.

**Why it is used:**  
- Serverless = no infrastructure to manage.  
- High resilience and scalability.  
- Near-zero cost for low transaction volumes.  
- Ideal for event-driven security logic.

---

## **AWS Systems Manager Parameter Store (SSM)**
**What it is:**  
A secure configuration store used to store parameters, secrets, and versioned settings.

**How it works here:**  
Holds all BGP-related configuration values:
- `/bgp-security/malicious-asns`  
- `/bgp-security/rpki-validator-url`  
- `/bgp-security/max-as-path-length`  
- `/bgp-security/scoring-weights`  
- `/bgp-security/threat-thresholds`

The Lambda function retrieves these settings on each execution.

**Why it is used:**  
- Centralizes routing security parameters.  
- Ensures no configuration is hard-coded.  
- Enables controlled and auditable policy updates.  
- Prevents drift and supports continuous governance.

---

## **Amazon CloudWatch (Logs, Metrics, Dashboards, Alarms)**
**What it is:**  
Monitoring and observability service for metrics, logs, alarms, and dashboards.

**How it works here:**  
- Lambda writes structured JSON logs.  
- Lambda emits custom metrics:
  - `SecurityScore`
  - `ThreatDetectionCount`
  - `ValidationCount`
  - `ValidationErrors`
- Dashboards visualize route anomalies and security posture trends.
- Alarms notify teams when BGP threats exceed thresholds.

**Why it is used:**  
- Creates visibility into external routing risk.  
- Enables continuous monitoring defined by NIST and ISO controls.  
- Produces a security “signal path” for SOC and IR teams.  
- Allows infrastructure-free monitoring without running agents.

---

## **AWS IAM (Identity and Access Management)**
**What it is:**  
AWS security system controlling access using roles, policies, trust relationships.

**How it works here:**  
- Lambda executes using a scoped IAM role.  
- Custom IAM policy restricts SSM access to `parameter/bgp-security/*` only.  
- Principle of Least Privilege enforced end-to-end.

**Why it is used:**  
- Prevents unauthorized modification of routing parameters.  
- Ensures validation logic only accesses approved resources.  
- Hardens the system against privilege escalation.

---

## **AWS EventBridge (Optional Future Integration)**
**What it is:**  
A serverless event bus for scheduling, routing, and triggering functions.

**How it works here (optional extension):**  
- Can trigger Lambda periodically to evaluate BGP feeds.  
- Enables integration with threat intel pipelines.

**Why it is used:**  
- Automates recurring validation cycles.  
- Decouples security events from compute logic.

---

## **AWS SNS (Optional Alerts)**
**What it is:**  
A notification service for email, SMS, or downstream integrations.

**How it works here:**  
- CloudWatch alarms deliver alerts via SNS topic `bgp-security-alerts`.  
- Supports on-call routing and enterprise IR processes.

**Why it is used:**  
- Ensures SOC or network teams are notified immediately.  
- Provides a bridge into enterprise monitoring systems.

---

# 🧰 Supporting Tools

## **Python (Lambda Runtime)**
**What it is:**  
Lightweight programming language widely used for automation, networking, and security.

**How it works here:**  
- Implements BGP scoring and rules.  
- Performs RPKI lookups via HTTPS.  
- Parses validation events and builds output objects.  
- Uses boto3 for all AWS SDK operations.

**Why it is used:**  
- Easy to maintain.  
- Easy to extend.  
- Popular for security automation and cloud functions.

---

## **boto3 (AWS SDK for Python)**
**What it is:**  
Python library for interacting with AWS APIs.

**How it works here:**  
Used by the Lambda function to:
- Query SSM for security policies.  
- Emit CloudWatch metrics.  
- Write structured JSON logs.  
- Support validation / decision logic.

**Why it is used:**  
- Stable, AWS-supported, and fast.  
- Required for Lambda AWS API integrations.

---

## **jq**
**What it is:**  
A command-line JSON parser and filter.

**How it works here:**  
Used when running CLI tests to:
- Pretty-print Lambda JSON output  
- Extract fields (score, threat level, validation status)  
- Validate JSON SSM parameters

**Why it is used:**  
- Essential for debugging.  
- Makes structured security data readable.

---

## **AWS CLI**
**What it is:**  
Command-line tool for interacting with AWS.

**How it works here:**  
All project deployment and testing occurs via CLI:
- IAM role creation  
- Parameter store configuration  
- Lambda creation and updates  
- CloudWatch dashboards  
- Alarms and log queries  
- Cleanup workflow

**Why it is used:**  
- Fully automatable  
- Idempotent  
- Works consistently across Linux environments  
- Perfect for reproducible security labs

---

# 🔐 Routing & Security Concepts Used

## **Border Gateway Protocol (BGP)**
**What it is:**  
The routing protocol that controls how networks on the Internet exchange prefixes and reachability information.

**How it works here:**  
The project validates:
- AS path structure  
- Prefix/origin AS correctness  
- Loop detection  
- RPKI status  
- ASN-level threat intelligence

This turns raw BGP inputs into actionable security outputs.

---

## **RPKI (Resource Public Key Infrastructure)**
**What it is:**  
Security framework for cryptographically validating which AS is authorized to announce a prefix.

**How it works here:**  
Lambda queries the validator endpoint in Parameter Store:
```
/bgp-security/rpki-validator-url
```
Returns:
- **valid**  
- **invalid**  
- **unknown**

This is weighted into the final `security_score`.

---

## **Threat Intelligence Concepts**
**What it is:**  
The use of known malicious ASNs, prefixes, or patterns.

**How it works here:**  
`/bgp-security/malicious-asns` defines a curated list of hostile/compromised AS numbers.

Lambda:
- Compares announced origin AS against the list.  
- Flags and downgrades score accordingly.

---

## **AS Path Validation**
**What it is:**  
Security inspection of the Autonomous System path used to reach a prefix.

**How it works here:**  
Lambda identifies:
- Path loops  
- Excessively long AS paths  
- Suspicious jumps across unrelated ASNs  
- Known peering anomalies

---

# 📊 Observability Technologies

## **CloudWatch Metrics**
Used to score routing risk over time:
- Average score  
- High/critical detections  
- Error rates  
- Long path detections  

## **CloudWatch Dashboards**
Used to visualize:
- Score trending  
- Threat distribution  
- Lambda performance  
- Validation logs

## **CloudWatch Logs**
Captures:
- Validation evidence  
- Input BGP event  
- Final score and threat category  
- Execution metadata

---

# 🚀 Summary

The AWS BGP Security Monitoring System integrates:
- **Serverless validation (Lambda)**  
- **Policy-driven configuration (SSM)**  
- **Full observability (CloudWatch)**  
- **Secure IAM enforcement**  
- **Routing-layer threat intelligence + RPKI validation**  

It transforms raw BGP announcements into:
- actionable security scores  
- measurable threats  
- auditable evidence  
- automated alerts  
- governance-aligned monitoring signals  

This aligns cloud security, network security, and routing integrity into a unified, automated, and compliant architecture.
