# AWS BGP Security Monitoring System

Enterprise-grade BGP route validation, threat scoring, and security observability using AWS Lambda, EventBridge, Systems Manager Parameter Store, and CloudWatch.

---

## Executive Summary

BGP route manipulation—whether malicious or accidental—can lead to hijacks, route leaks, traffic interception, or outages that immediately impact customers, SLAs, and regulatory obligations. This project implements a cloud-native BGP validation pipeline that ingests routing updates, applies codified security policy, produces a security score, and surfaces results via metrics, logs, dashboards, and alarms. The architecture demonstrates how routing risk can be transformed into measurable, governed, and observable signals for security and operations teams.

---

## Business Problem

Enterprises depend on upstream ISPs and external routing domains to deliver traffic reliably. BGP, however, has no built-in authentication or integrity guarantees. Attacks such as hijacks, leaks, path manipulation, and loop abuse create risks including:

- Customer traffic interception or redirection  
- Downtime from incorrect or malicious route advertisements  
- Loss of trust and failure to meet availability SLAs  
- Compliance gaps in financial and regulated environments  
- Insufficient visibility into routing anomalies

Traditional manual monitoring is slow, reactive, and silent on short-lived BGP anomalies. A modern enterprise requires automated, measurable BGP security controls.

---

## Solution Overview

This project provides a serverless BGP Security Monitoring System on AWS:

1. **Collector (`collector.py`)** normalizes BGP route updates into JSON events.  
2. **Amazon EventBridge** routes those events into a validator.  
3. **AWS Lambda (`bgp_with_ssm.py`)** loads policy from Systems Manager Parameter Store and calculates:  
   - Security score (0–100)  
   - Threat level (critical/high/medium/low)  
   - Validation status (passed/suspicious/failed)  
4. Results are logged and pushed as **CloudWatch custom metrics**.  
5. Dashboards and alarms provide **continuous routing security visibility**.  
6. All policy is parameterized—no code redeploys are needed to change thresholds.

---

## Architecture Diagram

```
aws-bgp-security-architecture.png
```

Include the file in your repo root as shown above.

---

## Architecture Components

### BGP Routers / On-Prem Edge
Any router (physical, virtual, or simulated) producing BGP updates.  
Outputs raw prefix, origin AS, and AS path data.

### BGP Collector (`scripts/collector.py`)
- Converts raw routing data into JSON events.  
- Example event:
  ```json
  {
    "prefix": "203.0.113.0/24",
    "origin_as": 64496,
    "as_path": [64512, 64496, 64512]
  }
  ```
- Sends events to EventBridge or directly invokes Lambda.

### Amazon EventBridge
- Event bus for routing updates.  
- Triggers Lambda on arrival.  
- Can also schedule periodic batch validations.

### AWS Lambda (`bgp_with_ssm.py`)
Performs the route-validation workflow:
- Load SSM config  
- Parse incoming event  
- Evaluate route  
- Produce score and threat level  
- Send CloudWatch metrics  
- Log structured JSON for SOC/SRE visibility  

### AWS Systems Manager Parameter Store
Centralized, version-controlled policy:
- `/bgp-security/malicious-asns`
- `/bgp-security/rpki-validator-url`
- `/bgp-security/max-as-path-length`
- `/bgp-security/scoring-weights`
- `/bgp-security/threat-thresholds`

### Amazon CloudWatch
- Logs (JSON structured validation output)  
- Metrics (`SecurityScore`, `ThreatDetectionCount`, `ValidationCount`)  
- Dashboards (score trend, threat heatmap, Lambda performance)  
- Alarms for critical thresholds  
- Optional SNS notifications

---

## How the Validator Works

### 1. Load Configuration
Reads all **/bgp-security/** parameters and converts JSON into Python structures.

### 2. Parse Event
Normalizes event into:
- Prefix  
- Origin AS  
- AS Path  

### 3. Validation Steps
- **Malicious ASN Detection** – matches origin or path against known bad ASNs.  
- **AS Path Length Check** – flags long paths.  
- **AS Path Loop Detection** – detects repeated patterns.  
- **RPKI Validation** (stub; extendable).  

### 4. Scoring Algorithm
Score begins at 100 and subtracts penalties based on configurable weights:
- as_path  
- rpki  
- prefix  
- geography (placeholder for extension)

### 5. Threat Classification
Using `/bgp-security/threat-thresholds`:

| Level | Score Range |
|-------|-------------|
| Critical | < 50 |
| High | 50–74 |
| Medium | 75–89 |
| Low | 90–100 |

### 6. Output Example
```json
{
  "prefix": "8.8.8.0/24",
  "origin_as": 666,
  "as_path": [64512, 666],
  "validation_status": "failed",
  "security_score": 15,
  "threat_level": "critical",
  "reasons": ["Origin ASN 666 is malicious"],
  "timestamp_utc": "2025-01-01T12:34:56Z"
}
```

### 7. CloudWatch Metrics
Lambda submits:
- `SecurityScore`  
- `ThreatDetectionCount` (dimensioned by threat level)  
- `ValidationCount`  
- `ValidationErrors`  

---

## Repository Structure

```
aws-bgp-security/
├─ README.md
├─ LinuxCommands.md
├─ Technologies.md
├─ compliance_mapping.md
├─ aws-bgp-security-architecture.png
├─ project-config.env
├─ lambda/
│  └─ bgp_with_ssm.py
├─ scripts/
│  ├─ collector.py
│  ├─ run_tests.sh
│  ├─ bulk_test.sh
│  ├─ performance_test.sh
│  └─ cleanup.sh
├─ tests/
│  ├─ test_valid_route.json
│  ├─ test_malicious_route.json
│  ├─ test_loop_route.json
│  └─ test_long_path.json
└─ docs/
   └─ dashboard-config.json
```

---

## Quick Deployment Summary  
(Complete commands are in **LinuxCommands.md**.)

### 1. Configure AWS & Install Tools
```
aws configure
aws sts get-caller-identity
sudo apt install python3 python3-pip jq -y
```

### 2. Environment Setup
```
mkdir -p aws-bgp-security/{scripts,lambda,tests,docs}
export PROJECT_NAME="bgp-security"
export AWS_REGION="us-east-1"
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
source project-config.env
```

### 3. Create SSM Parameters
Use commands from LinuxCommands.md to populate `/bgp-security/*`.

### 4. Create IAM Execution Role
Includes:
- AWSLambdaBasicExecutionRole  
- AmazonSSMReadOnlyAccess  
- CloudWatchAgentServerPolicy  
- Custom BGP-Security policy  

### 5. Deploy Lambda
```
cd lambda
zip bgp-validator.zip bgp_with_ssm.py
aws lambda create-function ...
```

Or use:
```
./deploy_complete.sh
```

### 6. Run Tests
```
./run_tests.sh
```

---

## Monitoring

### Logs
```
aws logs tail "/aws/lambda/bgp-validator" --follow
```

### Metrics
```
aws cloudwatch list-metrics --namespace "BGP/Security"
```

### Dashboard
```
aws cloudwatch put-dashboard \
  --dashboard-name "BGP-Security-Monitoring" \
  --dashboard-body file://docs/dashboard-config.json
```

### Alarms  
(critical threat example)
```
aws cloudwatch put-metric-alarm ...
```

---

## Backup & Restore

### Backup
```
aws ssm get-parameters-by-path ...
aws lambda get-function ...
aws iam get-role ...
```

### Restore  
```
aws ssm put-parameter ...
aws lambda create-function ...
```

### Cleanup  
```
./cleanup.sh
```

---

## Why This Project Matters (Business Value)

This project demonstrates the ability to:

- Translate routing risk into **measurable, monitorable signals**  
- Build event-driven serverless security pipelines  
- Use SSM for **policy-as-configuration**  
- Apply modern observability and automation patterns  
- Align design to frameworks including **NIST 800-53** and **ISO 27001**  
- Deliver architecture that supports SOC/SRE/Network teams with real metrics, dashboards, and alerts  

It shows both **security engineering depth** and **architectural maturity**—ideal for Cloud Security Architect, Network Security Architect, and Governance roles.

---
