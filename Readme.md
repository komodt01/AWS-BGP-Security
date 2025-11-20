# AWS BGP Security Monitoring System

Enterprise-grade BGP route validation and threat visibility on AWS.

This project turns BGP updates from on-prem / cloud edge routers into
security scores, threat levels, and CloudWatch dashboards using AWS Lambda,
Systems Manager Parameter Store, and CloudWatch metrics/alarms.

---

## 🎯 Business Problem

BGP (Border Gateway Protocol) is critical for connectivity but fragile from
a security perspective:

- **Route hijacking** can redirect traffic to malicious destinations
- **AS path manipulation** enables interception and eavesdropping
- **Route leaks** can create outages and data exposure
- **Weak monitoring** means suspicious routes go unnoticed
- **No standardized scoring** makes it hard to compare risk across clouds

Most environments rely on basic reachability testing and manual review of
router configs. This doesn’t scale and doesn’t surface risk in a way that
security teams and leadership can act on.

---

## 💡 Solution Overview

The **AWS BGP Security Monitoring System** provides:

- A **Lambda-based BGP validator** (`bgp_with_ssm.py`) that scores each route
- **Centralized configuration** in **AWS Systems Manager Parameter Store**
  (`/bgp-security/*`)
- **Custom CloudWatch metrics** for:
  - SecurityScore
  - ValidationCount (by threat level / result)
  - ThreatDetectionCount (by threat level)
- **Alarms & dashboards** for critical and high-risk routes
- An optional **BGP collector** (`collector.py`) that normalizes BGP routes
  and sends them to Lambda via Amazon EventBridge

This gives you a repeatable, cloud-native way to watch BGP behavior and
report risk across environments (on-prem, AWS, Azure, etc.).

---

## 🧩 High-Level Architecture

![AWS BGP Security Architecture](aws-bgp-security-architecture.png)

**Flow**

1. **BGP Routers / On-Prem Edge**  
   Edge routers (e.g., ASN 64512) establish BGP sessions to cloud providers
   and upstream ISPs (Direct Connect, VPN, ExpressRoute, etc.).

2. **BGP Collector (`collector.py`)**  
   Runs on a management host or container. It:
   - Polls a BGP daemon / router API / exported route files
   - Normalizes each route into JSON:

     ```json
     {
       "prefix": "8.8.8.0/24",
       "origin_as": 15169,
       "as_path": [64512, 15169]
     }
     ```

   - Publishes these events to **Amazon EventBridge** (or directly invokes
     the Lambda function).

3. **Amazon EventBridge**  
   - Receives route events from the collector (or from a schedule)
   - Invokes the `bgp-validator` Lambda with the JSON payload

4. **AWS Lambda – `bgp-validator`**  
   - Loads configuration from **SSM Parameter Store**
   - Validates each route:
     - Malicious origin ASNs
     - AS path loops
     - Excessive path length
     - (Future) RPKI validation
   - Computes a **security score (0–100)** and **threat level**  
     (`low`, `medium`, `high`, `critical`)
   - Emits logs and **CloudWatch custom metrics**

5. **AWS Systems Manager Parameter Store**  
   Stores environment-specific policy:

   - `/bgp-security/malicious-asns`
   - `/bgp-security/max-as-path-length`
   - `/bgp-security/scoring-weights`
   - `/bgp-security/threat-thresholds`
   - `/bgp-security/rpki-validator-url` (placeholder for future integration)

6. **Amazon CloudWatch Logs & Metrics**  
   - Stores Lambda execution logs
   - Tracks `SecurityScore`, `ValidationCount`, and `ThreatDetectionCount`
   - Dashboards visualize overall routing risk
   - Alarms notify on critical/high threat detection

---

## 🏗️ Network Context (Multi-Cloud)

This validator is designed for hybrid / multi-cloud BGP topologies. Examples:

- **On-Prem → AWS Direct Connect**  
  - On-premises ASN: 64512  
  - AWS public ASN (example): 7224  
  - BGP sessions secured with MD5, prefix filters, and route policies

- **On-Prem / AWS TGW → Azure**  
  - Transit Gateway ASN (example): 64513  
  - Azure’s ASN (example): 12076 over VPN + ExpressRoute  
  - Routes from multiple clouds are normalized and scored using the same
    Lambda logic, giving a **consistent security view** across providers.

Any BGP speaker that can export its route table in text/JSON form can be
integrated by `collector.py`.

---

## ⚙️ Key Components

- **AWS Lambda** – Stateless BGP validator and scoring engine
- **AWS Systems Manager Parameter Store** – Central configuration for BGP
  security policy
- **Amazon CloudWatch Logs** – Lambda logs (per-route validation details)
- **Amazon CloudWatch Metrics & Dashboards**
  - Security scores and threat counters over time
  - Alarms on critical/high threats and low security scores
- **AWS IAM** – Least-privilege execution role for Lambda
- **Amazon EventBridge** – Optional scheduled and/or event-driven invocations
- **BGP Collector (`collector.py`)**
  - Runs outside Lambda, close to the routers
  - Translates raw BGP data into the JSON event format

---

## 🚀 Getting Started

### Prerequisites

- AWS account with permissions for:
  - IAM, Lambda, CloudWatch, Logs, SSM Parameter Store, EventBridge
- AWS CLI v2 installed and configured
- Python 3.x and `boto3` installed (for local tools)
- Bash / Linux or WSL environment

### 1. Clone and Configure

```bash
git clone <your-repo-url> aws-bgp-security
cd aws-bgp-security

# Set up environment
export AWS_REGION=us-east-1
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

cat > project-config.env << EOF
export PROJECT_NAME="bgp-security"
export AWS_REGION="us-east-1"
export ACCOUNT_ID="$ACCOUNT_ID"
export LAMBDA_FUNCTION_NAME="bgp-validator"
export IAM_ROLE_NAME="lambda-bgp-execution-role"
EOF

source project-config.env
```

Create Lambda Function Package
cd lambda
zip bgp-validator.zip bgp_with_ssm.py
cd ..

Deploy Core Infrastructure
chmod +x deploy_complete.sh
./deploy_complete.sh

Run Validation Tests
chmod +x run_tests.sh
./run_tests.sh

Set Up EventBridge (Optional but Recommended)
aws events put-rule \
  --name bgp-validator-scheduled-check \
  --schedule-expression "rate(1 minute)" \
  --state ENABLED

aws lambda add-permission \
  --function-name $LAMBDA_FUNCTION_NAME \
  --statement-id bgp-schedule-permission \
  --action "lambda:InvokeFunction" \
  --principal events.amazonaws.com \
  --source-arn arn:aws:events:$AWS_REGION:$ACCOUNT_ID:rule/bgp-validator-scheduled-check

aws events put-targets \
  --rule bgp-validator-scheduled-check \
  --targets "Id"="1","Arn"="arn:aws:lambda:$AWS_REGION:$ACCOUNT_ID:function:$LAMBDA_FUNCTION_NAME","Input"='{"prefix":"8.8.8.0/24","origin_as":15169,"as_path":[64512,15169]}'

Integrate the BGP Collector
Configure collector.py on your BGP management host (see collector.py
section below) so that actual routes from routers are validated in near
real time.
