# Technologies – AWS BGP Security Monitoring System

This project is intentionally small but uses several core AWS building
blocks that mirror real enterprise designs. This document explains **what
each technology is** and **how it is used** in this project.

---

## AWS Lambda

**What it is**

AWS Lambda is a serverless compute service that runs code in response to
events. You pay only for the compute time consumed; there are no servers to
provision or manage.

**How it works here**

- The function `bgp_with_ssm.py` implements `lambda_handler`.
- Each invocation receives a single BGP route event (prefix, origin ASN,
  AS path).
- The function:
  - Loads policy from Systems Manager Parameter Store
  - Validates the route (malicious ASN, loops, path length, etc.)
  - Computes a security score and threat level
  - Writes logs to CloudWatch Logs
  - Publishes custom metrics to CloudWatch
- Lambda’s ephemeral nature makes it ideal for bursty BGP updates and
  event-driven monitoring.

---

## AWS Systems Manager Parameter Store

**What it is**

Systems Manager Parameter Store is a managed service for storing
configuration and secrets as key-value parameters. It supports plain text
and encrypted values, with versioning and access control.

**How it works here**

- Stores BGP security policy under the path `/bgp-security/*`, including:
  - `malicious-asns` – list of known bad origin ASNs
  - `max-as-path-length` – threshold for unusually long AS paths
  - `scoring-weights` – JSON document controlling how different factors
    influence the security score
  - `threat-thresholds` – JSON thresholds mapping score ranges to threat
    levels (low/medium/high/critical)
- Lambda reads these parameters at runtime using the `boto3` SSM client.
- This allows security teams to adjust policy **without redeploying code**.

---

## Amazon CloudWatch Logs

**What it is**

CloudWatch Logs is a logging service for AWS resources and applications.
Each Lambda function automatically writes logs to its own log group.

**How it works here**

- The validator logs a detailed result for each route:
  - Prefix, origin ASN, path, score, threat level, and flags
- Sample log message:  
  `"BGP validation completed: { ... }"`
- You can:
  - Search for specific prefixes or ASNs
  - Filter on error messages or specific threat levels
  - Tail logs in real time during testing

---

## Amazon CloudWatch Metrics, Dashboards, and Alarms

**What it is**

CloudWatch Metrics store numerical time-series data about AWS resources and
custom application behaviour. Dashboards visualize those metrics; alarms
evaluate them against thresholds and trigger actions.

**How it works here**

- The validator publishes custom metrics under the namespace
  **`BGP/Security`**:
  - `SecurityScore`
  - `ValidationCount` (dimensions: `ThreatLevel`, `Result`)
  - `ThreatDetectionCount` (dimension: `ThreatLevel`)
- Dashboards show:
  - Current average security score
  - Threat distribution by severity
  - Lambda performance (duration, invocations, errors)
- Alarms fire when:
  - Any `critical` threats are detected
  - The average security score drops below a threshold
- These alarms can be wired to **SNS topics**, email, chat, or ticketing
  systems to kick off incident response.

---

## AWS Identity and Access Management (IAM)

**What it is**

IAM manages identities, roles, and permissions in AWS. Policies define what
actions principals can perform on which resources.

**How it works here**

- A dedicated execution role (e.g., `lambda-bgp-execution-role`) is created
  with:
  - Trust policy allowing Lambda to assume the role
  - AWS managed policy `AWSLambdaBasicExecutionRole` (logs)
  - AWS managed policy `AmazonSSMReadOnlyAccess` (SSM read)
  - A custom policy `BGP-Security-Custom-Policy` granting:
    - `ssm:GetParameter*` on `/bgp-security/*`
    - `cloudwatch:PutMetricData` for custom metrics
- This follows **least privilege**: Lambda can only read the parameters and
  write metrics/logs required for route validation.

---

## Amazon EventBridge

**What it is**

EventBridge is a serverless event bus for routing events between AWS
services, SaaS providers, and custom applications.

**How it works here**

- EventBridge can:
  - Invoke the validator on a **schedule** (e.g., synthetic health checks)
  - Receive BGP update events from `collector.py` and forward them to
    Lambda
- Rules control:
  - Which events target the `bgp-validator` function
  - When scheduled checks run
- This gives you flexible options:
  - Scheduled validation of known prefixes
  - Event-driven validation as routes change

---

## AWS Simple Notification Service (SNS) *(optional extension)*

**What it is**

SNS is a fully managed pub/sub messaging service. It can send notifications
via email, SMS, HTTP, or other endpoints.

**How it works here**

- Not strictly required, but the project includes examples of:
  - Creating an SNS topic (e.g., `bgp-security-alerts`)
  - Wiring CloudWatch alarms to the topic
- This lets security or network teams receive near-real-time alerts when
  critical or high threats are detected.

---

## AWS Command Line Interface (AWS CLI)

**What it is**

The AWS CLI is a unified tool to manage AWS services from the command line.

**How it works here**

- All provisioning, deployment, testing, and cleanup steps are driven by
  AWS CLI commands captured in `LinuxCommands.md`:
  - Creating SSM parameters
  - Creating IAM roles and policies
  - Deploying/updating the Lambda function
  - Invoking tests
  - Managing CloudWatch dashboards, metrics, and alarms
  - Cleanup and verification
- This keeps the project repeatable and transparent for reviewers, and can
  be migrated to Terraform/CloudFormation later.

---

## Python 3 and `boto3`

**What they are**

- **Python 3** – General-purpose programming language used for the Lambda
  function and local utilities.
- **boto3** – AWS SDK for Python, providing Pythonic interfaces to AWS
  services.

**How they work here**

- `bgp_with_ssm.py` uses `boto3` clients for:
  - `ssm` (Parameter Store)
  - `cloudwatch` (metrics)
- `collector.py` uses `boto3` for:
  - `events` (EventBridge PutEvents)
  - `lambda` (direct Lambda invoke)
- Using `boto3` keeps the code portable: the same logic can run in Lambda
  or on a management host (for the collector) with minimal changes.

---

## BGP Routers and External Environment

**What they are**

BGP routers (on-premises or cloud edge routers) exchange route information
with peers (ISPs, cloud providers, partners) using the Border Gateway
Protocol.

**How they work here**

- Routers remain the **enforcement point** for route policy:
  - Prefix-lists
  - AS path filters
  - MD5 authentication
  - RPKI origin validation (if available)
- This project does **not** change router configuration. Instead, it:
  - Observes advertised routes (via collector)
  - Scores their security characteristics
  - Surfaces risk to security and network teams through dashboards and
    alarms
- This aligns with the role of a **cloud-native monitoring and governance
  layer** for BGP behaviour, rather than a replacement for routing policy.

---

By combining these technologies, the project demonstrates how a Cloud
Security Architect can turn low-level routing information into actionable,
business-relevant security insights using AWS-native services.
