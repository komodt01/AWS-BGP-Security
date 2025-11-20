# Compliance Mapping for AWS BGP Security Monitoring System

This document maps the AWS BGP Security Monitoring System to security, monitoring, and governance controls from **NIST 800-53 Rev. 5**, **ISO/IEC 27001:2022**, and routing-specific security best practices. The goal is to show how this architecture provides measurable, monitorable, and governable security outcomes aligned with industry frameworks.

---

## NIST 800-53 Rev. 5 Mapping

### **SC-7 — Boundary Protection**
**How this project supports it:**
- BGP route validation acts as a security control at the network boundary.  
- Malicious ASNs, hijacks, and leaks are detected by Lambda and scored.  
- EventBridge + Lambda create an automated inspection point for inbound route data.

### **SC-7(12) — Monitoring and Detection**
- CloudWatch metrics and dashboards provide continuous monitoring of routing anomalies.
- Threat levels (critical/high/medium/low) are observable and alarmable.

### **SI-4 — System Monitoring**
- Lambda logs JSON-structured validation results into CloudWatch Logs.  
- Custom metrics (`SecurityScore`, `ThreatDetectionCount`, `ValidationErrors`) form a monitoring baseline.  
- CloudWatch dashboards display trends over time.

### **SI-4(2) — Automated Analysis**
- Lambda automatically analyzes BGP announcements and applies security scoring.  
- No human intervention is required for anomaly detection.

### **SI-4(5) — Response to Anomalies**
- CloudWatch alarms detect critical threat levels and trigger automated notifications or operational workflows via SNS.

### **RA-5 — Vulnerability Monitoring**
- BGP misconfigurations, malicious AS paths, and RPKI-related discrepancies are treated as vulnerabilities.  
- The system identifies and classifies these as part of a proactive risk posture.

### **AU-6 — Audit Review, Analysis, and Reporting**
- Validation logs include timestamps, AS paths, threat decisions, and scoring evidence.  
- Logs are readable by audit and compliance teams.

### **AU-12 — Audit Generation**
- Lambda function produces detailed audit logs for each BGP event.  
- Includes full input, scoring outcome, and rule matches.

### **CM-6 — Configuration Settings**
- Systems Manager Parameter Store provides centralized, versioned configuration.  
- Security policy changes (malicious ASNs, thresholds, scoring weights) are controlled, logged, and auditable.

### **CA-7 — Continuous Monitoring**
- CloudWatch dashboards and recurring EventBridge triggers enable continuous posture evaluation.  
- Alarms notify SOC/SRE teams of emerging routing threats.

### **IR-5 — Incident Monitoring**
- Critical/higher-level threat alerts create incident detection points.  
- System can be integrated with enterprise IR workflows through SNS.

---

## ISO/IEC 27001:2022 Mapping

### **A.5.7 — Threat Intelligence**
- The malicious ASN list, RPKI validation, and policy rules form routing-specific threat intelligence feeds.

### **A.8.16 — Monitoring Activities**
- BGP events, validation logs, and CloudWatch dashboards offer real-time monitoring.  
- Detects abnormal behavior in external routing paths.

### **A.8.28 — Secure Coding / Validation of Inputs**
- Lambda validates and sanitizes input route data before scoring.  
- Rejects malformed or suspicious events.

### **A.12.1 — Operational Logging**
- Every BGP validation produces CloudWatch structured logs.  
- Supports auditability, investigations, and compliance reporting.

### **A.12.4 — Event Monitoring**
- CloudWatch alarms and dashboards track deviations and threats.  
- Includes threat counts, error rates, and performance indicators.

### **A.13.1 — Network Security**
- Evaluates BGP origin AS, path integrity, and manipulation indicators.  
- Provides routing-layer protection aligned to enterprise communication security needs.

### **A.16.1 — Incident Management**
- Critical threats trigger alarms → notifications → analyst response.  
- System integrates with standard enterprise incident workflows via SNS.

### **A.17.2 — Redundancy and Availability**
- Serverless design using Lambda/EventBridge/CloudWatch provides high operational resilience.  
- No infrastructure to maintain; minimal operational overhead.

---

## BGP Security Best Practice Mapping

### **MANRS (Mutually Agreed Norms for Routing Security)**
- **Filtering**: Malicious ASN list provides basic inbound validation.  
- **Global Validation**: Supports RPKI validity checks.  
- **Coordination**: Consistent JSON logs aid in collaborative troubleshooting.  
- **Monitoring**: CloudWatch dashboards validate routing health continuously.

### **RPKI-Based Route Origin Validation**
- Integrates RPKI lookup logic via `/bgp-security/rpki-validator-url`.  
- Classifies routes as valid/invalid/unknown.

### **RFC 6811 — BGP Prefix Origin Validation**
- System can verify origin matches expected AS for a given prefix.  
- Provides scoring penalties for inconsistent or invalid origins.

### **RFC 7454 — BGP Operations and Security Recommendations**
- Checks for:  
  - AS path loops  
  - Unusually long paths  
  - Suspicious origins  
  - Irregular patterns

### **BGP Anomaly Detection Practices**
- CloudWatch alarms detect:  
  - Sudden spikes in critical threats  
  - Excessively long AS paths  
  - Frequent validation errors  
  - Path manipulation patterns

---

## Covered Risk Domains

### **Routing Manipulation**
- Detects prefix hijacks, leaks, and malicious origin ASNs.

### **Path Integrity**
- Identifies long or looping AS paths indicative of tampering.

### **Misconfiguration Exposure**
- Detects malformed events and path aberrations.

### **Policy Drift**
- Configuration stored in SSM Parameter Store prevents hard-coded rules.  
- Updates require explicit change management.

### **Visibility & Observability**
- Metrics, dashboards, and logs establish a complete monitoring baseline.

### **Incident Response**
- Alarms integrate routing risk into enterprise IR pipelines.

---

## Summary

This BGP Security Monitoring System demonstrates compliance alignment with major frameworks by enabling:

- **Continuous monitoring**  
- **Structured audit logs**  
- **Policy-driven validation**  
- **Rapid anomaly detection**  
- **Measurable security scoring**  
- **Automated alerting**  
- **Clear governance pathways**

It shows how routing-layer risks—traditionally outside cloud visibility—can be translated into governed, audited, and monitored security signals that satisfy enterprise, regulatory, and architectural requirements.
