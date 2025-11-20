
---

## 2. `compliance_mapping.md`

```markdown
# Compliance Mapping – AWS BGP Security Monitoring System

This document maps the AWS BGP Security Monitoring System to selected
controls from **NIST SP 800-53 Rev. 5** and **ISO/IEC 27001:2022**.

The goal is not full coverage, but to show how this project supports
network security, monitoring, and incident response requirements.

---

## 1. NIST SP 800-53 Rev. 5

| Control ID | Name | How This Project Supports It |
|-----------|------|------------------------------|
| **AC-4** | Information Flow Enforcement | BGP route validation helps ensure traffic only flows over authorized paths. Malicious origin ASNs, abnormal path lengths, and loops are detected and surfaced as high/critical threats. This supports enforcing policy on acceptable routing behavior. |
| **CA-7** | Continuous Monitoring | Lambda and EventBridge provide continuous evaluation of BGP routes. CloudWatch metrics, dashboards, and alarms offer ongoing visibility into routing security posture. |
| **IR-4** | Incident Handling | ThreatDetectionCount metrics and alarms for critical/high threats help initiate incident response playbooks when suspicious routes are observed (e.g., potential hijacks or leaks). |
| **RA-5** | Vulnerability Monitoring & Scanning | While not a vulnerability scanner, this project functions as a specialized “control” for BGP vulnerabilities by systematically checking route attributes against policy (malicious ASNs, path length, loops). |
| **SC-5** | Denial of Service Protection | Detecting abnormal AS paths and possible route leaks can reduce exposure to routing-based DoS scenarios by enabling faster response and remediation. |
| **SC-7** | Boundary Protection | The system monitors routes across network boundaries (on-prem, AWS, other clouds), ensuring that boundary routing conforms to policy and surfaces deviations. |
| **SI-4** | System Monitoring | Collects and analyzes security-relevant events (BGP routes) via CloudWatch logs/metrics, with automated alerting on suspicious patterns. |

---

## 2. ISO/IEC 27001:2022 / Annex A

| Clause / Control | Name | How This Project Supports It |
|------------------|------|------------------------------|
| **A.5.23** | Information security for use of cloud services | Centralizing BGP security monitoring in AWS (Lambda, SSM, CloudWatch) helps govern how cloud connectivity is monitored and controlled, supporting defined security requirements for cloud usage. |
| **A.8.16** | Monitoring activities | CloudWatch logs and metrics provide monitoring of BGP validation events, including status, scores, and threat levels. Dashboards and alarms ensure anomalous activity is detected and investigated. |
| **A.8.20** | Network controls | The project strengthens network controls by validating BGP routes at cloud/on-prem boundaries and providing visibility into route integrity and path behavior. |
| **A.8.24** | Protection of information systems during audit testing | BGP route validation and observability reduce the need to perform intrusive testing on production routers; risk-informed monitoring can be used as evidence in audits without destabilizing routing. |
| **A.8.28** | Secure network services | By enforcing routing policies and scoring route security, this system enhances the security of network services such as Direct Connect, VPN, and ExpressRoute links. |
| **A.8.29** | Security of network services outsourcing | When connectivity to cloud providers or carriers is outsourced, this project gives independent visibility into route behavior, supporting oversight of those third-party network services. |

---

## 3. Notes & Assumptions

- This project focuses on **monitoring and detection**. Actual enforcement
  of route policy still occurs on routers / firewalls (e.g., prefix-lists,
  route-maps, MD5 auth).
- RPKI validation is currently modeled as a placeholder; integrating a real
  RPKI validator would further strengthen compliance alignment for route
  origin validation.
- Controls listed here are **partially supported**. Full compliance
  requires additional process, documentation, and complementary controls.
