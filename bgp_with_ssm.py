import json
import boto3
import logging
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def load_configuration(ssm):
    """
    Load all BGP security configuration from SSM Parameter Store.
    """
    param_names = [
        "/bgp-security/malicious-asns",
        "/bgp-security/rpki-validator-url",
        "/bgp-security/max-as-path-length",
        "/bgp-security/scoring-weights",
        "/bgp-security/threat-thresholds",
    ]

    resp = ssm.get_parameters(Names=param_names, WithDecryption=True)
    values = {p["Name"]: p["Value"] for p in resp["Parameters"]}

    # Parse values
    malicious_raw = values["/bgp-security/malicious-asns"]
    malicious_asns = {int(x.strip()) for x in malicious_raw.split(",") if x.strip()}

    config = {
        "malicious_asns": malicious_asns,
        "rpki_validator_url": values["/bgp-security/rpki-validator-url"],
        "max_as_path_length": int(values["/bgp-security/max-as-path-length"]),
        "scoring_weights": json.loads(values["/bgp-security/scoring-weights"]),
        "threat_thresholds": json.loads(values["/bgp-security/threat-thresholds"]),
    }
    return config


def parse_event(event):
    """
    Normalize event input into a route data structure.
    Supports manual invokes, API Gateway, and EventBridge.
    """
    if isinstance(event, str):
        event = json.loads(event)

    # Direct invoke case
    if isinstance(event, dict) and "prefix" in event:
        return event

    # API Gateway or EventBridge
    if isinstance(event, dict) and "body" in event:
        body = event["body"]
        if isinstance(body, str):
            body = json.loads(body)
        return body

    raise ValueError(f"Unsupported event shape: {event}")


def _detect_loop(as_path):
    seen = set()
    for asn in as_path:
        if asn in seen:
            return True
        seen.add(asn)
    return False


def validate_bgp_route(route_data, config):
    """
    Main validation logic:
      - Detect malicious ASNs
      - Detect AS path loops
      - Detect abnormal AS path length
      - Score route and classify threat levels
    """
    prefix = route_data.get("prefix")
    origin_as = int(route_data.get("origin_as"))
    as_path = [int(a) for a in route_data.get("as_path", [])]

    flags = {
        "is_malicious_asn": origin_as in config["malicious_asns"],
        "has_loop": _detect_loop(as_path),
        "path_too_long": len(as_path) > config["max_as_path_length"],
        "rpki_validated": False,  # Placeholder for real RPKI integration
    }

    # Start score at 100
    score = 100.0
    weights = config["scoring_weights"]

    if flags["is_malicious_asn"]:
        score -= 60 * weights.get("as_path", 0.4)
    if flags["has_loop"]:
        score -= 40 * weights.get("as_path", 0.4)
    if flags["path_too_long"]:
        score -= 20 * weights.get("as_path", 0.4)
    if not flags["rpki_validated"]:
        score -= 20 * weights.get("rpki", 0.4)

    score = max(0.0, min(100.0, score))

    thresholds = config["threat_thresholds"]

    if score <= thresholds["critical"]:
        threat = "critical"
    elif score <= thresholds["high"]:
        threat = "high"
    elif score <= thresholds["medium"]:
        threat = "medium"
    else:
        threat = "low"

    validation_status = (
        "failed" if threat in ("high", "critical") or flags["is_malicious_asn"] or flags["has_loop"]
        else "passed"
    )

    result = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "prefix": prefix,
        "origin_as": origin_as,
        "as_path": as_path,
        "security_score": round(score, 2),
        "threat_level": threat,
        "validation_status": validation_status,
        "flags": flags,
    }

    logger.info(f"BGP validation completed: {json.dumps(result)}")
    return result


def send_metrics(cloudwatch, result):
    """
    Push metrics to CloudWatch:
      - SecurityScore
      - ValidationCount (dimensions: ThreatLevel, Result)
      - ThreatDetectionCount
    """
    threat = result["threat_level"]
    score = result["security_score"]
    status = result["validation_status"]

    metric_data = [
        {
            "MetricName": "SecurityScore",
            "Dimensions": [],
            "Value": score,
            "Unit": "None",
        },
        {
            "MetricName": "ValidationCount",
            "Dimensions": [
                {"Name": "ThreatLevel", "Value": threat},
                {"Name": "Result", "Value": status},
            ],
            "Value": 1,
            "Unit": "Count",
        },
    ]

    if threat != "low":
        metric_data.append(
            {
                "MetricName": "ThreatDetectionCount",
                "Dimensions": [
                    {"Name": "ThreatLevel", "Value": threat},
                ],
                "Value": 1,
                "Unit": "Count",
            }
        )

    cloudwatch.put_metric_data(
        Namespace="BGP/Security",
        MetricData=metric_data,
    )


def lambda_handler(event, context):
    try:
        ssm = boto3.client("ssm")
        cloudwatch = boto3.client("cloudwatch")

        config = load_configuration(ssm)
        route_data = parse_event(event)
        result = validate_bgp_route(route_data, config)
        send_metrics(cloudwatch, result)

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(result),
        }

    except Exception as e:
        logger.exception("Lambda error")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)}),
        }
