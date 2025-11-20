import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)


# ================
# Lambda Entrypoint
# ================

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    BGP Security Validator Lambda

    Workflow:
      1. Load configuration from SSM Parameter Store (/bgp-security/*)
      2. Parse BGP route event (prefix, origin_as, as_path)
      3. Run validation + scoring
      4. Emit CloudWatch metrics
      5. Return structured JSON result
    """
    logger.info("Received event: %s", json.dumps(event))

    try:
        ssm = boto3.client("ssm")
        cloudwatch = boto3.client("cloudwatch")
    except (BotoCoreError, ClientError) as e:
        logger.error("Failed to create AWS clients: %s", str(e))
        return _error_response(f"Failed to create AWS clients: {str(e)}")

    try:
        config = load_configuration(ssm)
        route_data = parse_event(event)
        result = validate_bgp_route(route_data, config)
        send_metrics(cloudwatch, result)

        # Log final result for CloudWatch Logs queries
        logger.info("BGP validation completed: %s", json.dumps(result))

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(result, indent=2),
        }

    except ValueError as e:
        logger.error("Validation error: %s", str(e))
        return _error_response(str(e), status_code=400)
    except Exception as e:  # noqa: BLE001
        logger.error("Lambda error: %s", str(e))
        return _error_response(f"Internal error: {str(e)}", status_code=500)


def _error_response(message: str, status_code: int = 500) -> Dict[str, Any]:
    """Helper to build an error response."""
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"error": message}),
    }


# ======================
# Configuration Handling
# ======================

def load_configuration(ssm_client) -> Dict[str, Any]:
    """
    Load BGP security configuration from SSM Parameter Store under /bgp-security/.

    Expected parameters:
      - /bgp-security/malicious-asns          (StringList)
      - /bgp-security/rpki-validator-url      (String)
      - /bgp-security/max-as-path-length      (String -> int)
      - /bgp-security/scoring-weights         (String JSON)
      - /bgp-security/threat-thresholds       (String JSON)
    """
    prefix = "/bgp-security/"
    params: Dict[str, Any] = {}
    next_token = None

    try:
        while True:
            kwargs = {
                "Path": prefix,
                "Recursive": True,
                "WithDecryption": True,
            }
            if next_token:
                kwargs["NextToken"] = next_token

            resp = ssm_client.get_parameters_by_path(**kwargs)
            for p in resp.get("Parameters", []):
                name = p["Name"].replace(prefix, "")
                params[name] = p["Value"]

            next_token = resp.get("NextToken")
            if not next_token:
                break
    except (BotoCoreError, ClientError) as e:
        logger.error("Error loading configuration from SSM: %s", str(e))
        raise

    # Parse parameters with defaults
    malicious_asns_raw = params.get("malicious-asns", "")
    malicious_asns = _parse_malicious_asns(malicious_asns_raw)

    rpki_url = params.get("rpki-validator-url", "").strip()

    try:
        max_path_length = int(params.get("max-as-path-length", "20"))
    except ValueError:
        logger.warning("Invalid max-as-path-length; defaulting to 20")
        max_path_length = 20

    scoring_weights = _parse_json_param(
        params.get("scoring-weights"),
        default={"as_path": 0.4, "rpki": 0.4, "prefix": 0.15, "geography": 0.05},
        param_name="scoring-weights",
    )

    threat_thresholds = _parse_json_param(
        params.get("threat-thresholds"),
        default={"low": 90, "medium": 75, "high": 50, "critical": 0},
        param_name="threat-thresholds",
    )

    config = {
        "malicious_asns": malicious_asns,
        "rpki_validator_url": rpki_url,
        "max_as_path_length": max_path_length,
        "scoring_weights": scoring_weights,
        "threat_thresholds": threat_thresholds,
    }

    logger.info("Loaded configuration: %s", json.dumps({
        "malicious_asns_count": len(malicious_asns),
        "has_rpki_url": bool(rpki_url),
        "max_as_path_length": max_path_length,
        "scoring_weights": scoring_weights,
        "threat_thresholds": threat_thresholds,
    }))

    return config


def _parse_malicious_asns(value: str) -> List[int]:
    """Convert a StringList of ASNs to a list of ints."""
    if not value:
        return []

    items = [v.strip() for v in value.split(",") if v.strip()]
    result = []
    for item in items:
        try:
            result.append(int(item))
        except ValueError:
            logger.warning("Skipping invalid malicious ASN entry: %s", item)
    return result


def _parse_json_param(raw: str, default: Any, param_name: str) -> Any:
    """Parse a JSON string parameter with a safe default."""
    if not raw:
        logger.warning("Missing %s; using default.", param_name)
        return default
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Invalid JSON in %s; using default.", param_name)
        return default


# =============
# Event Parsing
# =============

def parse_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize the incoming event to a BGP route data structure:
      {
        "prefix": "203.0.113.0/24",
        "origin_as": 64496,
        "as_path": [64512, 64496]
      }

    Supports:
      - Direct CLI invocation with JSON payload
      - Events wrapped in 'body'
      - EventBridge-style: event['detail']
    """
    payload: Any = event

    # API Gateway / Lambda proxy style
    if isinstance(event, dict) and "body" in event:
        try:
            body = event["body"]
            payload = json.loads(body) if isinstance(body, str) else body
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON in event body.")

    # EventBridge style
    if isinstance(payload, dict) and "detail" in payload:
        payload = payload["detail"]

    if not isinstance(payload, dict):
        raise ValueError("Unsupported event format; expected JSON object.")

    prefix = payload.get("prefix")
    origin_as = payload.get("origin_as")
    as_path = payload.get("as_path")

    if prefix is None:
        raise ValueError("Missing required field 'prefix'.")
    if origin_as is None:
        raise ValueError("Missing required field 'origin_as'.")
    if as_path is None:
        raise ValueError("Missing required field 'as_path'.")

    try:
        origin_as_int = int(origin_as)
    except (TypeError, ValueError):
        raise ValueError("Field 'origin_as' must be an integer.")

    if not isinstance(as_path, list):
        raise ValueError("Field 'as_path' must be a list of ASNs.")

    normalized_path = []
    for hop in as_path:
        try:
            normalized_path.append(int(hop))
        except (TypeError, ValueError):
            raise ValueError("All entries in 'as_path' must be integers.")

    route_data = {
        "prefix": str(prefix),
        "origin_as": origin_as_int,
        "as_path": normalized_path,
    }
    return route_data


# ==================
# Validation & Score
# ==================

def validate_bgp_route(route_data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply BGP security validation and compute a security score.

    Factors:
      - Malicious ASN detection
      - AS path length vs max-as-path-length
      - AS path loop detection
      - RPKI status (stubbed; neutral for now)

    Scoring:
      - Start at 100
      - Apply weighted penalties based on scoring-weights
      - Map final score to threat level via threat-thresholds
    """
    prefix = route_data["prefix"]
    origin_as = route_data["origin_as"]
    as_path = route_data["as_path"]

    malicious_asns: List[int] = config.get("malicious_asns", [])
    max_path_len: int = config.get("max_as_path_length", 20)
    weights: Dict[str, float] = config.get("scoring_weights", {})
    thresholds: Dict[str, int] = config.get("threat_thresholds", {})

    reasons: List[str] = []
    status = "passed"

    # --- Malicious ASN detection ---
    is_malicious_origin = origin_as in malicious_asns
    is_malicious_in_path = any(asn in malicious_asns for asn in as_path)

    base_score = 100

    if is_malicious_origin:
        reasons.append(f"Origin ASN {origin_as} is in malicious ASN list.")
        status = "failed"
        base_score -= 40

    if is_malicious_in_path and not is_malicious_origin:
        reasons.append("AS path contains malicious ASN(s).")
        status = "failed"
        base_score -= 30

    # --- AS path length checks ---
    path_len = len(as_path)
    as_path_penalty = 0
    if path_len > max_path_len:
        as_path_penalty += 50
        reasons.append(
            f"AS path length {path_len} exceeds maximum {max_path_len}."
        )
        if status != "failed":
            status = "suspicious"

    # --- AS path loop detection ---
    has_loop, loop_desc = _detect_as_path_loop(as_path)
    if has_loop:
        as_path_penalty += 60
        reasons.append(loop_desc)
        status = "failed"

    # --- RPKI (stub logic) ---
    # For now we treat RPKI as "unknown" and do not penalize heavily.
    # This can be extended to call an external RPKI validator.
    rpki_status = "unknown"
    rpki_penalty = 0
    # Example extension placeholder:
    # rpki_status, rpki_penalty = _rpki_check(prefix, origin_as, config)

    # --- Prefix and geography factors (placeholders) ---
    prefix_penalty = 0
    geo_penalty = 0

    # --- Weighted scoring ---
    as_path_weight = float(weights.get("as_path", 0.4))
    rpki_weight = float(weights.get("rpki", 0.4))
    prefix_weight = float(weights.get("prefix", 0.15))
    geo_weight = float(weights.get("geography", 0.05))

    total_penalty = (
        as_path_weight * as_path_penalty
        + rpki_weight * rpki_penalty
        + prefix_weight * prefix_penalty
        + geo_weight * geo_penalty
    )

    score = max(0, round(base_score - total_penalty, 2))

    # --- Map score to threat level ---
    threat_level = _map_score_to_threat_level(score, thresholds)

    if not reasons:
        reasons.append("No significant anomalies detected.")

    result = {
        "prefix": prefix,
        "origin_as": origin_as,
        "as_path": as_path,
        "validation_status": status,     # passed / suspicious / failed
        "security_score": score,         # 0–100
        "threat_level": threat_level,    # critical / high / medium / low
        "rpki_status": rpki_status,
        "reasons": reasons,
        "timestamp_utc": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }

    return result


def _detect_as_path_loop(as_path: List[int]) -> Tuple[bool, str]:
    """Simple loop detection: checks if any ASN repeats non-consecutively."""
    seen = {}
    for idx, asn in enumerate(as_path):
        if asn in seen and idx - seen[asn] > 1:
            return True, f"AS path loop detected involving ASN {asn}."
        seen[asn] = idx
    return False, ""


def _map_score_to_threat_level(score: float, thresholds: Dict[str, int]) -> str:
    """
    Map score to threat level using thresholds assumed to be:
      - low:    minimum score for 'low'    (e.g., 90)
      - medium: minimum score for 'medium' (e.g., 75)
      - high:   minimum score for 'high'   (e.g., 50)
      - critical: minimum for 'critical'   (e.g., 0)
    Logic:
      score >= low    -> low
      score >= medium -> medium
      score >= high   -> high
      else            -> critical
    """
    low = int(thresholds.get("low", 90))
    medium = int(thresholds.get("medium", 75))
    high = int(thresholds.get("high", 50))
    # critical is implicit

    if score >= low:
        return "low"
    if score >= medium:
        return "medium"
    if score >= high:
        return "high"
    return "critical"


# ===================
# CloudWatch Metrics
# ===================

def send_metrics(cloudwatch_client, result: Dict[str, Any]) -> None:
    """
    Emit CloudWatch metrics for BGP validation.

    Metrics:
      - BGP/Security: SecurityScore (Average)
      - BGP/Security: ValidationCount (Sum, dim: ThreatLevel)
      - BGP/Security: ValidationErrors (Sum, when status == failed)
    """
    prefix = result.get("prefix", "unknown")
    score = float(result.get("security_score", 0))
    status = result.get("validation_status", "unknown")
    threat_level = result.get("threat_level", "unknown")

    metric_data = [
        {
            "MetricName": "SecurityScore",
            "Dimensions": [
                {"Name": "Prefix", "Value": prefix},
                {"Name": "ThreatLevel", "Value": threat_level},
            ],
            "Unit": "None",
            "Value": score,
        },
        {
            "MetricName": "ValidationCount",
            "Dimensions": [
                {"Name": "ThreatLevel", "Value": threat_level},
            ],
            "Unit": "Count",
            "Value": 1.0,
        },
    ]

    if status == "failed":
        metric_data.append(
            {
                "MetricName": "ValidationErrors",
                "Dimensions": [
                    {"Name": "ThreatLevel", "Value": threat_level},
                ],
                "Unit": "Count",
                "Value": 1.0,
            }
        )

    try:
        cloudwatch_client.put_metric_data(
            Namespace="BGP/Security",
            MetricData=metric_data,
        )
    except (BotoCoreError, ClientError) as e:
        logger.error("Failed to send metrics to CloudWatch: %s", str(e))
