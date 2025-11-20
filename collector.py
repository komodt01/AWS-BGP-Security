#!/usr/bin/env python3
"""
collector.py - BGP Route Collector and Validator Client

This script acts as a simple "collector" that sends BGP route data
to the BGP Security Lambda function and prints a human-readable summary.

Typical usage in this project:
  - Read a test JSON payload from tests/*.json
  - Invoke the bgp-validator Lambda
  - Print validation status, security score, and threat level

It can be extended later to integrate with real BGP collectors (e.g., ExaBGP,
router streaming telemetry, or log pipelines).
"""

import argparse
import json
import os
import sys
from typing import Any, Dict

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def load_payload_from_file(path: str) -> Dict[str, Any]:
    """Load a JSON payload from a file."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        print(f"[ERROR] Payload file not found: {path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Failed to parse JSON from {path}: {e}", file=sys.stderr)
        sys.exit(1)


def load_payload_from_stdin() -> Dict[str, Any]:
    """Load a JSON payload from stdin."""
    try:
        data = json.load(sys.stdin)
        return data
    except json.JSONDecodeError as e:
        print(f"[ERROR] Failed to parse JSON from stdin: {e}", file=sys.stderr)
        sys.exit(1)


def validate_bgp_payload(payload: Dict[str, Any]) -> None:
    """
    Validate that the payload has the fields expected by the Lambda:
      - prefix (str)
      - origin_as (int)
      - as_path (list of int)
    This is a light sanity check; Lambda does deeper validation.
    """
    required_fields = ["prefix", "origin_as", "as_path"]

    missing = [f for f in required_fields if f not in payload]
    if missing:
        print(f"[WARN] Payload is missing fields: {', '.join(missing)}", file=sys.stderr)

    if "as_path" in payload and not isinstance(payload["as_path"], list):
        print("[WARN] 'as_path' should be a list (e.g., [64512, 15169])", file=sys.stderr)


def invoke_lambda(
    function_name: str,
    region: str,
    payload: Dict[str, Any],
    log_raw_response: bool = False,
) -> Dict[str, Any]:
    """Invoke the BGP Security Lambda and return the parsed result body."""
    try:
        client = boto3.client("lambda", region_name=region)
    except (BotoCoreError, ClientError) as e:
        print(f"[ERROR] Failed to create Lambda client: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        response = client.invoke(
            FunctionName=function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload).encode("utf-8"),
        )
    except (BotoCoreError, ClientError) as e:
        print(f"[ERROR] Error invoking Lambda function '{function_name}': {e}", file=sys.stderr)
        sys.exit(1)

    # Read raw payload from Lambda
    raw_payload = response.get("Payload")
    if raw_payload is None:
        print("[ERROR] Lambda response did not contain a Payload field.", file=sys.stderr)
        sys.exit(1)

    raw_body = raw_payload.read()
    try:
        lambda_response = json.loads(raw_body.decode("utf-8"))
    except json.JSONDecodeError as e:
        print(f"[ERROR] Failed to decode Lambda response JSON: {e}", file=sys.stderr)
        print(f"Raw response: {raw_body}", file=sys.stderr)
        sys.exit(1)

    if log_raw_response:
        print("=== Raw Lambda Response ===")
        print(json.dumps(lambda_response, indent=2))

    # Many Lambda + API Gateway-style functions wrap the actual body in a 'body' field
    result_body = lambda_response.get("body", lambda_response)
    if isinstance(result_body, str):
        try:
            result_body = json.loads(result_body)
        except json.JSONDecodeError:
            # If body is not JSON, just leave as string
            pass

    if not isinstance(result_body, dict):
        print("[WARN] Lambda result body is not a JSON object; printing as-is.")
        print(result_body)
        return {}

    return result_body


def print_summary(result: Dict[str, Any]) -> None:
    """Print a compact, human-readable summary of the validation result."""
    prefix = result.get("prefix", "<unknown>")
    origin_as = result.get("origin_as", "<unknown>")
    status = result.get("validation_status", "<unknown>")
    score = result.get("security_score", "<unknown>")
    threat = result.get("threat_level", "<unknown>")
    reasons = result.get("reasons", [])

    print("\n=== BGP Validation Result ===")
    print(f"Prefix:         {prefix}")
    print(f"Origin ASN:     {origin_as}")
    print(f"Status:         {status}")
    print(f"Security Score: {score}")
    print(f"Threat Level:   {threat}")

    if reasons:
        print("\nReasons:")
        for r in reasons:
            print(f"  - {r}")

    ts = result.get("timestamp_utc")
    if ts:
        print(f"\nTimestamp (UTC): {ts}")

    print("============================\n")


def build_arg_parser() -> argparse.ArgumentParser:
    """Create an argument parser for collector.py."""
    parser = argparse.ArgumentParser(
        description="BGP route collector client for the BGP Security Lambda."
    )
    parser.add_argument(
        "--file",
        "-f",
        help="Path to JSON file containing a single BGP route payload "
             "(e.g., tests/test_valid_route.json).",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read JSON payload from stdin instead of a file.",
    )
    parser.add_argument(
        "--lambda-function",
        "-l",
        dest="lambda_function",
        default=os.environ.get("LAMBDA_FUNCTION_NAME", "bgp-validator"),
        help="Name of the Lambda function to invoke "
             f"(default: env LAMBDA_FUNCTION_NAME or 'bgp-validator').",
    )
    parser.add_argument(
        "--region",
        "-r",
        default=os.environ.get("AWS_REGION", "us-east-1"),
        help="AWS region for the Lambda function (default: env AWS_REGION or 'us-east-1').",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Print full raw Lambda response JSON in addition to the summary.",
    )
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    if not args.file and not args.stdin:
        parser.error("You must specify either --file or --stdin as the payload source.")

    # Load BGP payload
    if args.file:
        payload = load_payload_from_file(args.file)
    else:
        payload = load_payload_from_stdin()

    validate_bgp_payload(payload)

    print(f"[INFO] Invoking Lambda '{args.lambda_function}' in region '{args.region}'...")
    result = invoke_lambda(
        function_name=args.lambda_function,
        region=args.region,
        payload=payload,
        log_raw_response=args.raw,
    )

    if result:
        print_summary(result)
    else:
        print("[WARN] No structured result returned from Lambda.", file=sys.stderr)


if __name__ == "__main__":
    main()
