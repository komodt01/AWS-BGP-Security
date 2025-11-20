#!/usr/bin/env python3
"""
collector.py – Example BGP collector for the AWS BGP Security Monitoring System.

Purpose:
  - Runs close to your BGP routers (Linux jump host, NOC server, container)
  - Reads BGP routes from a file or other source
  - Normalizes them into the JSON structure expected by bgp-validator
  - Publishes them to Amazon EventBridge (or invokes Lambda directly)

Usage:
  python3 collector.py --source routes.jsonl --mode eventbridge
"""

import argparse
import json
import sys
from typing import Iterable, Dict, Any

import boto3


def load_routes_from_jsonl(path: str) -> Iterable[Dict[str, Any]]:
    """
    Load BGP routes from a JSON Lines file.
    Each line should be a JSON object like:
      {"prefix": "8.8.8.0/24", "origin_as": 15169, "as_path": [64512, 15169]}
    """
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                yield obj
            except json.JSONDecodeError:
                print(f"Skipping invalid JSON line: {line}", file=sys.stderr)


def load_routes_from_stdin() -> Iterable[Dict[str, Any]]:
    """
    Read routes from STDIN, one JSON object per line.
    """
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            print(f"Skipping invalid JSON line: {line}", file=sys.stderr)


def send_to_eventbridge(routes: Iterable[Dict[str, Any]],
                        bus_name: str,
                        source: str,
                        detail_type: str):
    """
    Publish routes to Amazon EventBridge as individual events.
    """
    client = boto3.client("events")
    entries = []

    for route in routes:
        entries.append(
            {
                "Source": source,
                "DetailType": detail_type,
                "Detail": json.dumps(route),
                "EventBusName": bus_name,
            }
        )

        # EventBridge PutEvents max 10 at a time
        if len(entries) == 10:
            resp = client.put_events(Entries=entries)
            failed = resp.get("FailedEntryCount", 0)
            if failed:
                print(f"[WARN] {failed} entries failed in PutEvents batch", file=sys.stderr)
            entries = []

    if entries:
        resp = client.put_events(Entries=entries)
        failed = resp.get("FailedEntryCount", 0)
        if failed:
            print(f"[WARN] {failed} entries failed in final PutEvents batch", file=sys.stderr)


def send_to_lambda(routes: Iterable[Dict[str, Any]], function_name: str):
    """
    Invoke the bgp-validator Lambda directly for each route.
    """
    client = boto3.client("lambda")

    for route in routes:
        payload = json.dumps(route).encode("utf-8")
        resp = client.invoke(
            FunctionName=function_name,
            InvocationType="RequestResponse",
            Payload=payload,
        )
        if "FunctionError" in resp:
            print(
                f"[ERROR] Lambda error for route {route}: {resp['FunctionError']}",
                file=sys.stderr,
            )


def parse_args():
    parser = argparse.ArgumentParser(description="BGP Collector for AWS BGP Security Monitoring")
    parser.add_argument(
        "--source",
        help="Path to JSONL route file. If omitted and --stdin is set, reads from stdin.",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read routes from stdin (one JSON object per line).",
    )
    parser.add_argument(
        "--mode",
        choices=["eventbridge", "lambda"],
        default="eventbridge",
        help="Delivery mode: eventbridge (default) or lambda direct invoke.",
    )
    parser.add_argument(
        "--event-bus",
        default="default",
        help="EventBridge bus name (for mode=eventbridge).",
    )
    parser.add_argument(
        "--event-source",
        default="bgp.collector",
        help="EventBridge 'Source' value.",
    )
    parser.add_argument(
        "--event-detail-type",
        default="BGPRouteUpdate",
        help="EventBridge 'DetailType' value.",
    )
    parser.add_argument(
        "--lambda-function",
        default="bgp-validator",
        help="Lambda function name (for mode=lambda).",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if args.stdin:
        routes = load_routes_from_stdin()
    elif args.source:
        routes = load_routes_from_jsonl(args.source)
    else:
        print("You must specify --source FILE or --stdin", file=sys.stderr)
        sys.exit(1)

    if args.mode == "eventbridge":
        send_to_eventbridge(
            routes,
            bus_name=args.event_bus,
            source=args.event_source,
            detail_type=args.event_detail_type,
        )
    else:
        send_to_lambda(routes, function_name=args.lambda_function)


if __name__ == "__main__":
    main()
