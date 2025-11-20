#!/bin/bash

# Load environment settings
source project-config.env

echo "🧪 Running BGP Security Tests..."
echo "================================"

test_scenarios=(
  "test_valid_route.json:Valid Google Route"
  "test_malicious_route.json:Malicious ASN 666"
  "test_loop_route.json:AS Path Loop"
  "test_long_path.json:Long AS Path"
)

for scenario in "${test_scenarios[@]}"; do
  IFS=':' read -r file description <<< "$scenario"

  echo "Testing: $description"
  echo "File: $file"

  aws lambda invoke \
    --cli-binary-format raw-in-base64-out \
    --function-name $LAMBDA_FUNCTION_NAME \
    --payload file://tests/$file \
    tests/out_$file > /dev/null

  # Extract fields from Lambda JSON structure
  # Remember: Lambda returns: { "statusCode": 200, "body": "<json-string>" }
  body=$(cat tests/out_$file | jq -r '.body')

  status=$(echo "$body" | jq -r '.validation_status')
  score=$(echo "$body" | jq -r '.security_score')
  threat=$(echo "$body" | jq -r '.threat_level')
  msg=$(echo "$body" | jq -r '.reasons[0]')

  echo "  → Status:  $status"
  echo "  → Score:   $score"
  echo "  → Threat:  $threat"
  echo "  → Reason:  $msg"
  echo ""
done

echo "✅ All tests completed!"
