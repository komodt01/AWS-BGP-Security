# Linux Commands Reference  
Complete AWS CLI and Linux command reference for the **BGP Security Project** (BGP route validator with Lambda, Systems Manager Parameter Store, CloudWatch, and BGP operational references including Direct Connect and multi-cloud notes).

---

## 🚀 Initial Environment Setup

### AWS CLI Installation and Configuration

    # Install AWS CLI v2 (if not already installed)
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip awscliv2.zip
    sudo ./aws/install

    # Verify installation
    aws --version

    # Configure AWS credentials and region
    aws configure
    # Enter your:
    # - AWS Access Key ID
    # - AWS Secret Access Key
    # - Default region (us-east-1)
    # - Default output format (json)

    # Verify authentication
    aws sts get-caller-identity

    # OPTIONAL: Set up a dedicated profile for BGP project
    aws configure --profile bgp-security
    export AWS_PROFILE=bgp-security

### Project Environment Setup

    # Create project directory structure
    mkdir -p aws-bgp-security/{scripts,lambda,tests,docs}
    cd aws-bgp-security

    # Set environment variables for consistency
    export PROJECT_NAME="bgp-security"
    export AWS_REGION="us-east-1"
    export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

    # Create environment configuration file
    cat > project-config.env << EOF
    export PROJECT_NAME="bgp-security"
    export AWS_REGION="us-east-1"
    export ACCOUNT_ID="$ACCOUNT_ID"
    export LAMBDA_FUNCTION_NAME="bgp-validator"
    export IAM_ROLE_NAME="lambda-bgp-execution-role"
    EOF

    # Load environment (add to your shell profile for persistence)
    source project-config.env

### Essential Tools Installation

    # Install Python and pip (if not already installed)
    sudo apt update
    sudo apt install -y python3 python3-pip

    # Install boto3 for AWS SDK
    pip3 install boto3

    # Install jq for JSON processing
    sudo apt install -y jq

    # Verify tools
    python3 --version
    pip3 --version
    jq --version

---

## 🔧 Systems Manager Configuration

### Create BGP Security Parameters

    # Create core BGP security parameters
    aws ssm put-parameter \
      --name "/bgp-security/malicious-asns" \
      --value "666,1337,31337,65666" \
      --type "StringList" \
      --description "Known malicious AS numbers for BGP validation" \
      --overwrite

    aws ssm put-parameter \
      --name "/bgp-security/rpki-validator-url" \
      --value "https://rpki-validator.cloudflare.com/api/v1/origin" \
      --type "String" \
      --description "RPKI validator service endpoint URL" \
      --overwrite

    aws ssm put-parameter \
      --name "/bgp-security/max-as-path-length" \
      --value "20" \
      --type "String" \
      --description "Maximum allowed AS path length before flagging as suspicious" \
      --overwrite

    aws ssm put-parameter \
      --name "/bgp-security/scoring-weights" \
      --value '{"as_path":0.4,"rpki":0.4,"prefix":0.15,"geography":0.05}' \
      --type "String" \
      --description "Weighted scoring algorithm for BGP security assessment" \
      --overwrite

    aws ssm put-parameter \
      --name "/bgp-security/threat-thresholds" \
      --value '{"low":90,"medium":75,"high":50,"critical":0}' \
      --type "String" \
      --description "Security score thresholds for threat level classification" \
      --overwrite

### Verify Systems Manager Parameters

    # List all BGP security parameters
    aws ssm get-parameters-by-path \
      --path "/bgp-security/" \
      --recursive \
      --with-decryption

    # Get specific parameter
    aws ssm get-parameter \
      --name "/bgp-security/malicious-asns" \
      --with-decryption

    # Get parameter with formatted output
    aws ssm get-parameter \
      --name "/bgp-security/scoring-weights" \
      --with-decryption \
      --query 'Parameter.Value' \
      --output text | jq '.'

    # Delete parameter (if needed)
    # aws ssm delete-parameter --name "/bgp-security/parameter-name"

---

## 👤 IAM Role and Policy Management

### Create Lambda Execution Role

    # Create trust policy for Lambda
    cat > lambda-trust-policy.json << 'EOF'
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": {
            "Service": "lambda.amazonaws.com"
          },
          "Action": "sts:AssumeRole"
        }
      ]
    }
    EOF

    # Create IAM role
    aws iam create-role \
      --role-name $IAM_ROLE_NAME \
      --assume-role-policy-document file://lambda-trust-policy.json \
      --description "Execution role for BGP security Lambda function"

    # Attach AWS managed policies
    aws iam attach-role-policy \
      --role-name $IAM_ROLE_NAME \
      --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

    aws iam attach-role-policy \
      --role-name $IAM_ROLE_NAME \
      --policy-arn arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess

    aws iam attach-role-policy \
      --role-name $IAM_ROLE_NAME \
      --policy-arn arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy

### Create Custom Policy for BGP Security

    # Create custom policy for specific BGP security requirements
    cat > bgp-security-policy.json << 'EOF'
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ssm:GetParameter",
                    "ssm:GetParameters",
                    "ssm:GetParametersByPath",
                    "ssm:DescribeParameters"
                ],
                "Resource": [
                    "arn:aws:ssm:*:*:parameter/bgp-security/*"
                ]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "cloudwatch:PutMetricData"
                ],
                "Resource": "*"
            }
        ]
    }
    EOF

    # Create the custom policy
    aws iam create-policy \
      --policy-name BGP-Security-Custom-Policy \
      --policy-document file://bgp-security-policy.json \
      --description "Custom policy for BGP security Lambda function"

    # Attach custom policy to role
    aws iam attach-role-policy \
      --role-name $IAM_ROLE_NAME \
      --policy-arn arn:aws:iam::$ACCOUNT_ID:policy/BGP-Security-Custom-Policy

### Verify IAM Configuration

    # List attached policies
    aws iam list-attached-role-policies \
      --role-name $IAM_ROLE_NAME

    # Get role details
    aws iam get-role \
      --role-name $IAM_ROLE_NAME

    # Test role assumption (optional)
    aws sts assume-role \
      --role-arn "arn:aws:iam::$ACCOUNT_ID:role/$IAM_ROLE_NAME" \
      --role-session-name "bgp-test-session"

---

## 📡 Direct Connect BGP Primer (Reference)

These are **reference-only** commands for edge router configuration when using **AWS Direct Connect + BGP**.  
They complement the Lambda-based security checks by showing how BGP sessions are actually configured on-prem.

### Cisco IOS-style BGP Configuration Example

    router bgp <LOCAL_ASN>
      bgp log-neighbor-changes

      neighbor <AWS_PEER_IP> remote-as <AWS_BGP_ASN>
      neighbor <AWS_PEER_IP> description AWS Direct Connect Private VIF
      neighbor <AWS_PEER_IP> password StrongBGPpw!
      neighbor <AWS_PEER_IP> timers 30 90
      neighbor <AWS_PEER_IP> ebgp-multihop 2
      !
      # Advertise on-prem networks to AWS
      network 10.0.0.0 mask 255.255.0.0

### Operational Notes

- Use **MD5 password** on the BGP session (as required by AWS DX).
- Ensure the **VLAN**, **subnet**, and **MTU** are configured consistently with the DX LOA-CFA.
- Only advertise **approved prefixes** (e.g., RFC1918) according to routing policy.
- Use **prefix-lists** and **route-maps** to prevent route leaks and to enforce security policy.

*(These reference configs are not executed by the project, but they show how your Lambda validator could be extended to evaluate real route advertisements from a DX-connected router.)*

---

## ⚡ Lambda Function Deployment

### Create Lambda Function Code

    # Navigate to lambda directory
    cd lambda

    # Create the BGP validator function
    cat > bgp_with_ssm.py << 'EOF'
    import json
    import boto3
    import logging
    from datetime import datetime

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    def lambda_handler(event, context):
        try:
            # Initialize AWS services
            ssm = boto3.client('ssm')
            cloudwatch = boto3.client('cloudwatch')

            # Load configuration from Systems Manager
            config = load_configuration(ssm)

            # Parse BGP route data
            route_data = parse_event(event)

            # Validate BGP route
            result = validate_bgp_route(route_data, config)

            # Send metrics to CloudWatch
            send_metrics(cloudwatch, result)

            return {
                'statusCode': 200,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps(result, indent=2)
            }

        except Exception as e:
            logger.error(f"Lambda error: {str(e)}")
            return {
                'statusCode': 500,
                'body': json.dumps({'error': str(e)})
            }

    def load_configuration(ssm):
        # Implementation here
        pass

    def parse_event(event):
        # Implementation here
        pass

    def validate_bgp_route(route_data, config):
        # Implementation here
        pass

    def send_metrics(cloudwatch, result):
        # Implementation here
        pass
    EOF

    # Create deployment package
    zip bgp-validator.zip bgp_with_ssm.py

    # Return to project root
    cd ..

### Deploy Lambda Function

    # Create Lambda function
    aws lambda create-function \
      --function-name $LAMBDA_FUNCTION_NAME \
      --runtime python3.9 \
      --role "arn:aws:iam::$ACCOUNT_ID:role/$IAM_ROLE_NAME" \
      --handler bgp_with_ssm.lambda_handler \
      --zip-file fileb://lambda/bgp-validator.zip \
      --timeout 60 \
      --memory-size 512 \
      --description "BGP Security Route Validator with Systems Manager integration"

    # Wait for function to be active
    aws lambda wait function-active \
      --function-name $LAMBDA_FUNCTION_NAME

    # Verify function creation
    aws lambda get-function \
      --function-name $LAMBDA_FUNCTION_NAME \
      --query 'Configuration.[FunctionName,State,Runtime,Handler]'

### Update Lambda Function

    # Update function code
    aws lambda update-function-code \
      --function-name $LAMBDA_FUNCTION_NAME \
      --zip-file fileb://lambda/bgp-validator.zip

    # Update function configuration
    aws lambda update-function-configuration \
      --function-name $LAMBDA_FUNCTION_NAME \
      --handler bgp_with_ssm.lambda_handler \
      --timeout 60 \
      --memory-size 512

    # Update environment variables (if needed)
    aws lambda update-function-configuration \
      --function-name $LAMBDA_FUNCTION_NAME \
      --environment Variables='{ENVIRONMENT=prod,LOG_LEVEL=INFO}'

---

## 🧪 Testing and Validation

### Create Test Payloads

    # Create test directory and payloads
    mkdir -p tests
    cd tests

    # Valid Google route test
    cat > test_valid_route.json << 'EOF'
    {
      "prefix": "8.8.8.0/24",
      "origin_as": 15169,
      "as_path": [64512, 15169]
    }
    EOF

    # Malicious ASN test
    cat > test_malicious_route.json << 'EOF'
    {
      "prefix": "8.8.8.0/24",
      "origin_as": 666,
      "as_path": [64512, 666]
    }
    EOF

    # AS path loop test
    cat > test_loop_route.json << 'EOF'
    {
      "prefix": "203.0.113.0/24",
      "origin_as": 64496,
      "as_path": [64512, 64496, 64512]
    }
    EOF

    # Long AS path test
    cat > test_long_path.json << 'EOF'
    {
      "prefix": "198.51.100.0/24",
      "origin_as": 65010,
      "as_path": [64512, 65001, 65002, 65003, 65004, 65005, 65006, 65007, 65008, 65009, 65010]
    }
    EOF

    cd ..

### Execute Lambda Tests

    # Test valid route
    aws lambda invoke \
      --cli-binary-format raw-in-base64-out \
      --function-name $LAMBDA_FUNCTION_NAME \
      --payload file://tests/test_valid_route.json \
      tests/result_valid.json

    echo "Valid route result:"
    cat tests/result_valid.json | jq '.'

    # Test malicious route
    aws lambda invoke \
      --cli-binary-format raw-in-base64-out \
      --function-name $LAMBDA_FUNCTION_NAME \
      --payload file://tests/test_malicious_route.json \
      tests/result_malicious.json

    echo "Malicious route result:"
    cat tests/result_malicious.json | jq '.'

    # Test AS path loop
    aws lambda invoke \
      --cli-binary-format raw-in-base64-out \
      --function-name $LAMBDA_FUNCTION_NAME \
      --payload file://tests/test_loop_route.json \
      tests/result_loop.json

    echo "AS path loop result:"
    cat tests/result_loop.json | jq '.'

    # Test long AS path
    aws lambda invoke \
      --cli-binary-format raw-in-base64-out \
      --function-name $LAMBDA_FUNCTION_NAME \
      --payload file://tests/test_long_path.json \
      tests/result_long_path.json

    echo "Long AS path result:"
    cat tests/result_long_path.json | jq '.'

### Automated Test Script (run_tests.sh)

    # Create automated test script
    cat > run_tests.sh << 'EOF'
    #!/bin/bash

    # Load environment
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

      # Extract fields from Lambda JSON structure: { statusCode, body }
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
    EOF

    chmod +x run_tests.sh

    # Run automated tests
    ./run_tests.sh

---

## 📊 CloudWatch Monitoring

### View Lambda Function Logs

    # Get recent Lambda logs
    aws logs filter-log-events \
      --log-group-name "/aws/lambda/$LAMBDA_FUNCTION_NAME" \
      --start-time $(date -d '1 hour ago' +%s)000 \
      --limit 20

    # Follow logs in real-time (requires AWS CLI v2.2+)
    aws logs tail "/aws/lambda/$LAMBDA_FUNCTION_NAME" --follow

    # Filter logs by severity
    aws logs filter-log-events \
      --log-group-name "/aws/lambda/$LAMBDA_FUNCTION_NAME" \
      --filter-pattern "ERROR" \
      --start-time $(date -d '1 hour ago' +%s)000

    # Search for specific validation events
    aws logs filter-log-events \
      --log-group-name "/aws/lambda/$LAMBDA_FUNCTION_NAME" \
      --filter-pattern "BGP validation completed" \
      --start-time $(date -d '6 hours ago' +%s)000

### CloudWatch Metrics Queries

    # Get Lambda function metrics (duration)
    aws cloudwatch get-metric-statistics \
      --namespace AWS/Lambda \
      --metric-name Duration \
      --dimensions Name=FunctionName,Value=$LAMBDA_FUNCTION_NAME \
      --start-time $(date -d '1 hour ago' --iso-8601) \
      --end-time $(date --iso-8601) \
      --period 300 \
      --statistics Average,Maximum

    # Get custom BGP security metrics
    aws cloudwatch get-metric-statistics \
      --namespace "BGP/Security" \
      --metric-name SecurityScore \
      --start-time $(date -d '1 hour ago' --iso-8601) \
      --end-time $(date --iso-8601) \
      --period 300 \
      --statistics Average,Minimum,Maximum

    # List available custom metrics
    aws cloudwatch list-metrics \
      --namespace "BGP/Security"

### Create CloudWatch Dashboard

    # Create dashboard configuration
    cat > dashboard-config.json << 'EOF'
    {
      "widgets": [
        {
          "type": "metric",
          "x": 0,
          "y": 0,
          "width": 12,
          "height": 6,
          "properties": {
            "metrics": [
              ["BGP/Security", "SecurityScore"]
            ],
            "view": "timeSeries",
            "stacked": false,
            "region": "us-east-1",
            "title": "BGP Security Score Timeline",
            "period": 300,
            "stat": "Average"
          }
        }
      ]
    }
    EOF

    # Create dashboard
    aws cloudwatch put-dashboard \
      --dashboard-name "BGP-Security-Monitoring" \
      --dashboard-body file://dashboard-config.json

    # List dashboards
    aws cloudwatch list-dashboards

    # Get dashboard
    aws cloudwatch get-dashboard \
      --dashboard-name "BGP-Security-Monitoring"

### CloudWatch Alarms

    # Create alarm for critical threats
    aws cloudwatch put-metric-alarm \
      --alarm-name "BGP-Critical-Threat-Detected" \
      --alarm-description "Critical BGP threats detected" \
      --metric-name ValidationCount \
      --namespace "BGP/Security" \
      --statistic Sum \
      --period 300 \
      --threshold 1 \
      --comparison-operator GreaterThanOrEqualToThreshold \
      --dimensions Name=ThreatLevel,Value=critical \
      --evaluation-periods 1

    # Create alarm for low security scores
    aws cloudwatch put-metric-alarm \
      --alarm-name "BGP-Security-Score-Low" \
      --alarm-description "BGP security score below threshold" \
      --metric-name SecurityScore \
      --namespace "BGP/Security" \
      --statistic Average \
      --period 300 \
      --threshold 50 \
      --comparison-operator LessThanThreshold \
      --evaluation-periods 2

    # List alarms
    aws cloudwatch describe-alarms \
      --alarm-names "BGP-Critical-Threat-Detected" "BGP-Security-Score-Low"

    # Test alarm (simulate alarm state)
    aws cloudwatch set-alarm-state \
      --alarm-name "BGP-Critical-Threat-Detected" \
      --state-value ALARM \
      --state-reason "Testing alarm notification"

---

## 🔧 Management and Maintenance

### Function Configuration Management

    # Get current function configuration
    aws lambda get-function-configuration \
      --function-name $LAMBDA_FUNCTION_NAME

    # Update function timeout
    aws lambda update-function-configuration \
      --function-name $LAMBDA_FUNCTION_NAME \
      --timeout 90

    # Update function memory
    aws lambda update-function-configuration \
      --function-name $LAMBDA_FUNCTION_NAME \
      --memory-size 1024

    # Set reserved concurrency
    aws lambda put-reserved-concurrency-settings \
      --function-name $LAMBDA_FUNCTION_NAME \
      --reserved-concurrency-limit 100

    # Remove reserved concurrency
    aws lambda delete-reserved-concurrency-settings \
      --function-name $LAMBDA_FUNCTION_NAME

### Version Management

    # Publish function version
    aws lambda publish-version \
      --function-name $LAMBDA_FUNCTION_NAME \
      --description "Production version with Systems Manager integration"

    # Create alias
    aws lambda create-alias \
      --function-name $LAMBDA_FUNCTION_NAME \
      --name PROD \
      --function-version 1 \
      --description "Production alias"

    # Update alias
    aws lambda update-alias \
      --function-name $LAMBDA_FUNCTION_NAME \
      --name PROD \
      --function-version 2

    # List versions
    aws lambda list-versions-by-function \
      --function-name $LAMBDA_FUNCTION_NAME

    # List aliases
    aws lambda list-aliases \
      --function-name $LAMBDA_FUNCTION_NAME

### Performance Monitoring

    # Get function invocation statistics
    aws cloudwatch get-metric-statistics \
      --namespace AWS/Lambda \
      --metric-name Invocations \
      --dimensions Name=FunctionName,Value=$LAMBDA_FUNCTION_NAME \
      --start-time $(date -d '24 hours ago' --iso-8601) \
      --end-time $(date --iso-8601) \
      --period 3600 \
      --statistics Sum

    # Check for errors
    aws cloudwatch get-metric-statistics \
      --namespace AWS/Lambda \
      --metric-name Errors \
      --dimensions Name=FunctionName,Value=$LAMBDA_FUNCTION_NAME \
      --start-time $(date -d '24 hours ago' --iso-8601) \
      --end-time $(date --iso-8601) \
      --period 3600 \
      --statistics Sum

    # Monitor throttles
    aws cloudwatch get-metric-statistics \
      --namespace AWS/Lambda \
      --metric-name Throttles \
      --dimensions Name=FunctionName,Value=$LAMBDA_FUNCTION_NAME \
      --start-time $(date -d '24 hours ago' --iso-8601) \
      --end-time $(date --iso-8601) \
      --period 3600 \
      --statistics Sum

---

## 🔄 Backup and Recovery

### Export Configuration

    # Export Systems Manager parameters
    aws ssm get-parameters-by-path \
      --path "/bgp-security/" \
      --recursive \
      --with-decryption \
      --output json > bgp-security-config-backup.json

    # Export Lambda function configuration
    aws lambda get-function \
      --function-name $LAMBDA_FUNCTION_NAME \
      --output json > lambda-function-backup.json

    # Download function code
    DOWNLOAD_URL=$(aws lambda get-function \
      --function-name $LAMBDA_FUNCTION_NAME \
      --query 'Code.Location' \
      --output text)

    curl -o function-code-backup.zip "$DOWNLOAD_URL"

    # Export IAM role
    aws iam get-role \
      --role-name $IAM_ROLE_NAME \
      --output json > iam-role-backup.json

    aws iam list-attached-role-policies \
      --role-name $IAM_ROLE_NAME \
      --output json > iam-policies-backup.json

### Restore from Backup

    # Restore Systems Manager parameters from backup
    jq -r '.Parameters[] | "\(.Name) \(.Value) \(.Type)"' bgp-security-config-backup.json | \
    while read name value type; do
      aws ssm put-parameter \
        --name "$name" \
        --value "$value" \
        --type "$type" \
        --overwrite
    done

    # Restore Lambda function
    aws lambda create-function \
      --function-name "${LAMBDA_FUNCTION_NAME}-restored" \
      --runtime python3.9 \
      --role "arn:aws:iam::$ACCOUNT_ID:role/$IAM_ROLE_NAME" \
      --handler bgp_with_ssm.lambda_handler \
      --zip-file fileb://function-code-backup.zip \
      --timeout 60 \
      --memory-size 512

---

## 🗑️ Cleanup and Teardown

### Delete Resources in Correct Order

    # Create cleanup script
    cat > cleanup.sh << 'EOF'
    #!/bin/bash

    # Load environment
    source project-config.env

    echo "🗑️ Starting BGP Security Project Cleanup..."

    # Delete CloudWatch alarms
    echo "Deleting CloudWatch alarms..."
    aws cloudwatch delete-alarms \
      --alarm-names "BGP-Critical-Threat-Detected" "BGP-Security-Score-Low"

    # Delete CloudWatch dashboard
    echo "Deleting CloudWatch dashboard..."
    aws cloudwatch delete-dashboards \
      --dashboard-names "BGP-Security-Monitoring"

    # Delete Lambda function
    echo "Deleting Lambda function..."
    aws lambda delete-function \
      --function-name $LAMBDA_FUNCTION_NAME

    # Detach policies from IAM role
    echo "Detaching IAM policies..."
    aws iam detach-role-policy \
      --role-name $IAM_ROLE_NAME \
      --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

    aws iam detach-role-policy \
      --role-name $IAM_ROLE_NAME \
      --policy-arn arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess

    aws iam detach-role-policy \
      --role-name $IAM_ROLE_NAME \
      --policy-arn arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy

    aws iam detach-role-policy \
      --role-name $IAM_ROLE_NAME \
      --policy-arn arn:aws:iam::$ACCOUNT_ID:policy/BGP-Security-Custom-Policy

    # Delete custom policy
    echo "Deleting custom IAM policy..."
    aws iam delete-policy \
      --policy-arn arn:aws:iam::$ACCOUNT_ID:policy/BGP-Security-Custom-Policy

    # Delete IAM role
    echo "Deleting IAM role..."
    aws iam delete-role \
      --role-name $IAM_ROLE_NAME

    # Delete Systems Manager parameters
    echo "Deleting Systems Manager parameters..."
    PARAMS=$(aws ssm get-parameters-by-path \
      --path "/bgp-security/" \
      --recursive \
      --query 'Parameters[].Name' \
      --output text)

    for param in $PARAMS; do
      aws ssm delete-parameter --name "$param"
      echo "Deleted parameter: $param"
    done

    echo "✅ Cleanup completed!"
    echo "💰 Verify no charges are accruing in AWS Billing Console"
    EOF

    chmod +x cleanup.sh

    # Run cleanup (BE CAREFUL - this deletes everything!)
    # ./cleanup.sh

### Verify Cleanup

    # Verify Lambda function deleted
    aws lambda get-function --function-name $LAMBDA_FUNCTION_NAME 2>&1 | grep -q "ResourceNotFoundException" && echo "✅ Lambda function deleted" || echo "❌ Lambda function still exists"

    # Verify IAM role deleted
    aws iam get-role ---role-name $IAM_ROLE_NAME 2>&1 | grep -q "NoSuchEntity" && echo "✅ IAM role deleted" || echo "❌ IAM role still exists"

    # Verify Systems Manager parameters deleted
    PARAM_COUNT=$(aws ssm get-parameters-by-path --path "/bgp-security/" --recursive --query 'Parameters | length(@)')
    if [ "$PARAM_COUNT" -eq 0 ]; then
      echo "✅ All Systems Manager parameters deleted"
    else
      echo "❌ $PARAM_COUNT Systems Manager parameters still exist"
    fi

    # Check for any remaining CloudWatch alarms
    ALARM_COUNT=$(aws cloudwatch describe-alarms --alarm-name-prefix "BGP-" --query 'MetricAlarms | length(@)')
    if [ "$ALARM_COUNT" -eq 0 ]; then
      echo "✅ All CloudWatch alarms deleted"
    else
      echo "❌ $ALARM_COUNT CloudWatch alarms still exist"
    fi

---

## 📋 Quick Reference Commands

### Essential Daily Commands

    # Load project environment
    source project-config.env

    # Check Lambda function status
    aws lambda get-function-configuration \
      --function-name $LAMBDA_FUNCTION_NAME \
      --query '[State,LastUpdateStatus,FunctionName]'

    # Quick function test
    aws lambda invoke \
      --cli-binary-format raw-in-base64-out \
      --function-name $LAMBDA_FUNCTION_NAME \
      --payload '{"prefix":"8.8.8.0/24","origin_as":15169,"as_path":[64512,15169]}' \
      /tmp/test-result.json && cat /tmp/test-result.json | jq '.body | fromjson'

    # View recent logs
    aws logs filter-log-events \
      --log-group-name "/aws/lambda/$LAMBDA_FUNCTION_NAME" \
      --start-time $(date -d '10 minutes ago' +%s)000 \
      --limit 5

    # Check current metrics
    aws cloudwatch get-metric-statistics \
      --namespace "BGP/Security" \
      --metric-name SecurityScore \
      --start-time $(date -d '1 hour ago' --iso-8601) \
      --end-time $(date --iso-8601) \
      --period 300 \
      --statistics Average \
      --query 'Datapoints[-1].Average'

### Troubleshooting Commands

    # Check IAM permissions
    aws iam simulate-principal-policy \
      --policy-source-arn "arn:aws:iam::$ACCOUNT_ID:role/$IAM_ROLE_NAME" \
      --action-names "ssm:GetParametersByPath" \
      --resource-arns "arn:aws:ssm:$AWS_REGION:$ACCOUNT_ID:parameter/bgp-security/*"

    # Test Systems Manager access
    aws ssm get-parameter \
      --name "/bgp-security/malicious-asns" \
      --with-decryption

    # Check Lambda execution errors
    aws logs filter-log-events \
      --log-group-name "/aws/lambda/$LAMBDA_FUNCTION_NAME" \
      --filter-pattern "ERROR" \
      --start-time $(date -d '1 hour ago' +%s)000

    # Monitor Lambda performance
    aws cloudwatch get-metric-statistics \
      --namespace AWS/Lambda \
      --metric-name Duration \
      --dimensions Name=FunctionName,Value=$LAMBDA_FUNCTION_NAME \
      --start-time $(date -d '1 hour ago' --iso-8601) \
      --end-time $(date --iso-8601) \
      --period 300 \
      --statistics Average,Maximum

### Emergency Response Commands

    # Disable Lambda function (in case of issues)
    aws lambda put-reserved-concurrency-settings \
      --function-name $LAMBDA_FUNCTION_NAME \
      --reserved-concurrency-limit 0

    # Re-enable Lambda function
    aws lambda delete-reserved-concurrency-settings \
      --function-name $LAMBDA_FUNCTION_NAME

    # Force function update (emergency code deployment)
    aws lambda update-function-code \
      --function-name $LAMBDA_FUNCTION_NAME \
      --zip-file fileb://lambda/emergency-fix.zip

    # Check billing impact (cost monitoring)
    aws ce get-cost-and-usage \
      --time-period Start=$(date -d '7 days ago' --iso-8601),End=$(date --iso-8601) \
      --granularity DAILY \
      --metrics BlendedCost \
      --group-by Type=DIMENSION,Key=SERVICE

    # Emergency alarm disable
    aws cloudwatch disable-alarm-actions \
      --alarm-names "BGP-Critical-Threat-Detected"

    # Emergency alarm re-enable
    aws cloudwatch enable-alarm-actions \
      --alarm-names "BGP-Critical-Threat-Detected"

---

## 🔧 Advanced Operations

### Batch Processing Commands

    # Bulk test multiple BGP routes
    cat > bulk_test.sh << 'EOF'
    #!/bin/bash

    # Array of test cases
    declare -a test_cases=(
      '{"prefix":"8.8.8.0/24","origin_as":15169,"as_path":[64512,15169]}:Google DNS'
      '{"prefix":"1.1.1.0/24","origin_as":13335,"as_path":[64512,13335]}:Cloudflare DNS'
      '{"prefix":"8.8.8.0/24","origin_as":666,"as_path":[64512,666]}:Malicious ASN'
      '{"prefix":"203.0.113.0/24","origin_as":64496,"as_path":[64512,64496,64512]}:AS Loop'
      '{"prefix":"198.51.100.0/24","origin_as":65010,"as_path":[64512,65001,65002,65003,65004,65005,65006,65007,65008,65009,65010]}:Long Path'
    )

    echo "🧪 Running bulk BGP validation tests..."
    echo "====================================="

    for test_case in "${test_cases[@]}"; do
      IFS=':' read -r payload description <<< "$test_case"

      echo "Testing: $description"

      # Create temporary payload file
      echo "$payload" > /tmp/test_payload.json

      # Invoke Lambda
      aws lambda invoke \
        --cli-binary-format raw-in-base64-out \
        --function-name $LAMBDA_FUNCTION_NAME \
        --payload file:///tmp/test_payload.json \
        /tmp/test_result.json > /dev/null

      # Extract results
      if [ -f /tmp/test_result.json ]; then
        body=$(cat /tmp/test_result.json | jq -r '.body')
        status=$(echo "$body" | jq -r '.validation_status // "error"')
        score=$(echo "$body" | jq -r '.security_score // 0')
        threat=$(echo "$body" | jq -r '.threat_level // "unknown"')

        echo "  → Status: $status | Score: $score | Threat: $threat"
      else
        echo "  → ERROR: No response received"
      fi

      echo ""
      sleep 1  # Rate limiting
    done

    # Cleanup
    rm -f /tmp/test_payload.json /tmp/test_result.json

    echo "✅ Bulk testing completed!"
    EOF

    chmod +x bulk_test.sh
    ./bulk_test.sh

### Performance Benchmarking

    # Create performance test script
    cat > performance_test.sh << 'EOF'
    #!/bin/bash

    source project-config.env

    echo "⚡ BGP Validator Performance Benchmarking..."
    echo "==========================================="

    # Test payload
    PAYLOAD='{"prefix":"8.8.8.0/24","origin_as":15169,"as_path":[64512,15169]}'

    # Number of concurrent tests
    CONCURRENT_TESTS=10
    TOTAL_TESTS=100

    echo "Configuration:"
    echo "  - Concurrent requests: $CONCURRENT_TESTS"
    echo "  - Total requests: $TOTAL_TESTS"
    echo "  - Function: $LAMBDA_FUNCTION_NAME"
    echo ""

    # Function to run single test
    run_test() {
      local test_id=$1
      start_time=$(date +%s%3N)

      aws lambda invoke \
        --cli-binary-format raw-in-base64-out \
        --function-name $LAMBDA_FUNCTION_NAME \
        --payload "$PAYLOAD" \
        /tmp/perf_result_${test_id}.json > /dev/null 2>&1

      end_time=$(date +%s%3N)
      duration=$((end_time - start_time))

      echo "$duration" > /tmp/perf_time_${test_id}.txt
    }

    # Run concurrent tests
    echo "Running performance tests..."
    for batch in $(seq 1 $((TOTAL_TESTS / CONCURRENT_TESTS))); do
      echo -n "Batch $batch/$((TOTAL_TESTS / CONCURRENT_TESTS)): "

      # Start concurrent tests
      for i in $(seq 1 $CONCURRENT_TESTS); do
        test_id=$(((batch - 1) * CONCURRENT_TESTS + i))
        run_test $test_id &
      done

      # Wait for batch to complete
      wait
      echo "✅ Completed"
    done

    # Calculate statistics
    echo ""
    echo "📊 Performance Results:"
    echo "======================"

    # Collect all timing data
    times=()
    for i in $(seq 1 $TOTAL_TESTS); do
      if [ -f /tmp/perf_time_${i}.txt ]; then
        times+=($(cat /tmp/perf_time_${i}.txt))
      fi
    done

    # Calculate statistics using awk
    if [ ${#times[@]} -gt 0 ]; then
      printf '%s\n' "${times[@]}" | awk '
      {
        sum += $1
        sumsq += $1^2
        times[NR] = $1
      }
      END {
        mean = sum / NR
        variance = (sumsq - sum^2/NR) / (NR-1)
        stddev = sqrt(variance)

        # Sort for percentiles
        asort(times)

        p50 = times[int(NR * 0.5)]
        p95 = times[int(NR * 0.95)]
        p99 = times[int(NR * 0.99)]

        printf "Total requests: %d\n", NR
        printf "Mean response time: %.2f ms\n", mean
        printf "Standard deviation: %.2f ms\n", stddev
        printf "Min response time: %.2f ms\n", times[1]
        printf "Max response time: %.2f ms\n", times[NR]
        printf "50th percentile (median): %.2f ms\n", p50
        printf "95th percentile: %.2f ms\n", p95
        printf "99th percentile: %.2f ms\n", p99
      }'
    fi

    # Cleanup
    rm -f /tmp/perf_result_*.json /tmp/perf_time_*.txt

    echo ""
    echo "✅ Performance benchmarking completed!"
    EOF

    chmod +x performance_test.sh
    ./performance_test.sh

### Configuration Management

    # Export all configuration for backup
    create_config_backup() {
      local backup_dir="backup_$(date +%Y%m%d_%H%M%S)"
      mkdir -p "$backup_dir"

      echo "📦 Creating configuration backup in $backup_dir..."

      # Systems Manager parameters
      aws ssm get-parameters-by-path \
        --path "/bgp-security/" \
        --recursive \
        --with-decryption \
        --output json > "$backup_dir/ssm_parameters.json"

      # Lambda function configuration
      aws lambda get-function \
        --function-name $LAMBDA_FUNCTION_NAME \
        --output json > "$backup_dir/lambda_function.json"

      # IAM role and policies
      aws iam get-role \
        --role-name $IAM_ROLE_NAME \
        --output json > "$backup_dir/iam_role.json"

      aws iam list-attached-role-policies \
        --role-name $IAM_ROLE_NAME \
        --output json > "$backup_dir/iam_attached_policies.json"

      # CloudWatch alarms
      aws cloudwatch describe-alarms \
        --alarm-name-prefix "BGP-" \
        --output json > "$backup_dir/cloudwatch_alarms.json"

      # Dashboard configuration
      aws cloudwatch get-dashboard \
        --dashboard-name "BGP-Security-Monitoring" \
        --output json > "$backup_dir/dashboard.json" 2>/dev/null || echo "No dashboard found"

      echo "✅ Backup created: $backup_dir"
    }

    # Update configuration from environment
    update_config_from_env() {
      echo "🔧 Updating configuration from environment variables..."

      # Update Systems Manager parameters from environment
      if [ ! -z "$BGP_MALICIOUS_ASNS" ]; then
        aws ssm put-parameter \
          --name "/bgp-security/malicious-asns" \
          --value "$BGP_MALICIOUS_ASNS" \
          --type "StringList" \
          --overwrite
        echo "Updated malicious ASNs"
      fi

      if [ ! -z "$BGP_MAX_PATH_LENGTH" ]; then
        aws ssm put-parameter \
          --name "/bgp-security/max-as-path-length" \
          --value "$BGP_MAX_PATH_LENGTH" \
          --type "String" \
          --overwrite
        echo "Updated max AS path length"
      fi

      echo "✅ Configuration update completed"
    }

    # Validate configuration consistency
    validate_config() {
      echo "🔍 Validating configuration consistency..."

      # Check that all required parameters exist
      required_params=(
        "/bgp-security/malicious-asns"
        "/bgp-security/rpki-validator-url"
        "/bgp-security/max-as-path-length"
        "/bgp-security/scoring-weights"
        "/bgp-security/threat-thresholds"
      )

      missing_params=()
      for param in "${required_params[@]}"; do
        if ! aws ssm get-parameter --name "$param" >/dev/null 2>&1; then
          missing_params+=("$param")
        fi
      done

      if [ ${#missing_params[@]} -eq 0 ]; then
        echo "✅ All required parameters present"
      else
        echo "❌ Missing parameters:"
        printf '  - %s\n' "${missing_params[@]}"
      fi

      # Validate JSON parameters
      json_params=(
        "/bgp-security/scoring-weights"
        "/bgp-security/threat-thresholds"
      )

      for param in "${json_params[@]}"; do
        value=$(aws ssm get-parameter --name "$param" --query 'Parameter.Value' --output text 2>/dev/null)
        if echo "$value" | jq . >/dev/null 2>&1; then
          echo "✅ $param: Valid JSON"
        else
          echo "❌ $param: Invalid JSON"
        fi
      done
    }

    # Execute configuration functions (manual as needed)
    # create_config_backup
    # validate_config

### Monitoring and Alerting Automation

    # Create comprehensive monitoring setup
    setup_advanced_monitoring() {
      echo "📊 Setting up advanced monitoring..."

      # Create SNS topic for alerts
      TOPIC_ARN=$(aws sns create-topic \
        --name "bgp-security-alerts" \
        --output text --query 'TopicArn')

      echo "Created SNS topic: $TOPIC_ARN"

      # Subscribe email to topic (replace with your email)
      # aws sns subscribe \
      #   --topic-arn "$TOPIC_ARN" \
      #   --protocol email \
      #   --notification-endpoint "your-email@example.com"

      # Create comprehensive alarms
      alarm_configs=(
        "BGP-Critical-Threat-Detected:ThreatDetectionCount:critical:GreaterThanOrEqualToThreshold:1:1"
        "BGP-High-Threat-Volume:ThreatDetectionCount:high:GreaterThanThreshold:5:2"
        "BGP-Security-Score-Critical:SecurityScore::LessThanThreshold:25:3"
        "BGP-Validation-Errors:ValidationCount:error:GreaterThanThreshold:3:2"
        "BGP-Lambda-High-Duration:Duration::GreaterThanThreshold:10000:3"
        "BGP-Lambda-Error-Rate:Errors::GreaterThanThreshold:5:2"
      )

      for config in "${alarm_configs[@]}"; do
        IFS=':' read -r name metric dimension operator threshold periods <<< "$config"

        # Build dimensions array
        if [ ! -z "$dimension" ]; then
          dimensions="[{\"Name\":\"ThreatLevel\",\"Value\":\"$dimension\"}]"
        else
          dimensions="[]"
        fi

        # Determine namespace
        if [[ "$metric" == "Duration" || "$metric" == "Errors" ]]; then
          namespace="AWS/Lambda"
          if [ -z "$dimension" ]; then
            dimensions="[{\"Name\":\"FunctionName\",\"Value\":\"$LAMBDA_FUNCTION_NAME\"}]"
          fi
        else
          namespace="BGP/Security"
        fi

        # Create alarm
        aws cloudwatch put-metric-alarm \
          --alarm-name "$name" \
          --alarm-description "Automated alarm for $metric" \
          --metric-name "$metric" \
          --namespace "$namespace" \
          --statistic Sum \
          --period 300 \
          --threshold "$threshold" \
          --comparison-operator "$operator" \
          --evaluation-periods "$periods" \
          --alarm-actions "$TOPIC_ARN" \
          --dimensions "$dimensions"

        echo "Created alarm: $name"
      done

      echo "✅ Advanced monitoring setup completed"
    }

    # Create custom dashboard with all metrics
    create_comprehensive_dashboard() {
      echo "📊 Creating comprehensive dashboard..."

      cat > comprehensive_dashboard.json << 'EOF'
    {
      "widgets": [
        {
          "type": "metric",
          "x": 0, "y": 0, "width": 6, "height": 6,
          "properties": {
            "metrics": [["BGP/Security", "SecurityScore"]],
            "view": "singleValue",
            "region": "us-east-1",
            "title": "🛡️ Security Score",
            "period": 300,
            "stat": "Average"
          }
        },
        {
          "type": "metric",
          "x": 6, "y": 0, "width": 6, "height": 6,
          "properties": {
            "metrics": [
              ["BGP/Security", "ThreatDetectionCount", "ThreatLevel", "critical"],
              [".", ".", ".", "high"],
              [".", ".", ".", "medium"],
              [".", ".", ".", "low"]
            ],
            "view": "pie",
            "region": "us-east-1",
            "title": "🚨 Threat Distribution",
            "period": 3600,
            "stat": "Sum"
          }
        },
        {
          "type": "metric",
          "x": 12, "y": 0, "width": 12, "height": 6,
          "properties": {
            "metrics": [["BGP/Security", "SecurityScore"]],
            "view": "timeSeries",
            "region": "us-east-1",
            "title": "📈 Security Score Timeline",
            "period": 300,
            "stat": "Average",
            "yAxis": {"left": {"min": 0, "max": 100}}
          }
        },
        {
          "type": "metric",
          "x": 0, "y": 6, "width": 12, "height": 6,
          "properties": {
            "metrics": [
              ["AWS/Lambda", "Duration", "FunctionName", "bgp-validator"],
              [".", "Invocations", ".", "."],
              [".", "Errors", ".", "."]
            ],
            "view": "timeSeries",
            "region": "us-east-1",
            "title": "⚡ Lambda Performance",
            "period": 300,
            "stat": "Average"
          }
        },
        {
          "type": "log",
          "x": 12, "y": 6, "width": 12, "height": 6,
          "properties": {
            "query": "SOURCE '/aws/lambda/bgp-validator'\n| fields @timestamp, @message\n| filter @message like /validation completed/\n| sort @timestamp desc\n| limit 20",
            "region": "us-east-1",
            "title": "📋 Recent Validations"
          }
        }
      ]
    }
    EOF

      aws cloudwatch put-dashboard \
        --dashboard-name "BGP-Security-Comprehensive" \
        --dashboard-body file://comprehensive_dashboard.json

      echo "✅ Comprehensive dashboard created"
    }

    # setup_advanced_monitoring
    # create_comprehensive_dashboard

---

## 🚀 Deployment Automation

### Complete Deployment Script (deploy_complete.sh)

    # Create complete deployment script
    cat > deploy_complete.sh << 'EOF'
    #!/bin/bash

    set -e  # Exit on any error

    # Load configuration
    source project-config.env

    echo "🚀 BGP Security Complete Deployment"
    echo "===================================="
    echo "Project: $PROJECT_NAME"
    echo "Region: $AWS_REGION"
    echo "Account: $ACCOUNT_ID"
    echo ""

    # Step 1: IAM Setup
    echo "👤 Setting up IAM roles and policies..."
    if ! aws iam get-role --role-name $IAM_ROLE_NAME >/dev/null 2>&1; then
      # Create trust policy
      cat > /tmp/lambda-trust-policy.json << 'EOFTRUST'
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": {"Service": "lambda.amazonaws.com"},
          "Action": "sts:AssumeRole"
        }
      ]
    }
    EOFTRUST

      # Create role
      aws iam create-role \
        --role-name $IAM_ROLE_NAME \
        --assume-role-policy-document file:///tmp/lambda-trust-policy.json

      # Attach policies
      aws iam attach-role-policy \
        --role-name $IAM_ROLE_NAME \
        --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

      aws iam attach-role-policy \
        --role-name $IAM_ROLE_NAME \
        --policy-arn arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess

      aws iam attach-role-policy \
        --role-name $IAM_ROLE_NAME \
        --policy-arn arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy

      echo "✅ IAM role created and configured"
    else
      echo "✅ IAM role already exists"
    fi

    # Step 2: Systems Manager Parameters
    echo "🔧 Setting up Systems Manager parameters..."
    parameters=(
      "/bgp-security/malicious-asns:666,1337,31337,65666:StringList"
      "/bgp-security/rpki-validator-url:https://rpki-validator.cloudflare.com/api/v1/origin:String"
      "/bgp-security/max-as-path-length:20:String"
      '/bgp-security/scoring-weights:{"as_path":0.4,"rpki":0.4,"prefix":0.15,"geography":0.05}:String'
      '/bgp-security/threat-thresholds:{"low":90,"medium":75,"high":50,"critical":0}:String'
    )

    for param_config in "${parameters[@]}"; do
      IFS=':' read -r name value type <<< "$param_config"
      aws ssm put-parameter \
        --name "$name" \
        --value "$value" \
        --type "$type" \
        --overwrite >/dev/null
      echo "✅ Created parameter: $name"
    done

    # Step 3: Lambda Function
    echo "⚡ Deploying Lambda function..."
    if [ ! -f lambda/bgp-validator.zip ]; then
      echo "❌ Lambda deployment package not found: lambda/bgp-validator.zip"
      echo "Please create the deployment package first"
      exit 1
    fi

    # Wait for IAM role to propagate
    echo "Waiting for IAM role propagation..."
    sleep 10

    # Deploy or update Lambda function
    if aws lambda get-function --function-name $LAMBDA_FUNCTION_NAME >/dev/null 2>&1; then
      echo "Updating existing Lambda function..."
      aws lambda update-function-code \
        --function-name $LAMBDA_FUNCTION_NAME \
        --zip-file fileb://lambda/bgp-validator.zip >/dev/null
    else
      echo "Creating new Lambda function..."
      aws lambda create-function \
        --function-name $LAMBDA_FUNCTION_NAME \
        --runtime python3.9 \
        --role "arn:aws:iam::$ACCOUNT_ID:role/$IAM_ROLE_NAME" \
        --handler bgp_with_ssm.lambda_handler \
        --zip-file fileb://lambda/bgp-validator.zip \
        --timeout 60 \
        --memory-size 512 \
        --description "BGP Security Route Validator" >/dev/null
    fi

    # Wait for function to be active
    aws lambda wait function-active --function-name $LAMBDA_FUNCTION_NAME
    echo "✅ Lambda function deployed and active"

    # Step 4: Test Deployment
    echo "🧪 Testing deployment..."
    test_result=$(aws lambda invoke \
      --cli-binary-format raw-in-base64-out \
      --function-name $LAMBDA_FUNCTION_NAME \
      --payload '{"prefix":"8.8.8.0/24","origin_as":15169,"as_path":[64512,15169]}' \
      /tmp/deployment_test.json 2>&1)

    if [ $? -eq 0 ] && [ -f /tmp/deployment_test.json ]; then
      body=$(cat /tmp/deployment_test.json | jq -r '.body')
      status=$(echo "$body" | jq -r '.validation_status // "error"')
      if [ "$status" = "passed" ]; then
        echo "✅ Deployment test passed"
      else
        echo "⚠️  Deployment test completed but validation status: $status"
      fi
    else
      echo "❌ Deployment test failed"
      echo "$test_result"
    fi

    # Step 5: Create Monitoring
    echo "📊 Setting up monitoring..."
    aws cloudwatch put-metric-alarm \
      --alarm-name "BGP-Critical-Threat-Detected" \
      --alarm-description "Critical BGP threats detected" \
      --metric-name ValidationCount \
      --namespace "BGP/Security" \
      --statistic Sum \
      --period 300 \
      --threshold 1 \
      --comparison-operator GreaterThanOrEqualToThreshold \
      --dimensions Name=ThreatLevel,Value=critical \
      --evaluation-periods 1 >/dev/null

    echo "✅ Basic monitoring configured"

    # Cleanup
    rm -f /tmp/lambda-trust-policy.json /tmp/deployment_test.json

    echo ""
    echo "🎉 BGP Security Deployment Complete!"
    echo "===================================="
    echo "Lambda Function: $LAMBDA_FUNCTION_NAME"
    echo "Region: $AWS_REGION"
    echo "Dashboard: https://$AWS_REGION.console.aws.amazon.com/cloudwatch/home?region=$AWS_REGION#dashboards:"
    echo ""
    echo "Next steps:"
    echo "1. Create CloudWatch dashboard"
    echo "2. Set up SNS notifications"
    echo "3. Configure additional monitoring"
    echo "4. Test with various BGP scenarios"
    EOF

    chmod +x deploy_complete.sh
    # ./deploy_complete.sh

---

## 📚 Project Lifecycle & Most Used Commands

### Project Lifecycle Commands

    # Complete project setup
    source project-config.env && ./deploy_complete.sh

    # Daily operations
    ./run_tests.sh && aws logs tail "/aws/lambda/$LAMBDA_FUNCTION_NAME" --follow

    # Performance monitoring
    ./performance_test.sh

    # Configuration management
    validate_config && create_config_backup

    # Emergency procedures
    aws lambda put-reserved-concurrency-settings --function-name $LAMBDA_FUNCTION_NAME --reserved-concurrency-limit 0

    # Complete cleanup
    ./cleanup.sh

### Most Used Commands

    # Quick test
    aws lambda invoke \
      --cli-binary-format raw-in-base64-out \
      --function-name $LAMBDA_FUNCTION_NAME \
      --payload '{"prefix":"8.8.8.0/24","origin_as":666,"as_path":[666]}' \
      /tmp/quick_test.json && cat /tmp/quick_test.json | jq '.body | fromjson'

    # Check logs
    aws logs filter-log-events \
      --log-group-name "/aws/lambda/$LAMBDA_FUNCTION_NAME" \
      --start-time $(date -d '10 minutes ago' +%s)000 \
      --limit 5

    # Update configuration
    aws ssm put-parameter \
      --name "/bgp-security/malicious-asns" \
      --value "666,1337,31337,65666,13335" \
      --type "StringList" \
      --overwrite

    # Monitor performance
    aws cloudwatch get-metric-statistics \
      --namespace "AWS/Lambda" \
      --metric-name Duration \
      --dimensions Name=FunctionName,Value=$LAMBDA_FUNCTION_NAME \
      --start-time $(date -d '1 hour ago' --iso-8601) \
      --end-time $(date --iso-8601) \
      --period 300 \
      --statistics Average

---

## 🌐 BGP Reference & Multi-Cloud Notes

These notes summarize key concepts from your **BGP + Direct Connect** and **multi-cloud BGP** reference material.

### ASN & Prefix Basics

- **ASN (Autonomous System Number)** identifies a routing domain.
- Public ASNs are globally unique; private ASNs (64512–65534, 4200000000–4294967294) are used internally.
- Origin AS is the **last AS** in the AS_PATH and is what your validator checks against the malicious AS list.
- BGP makes decisions based on:
  - Local preference
  - AS path length
  - Origin type
  - MED
  - eBGP vs iBGP
  - Router ID / tie breakers

### Direct Connect BGP Operational Best Practices

- Always use **MD5 authentication** with a strong password for BGP sessions to AWS.
- Keep **timers** consistent (e.g., keepalive 30s, hold 90s) unless a specific SLA requires otherwise.
- Advertise **only approved prefixes** (e.g., specific RFC1918 ranges).
- Use **prefix-lists** and **route-maps** to:
  - Filter inbound routes from AWS.
  - Prevent route leaks back to the internet.
  - Implement security and compliance policies at the edge.

### Multi-Cloud BGP Principles (AWS / Azure / GCP)

- **AWS**:
  - Uses BGP on VPN and Direct Connect (DX).
  - Transit Gateway aggregates VPCs; BGP peers sit on VPN or DX attachments.
  - Route selection heavily influenced by local preference and AS_PATH.

- **Azure**:
  - ExpressRoute uses private peering with BGP.
  - Azure VPN Gateways also use BGP for dynamic routing with on-prem devices.
  - Similar patterns: advertise specific VNet ranges, filter on-premises prefixes.

- **GCP**:
  - Cloud Interconnect with BGP for private connections.
  - Cloud VPN with BGP (HA VPN) for dynamic routing.
  - Prefix advertisement is explicit and controlled via custom route exports/imports.

### Multi-Cloud Operational Best Practices

- Use a **consistent ASN strategy** across clouds (e.g., one ASN per region or per cloud edge).
- Enforce **prefix filtering** on every BGP session:
  - Only allow expected RFC1918 / site-local ranges.
  - Prevent accidental advertisement of 0.0.0.0/0 or public routes.
- Configure **max-prefix limits** for each peering to avoid runaway route advertisements.
- Standardize **BGP timers** to reduce troubleshooting complexity.
- Design for **failover**:
  - Dual tunnels / dual peers per cloud.
  - Clear policy for primary vs backup paths (local-pref).
- Align these operational patterns with your **Lambda-based BGP Security Validator** by:
  - Feeding real route samples into the validator.
  - Comparing observed AS paths and origins to the malicious ASN list and scoring model.
  - Using CloudWatch metrics and alarms as a “control-plane” signal for network security posture.

---

This comprehensive Linux commands and reference runbook provides all the AWS CLI commands and operational context needed to deploy, manage, test, monitor, and maintain the **BGP Security project** on AWS, while also grounding it in real-world BGP and multi-cloud routing practices.
