#!/bin/bash

#Script maintained by Erick Ferreira - github @erickrazr

# shellcheck disable=SC2102,SC2181,SC2207

if ! type "aws" > /dev/null; then
  echo "Error: AWS CLI not installed or not in execution path, AWS CLI is required for script execution."
  exit 1
fi

##########################################################################################
## Optionally query the AWS Organization by passing "org" as an argument.
##########################################################################################

if [ "${1}X" == "orgX" ] || [ "${2}X" == "orgX" ] || [ "${3}X" == "orgX" ]; then
   USE_AWS_ORG="true"
else
   USE_AWS_ORG="false"
fi

#### Use epm parameter to report EPM Sizing

if [ "${1}X" == "epmX" ] || [ "${2}X" = "epmX" ] || [ "${3}X" == "epmX" ]; then
   WITH_EPM="true"
else
   WITH_EPM="false"
fi

##########################################################################################
## Utility functions.
##########################################################################################

error_and_exit() {
  echo
  echo "ERROR: ${1}"
  echo
  exit 1
}

##########################################################################################
## AWS Utility functions.
##########################################################################################

print_bold() {
  echo -e "\033[1m${1}\033[0m"
}

aws_ec2_describe_regions() {
  aws ec2 describe-regions --query 'Regions[*].RegionName' --output text 2>/dev/null | sort
}

####

aws_get_organization_payer_account_id() {
  aws organizations describe-organization --query 'Organization.MasterAccountId' --output text 2>/dev/null
}

aws_organizations_list_accounts() {
  aws organizations list-accounts --query 'Accounts[*].[Name,Id]' --output text 2>/dev/null
}

aws_sts_assume_role() {
  aws sts assume-role \
    --role-arn "${1}" \
    --role-session-name pcs-sizing-script \
    --duration-seconds 999 \
    --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
    --output text 2>/dev/null
}

####### Begin --- Microsoft CSPM Premium Billable Resources  Methods #####

aws_count_ec2_instances() {
  aws ec2 describe-instances \
    --region "${1}" \
    --max-items 99999 \
    --filters 'Name=instance-state-name,Values=running' \
    --query 'Reservations[*].Instances[*].InstanceId' \
    --output text 2>/dev/null | wc -w
}

aws_count_rds_instances() {
  aws rds describe-db-instances \
    --region "${1}" \
    --max-items 99999 \
    --query 'DBInstances[*].DBInstanceIdentifier' \
    --output text 2>/dev/null | wc -w
}

aws_count_s3_buckets() {
  aws s3api list-buckets \
    --query 'Buckets[*].Name' \
    --output text | wc -w 2>/dev/null
}

####### END --- Microsoft CSPM Premium Billable Resources  Methods #####

####### BEGIN --- Microsoft Entra Permissions Management Methods #####

aws_count_lambda_functions() {
  aws lambda list-functions \
    --region "${1}" \
    --query 'Functions[*].FunctionName' \
    --output text 2>/dev/null | wc -w
}

aws_count_eks_clusters() {
  aws eks list-clusters \
    --region "${1}" \
    --max-items 99999 \
    --query 'clusters[*]' \
    --output text 2>/dev/null | wc -w
}

aws_count_ecs_clusters() {
  aws ecs list-clusters \
  --region "${1}" \
  --max-items 99999 \
  --query 'clusterArns[*]' \
  --output text 2>/dev/null | wc -w
}

aws_count_dynamodb_tables() {
  aws dynamodb list-tables \
    --region "${1}" \
    --query 'TableNames[*]' \
    --output text 2>/dev/null | wc -w
}

aws_count_emr_clusters() {
  aws emr list-clusters \
    --region "${1}" \
    --active \
    --query 'Clusters[*].Id' \
    --output text 2>/dev/null | wc -w
}

aws_count_kinesis_streams() {
  aws kinesis list-streams \
    --region "${1}" \
    --query 'StreamNames[*]' \
    --output text 2>/dev/null | wc -w
}

aws_count_elasticache_clusters() {
  aws elasticache describe-cache-clusters \
    --region "${1}" \
    --query 'CacheClusters[*].CacheClusterId' \
    --output text 2>/dev/null | wc -w
}

####### End --- Microsoft Entra Permissions Management Methods #####


####

get_region_list() {
  echo "Querying AWS Regions"
  REGIONS=$(aws_ec2_describe_regions) || error_and_exit "Failed to get region list"
  REGION_LIST=(${REGIONS})

  if [ ${#REGION_LIST[@]} -eq 0 ]; then
    error_and_exit "No regions found. Exiting."
  fi

  echo "Total number of regions: ${#REGION_LIST[@]}"
}

get_account_list() {
 if [ "$USE_AWS_ORG" = "true" ]; then
    echo "Querying AWS Organization"
    MASTER_ACCOUNT_ID=$(aws_get_organization_payer_account_id) || error_and_exit "Failed to describe AWS Organization"
    MASTER_AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID
    MASTER_AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY
    MASTER_AWS_SESSION_TOKEN=$AWS_SESSION_TOKEN

    ACCOUNT_LIST=$(aws_organizations_list_accounts) || error_and_exit "Failed to list AWS Organization accounts"
    TOTAL_ACCOUNTS=$(echo "${ACCOUNT_LIST}" | wc -l 2>/dev/null)
    echo "Total number of member accounts: ${TOTAL_ACCOUNTS}"
  else
    MASTER_ACCOUNT_ID=""
    ACCOUNT_LIST=""
    TOTAL_ACCOUNTS=1
  fi
}

assume_role() {
  ACCOUNT_NAME="${1}"
  ACCOUNT_ID="${2}"
  echo ""
  print_bold "###################################################################################"
  echo "Processing Account: $(print_bold "${ACCOUNT_NAME} (${ACCOUNT_ID}"))"
  if [ "${ACCOUNT_ID}" = "${MASTER_ACCOUNT_ID}" ]; then
    echo "  Account is the master account, skipping assume role ..."
    print_bold "###################################################################################"
    return
  fi

  ROLES=("OrganizationAccountAccessRole" "AWSControlTowerExecution")
  for ROLE in "${ROLES[@]}"; do
    ACCOUNT_ASSUME_ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE}"
    SESSION_DATA=$(aws_sts_assume_role "${ACCOUNT_ASSUME_ROLE_ARN}")
    
    if [ $? -eq 0 ] && [ -n "${SESSION_DATA}" ]; then
      echo "  Successfully assumed role: ${ROLE}"

      # Exportar as credenciais da role assumida
      AWS_ACCESS_KEY_ID=$(echo "${SESSION_DATA}" | cut -f1)
      AWS_SECRET_ACCESS_KEY=$(echo "${SESSION_DATA}" | cut -f2)
      AWS_SESSION_TOKEN=$(echo "${SESSION_DATA}" | cut -f3)
      export AWS_ACCESS_KEY_ID
      export AWS_SECRET_ACCESS_KEY
      export AWS_SESSION_TOKEN

      print_bold "###################################################################################"
      return
    else
      echo "  Warning: Failed to assume role ${ROLE} into Member Account ${ACCOUNT_NAME} (${ACCOUNT_ID})"
    fi
  done

  echo "  Error: Failed to assume any role into Member Account ${ACCOUNT_NAME} (${ACCOUNT_ID}), skipping ..."
  print_bold "###################################################################################"
}

##########################################################################################
# Unset environment variables used to assume role into the last member account.
##########################################################################################

unassume_role() {
  AWS_ACCESS_KEY_ID=$MASTER_AWS_ACCESS_KEY_ID
  AWS_SECRET_ACCESS_KEY=$MASTER_AWS_SECRET_ACCESS_KEY
  AWS_SESSION_TOKEN=$MASTER_AWS_SESSION_TOKEN
}

##########################################################################################
## Set or reset counters.
##########################################################################################

reset_account_counters() {
  EC2_INSTANCE_COUNT=0
  RDS_INSTANCE_COUNT=0
  S3_BUCKET_COUNT=0
  LAMBDA_FUNCTION_COUNT=0
  EKS_CLUSTER_COUNT=0
  ECS_CLUSTER_COUNT=0
  DYNAMODB_TABLE_COUNT=0
  EMR_CLUSTER_COUNT=0
  KINESIS_STREAM_COUNT=0
  ELASTICACHE_CLUSTER_COUNT=0
}

reset_global_counters() {
  EC2_INSTANCE_COUNT_GLOBAL=0
  RDS_INSTANCE_COUNT_GLOBAL=0
  S3_BUCKET_COUNT_GLOBAL=0
  LAMBDA_FUNCTION_COUNT_GLOBAL=0
  EKS_CLUSTER_COUNT_GLOBAL=0
  ECS_CLUSTER_COUNT_GLOBAL=0
  DYNAMODB_TABLE_COUNT_GLOBAL=0
  EMR_CLUSTER_COUNT_GLOBAL=0
  KINESIS_STREAM_COUNT_GLOBAL=0
  ELASTICACHE_CLUSTER_COUNT_GLOBAL=0
}

##########################################################################################
## Iterate through the (or each member) account, region, and billable resource type.
##########################################################################################

count_account_resources() {
  for ((ACCOUNT_INDEX=0; ACCOUNT_INDEX<=(TOTAL_ACCOUNTS-1); ACCOUNT_INDEX++))
  do
    if [ "${USE_AWS_ORG}" = "true" ]; then
      ACCOUNT_NAME=$(echo "${ACCOUNT_LIST}" | awk "NR==$((ACCOUNT_INDEX+1)) {print \$1}" 2>/dev/null)
      ACCOUNT_ID=$(echo "${ACCOUNT_LIST}" | awk "NR==$((ACCOUNT_INDEX+1)) {print \$2}" 2>/dev/null)
      ASSUME_ROLE_ERROR=""
      assume_role "${ACCOUNT_NAME}" "${ACCOUNT_ID}"
      if [ -n "${ASSUME_ROLE_ERROR}" ]; then
        continue
      fi
    fi

    echo ""
    echo "-----------------------------------------------------------------------------------"
    echo "EC2 Instances (running)"
    for region in "${REGION_LIST[@]}"
    do
      RESOURCE_COUNT=$(aws_count_ec2_instances "${region}")
      echo "  EC2 Instances (running) in region ${region}: ${RESOURCE_COUNT}"
      EC2_INSTANCE_COUNT=$((EC2_INSTANCE_COUNT + RESOURCE_COUNT))
    done
    echo "Total EC2 Instances (running) on all regions: ${EC2_INSTANCE_COUNT}"
    echo "-----------------------------------------------------------------------------------"

    echo ""
    echo "-----------------------------------------------------------------------------------"
    echo "RDS Instances"
    for region in "${REGION_LIST[@]}"
    do
      RESOURCE_COUNT=$(aws_count_rds_instances "${region}")
      echo "  RDS Instances in region ${region}: ${RESOURCE_COUNT}"
      RDS_INSTANCE_COUNT=$((RDS_INSTANCE_COUNT + RESOURCE_COUNT))
    done
    echo "Total RDS Instances on all regions: ${RDS_INSTANCE_COUNT}"
    echo "-----------------------------------------------------------------------------------"

    echo ""
    echo "-----------------------------------------------------------------------------------"
    echo "S3 Buckets"
    S3_BUCKET_COUNT=$(aws_count_s3_buckets)
    echo "Total S3 Buckets on all regions: ${S3_BUCKET_COUNT}"
    echo "-----------------------------------------------------------------------------------"

    if [ "${WITH_EPM}" = "true" ]; then

      echo ""
      echo "-----------------------------------------------------------------------------------"
      echo "Lambda Functions"
      for region in "${REGION_LIST[@]}"
      do
        RESOURCE_COUNT=$(aws_count_lambda_functions "${region}")
        echo "  Lambda Functions in region ${region}: ${RESOURCE_COUNT}"
        LAMBDA_FUNCTION_COUNT=$((LAMBDA_FUNCTION_COUNT + RESOURCE_COUNT))
      done
      echo "Total Lambda Functions on all regions: ${LAMBDA_FUNCTION_COUNT}"
      echo "-----------------------------------------------------------------------------------"

      echo ""
      echo "-----------------------------------------------------------------------------------"
      echo "EKS Clusters"
      for region in "${REGION_LIST[@]}"
      do
        RESOURCE_COUNT=$(aws_count_eks_clusters "${region}")
        echo "  EKS Clusters in region ${region}: ${RESOURCE_COUNT}"
        EKS_CLUSTER_COUNT=$((EKS_CLUSTER_COUNT + RESOURCE_COUNT))
      done
      echo "Total EKS Clusters on all regions: ${EKS_CLUSTER_COUNT}"
      echo "-----------------------------------------------------------------------------------"

      echo ""
      echo "-----------------------------------------------------------------------------------"
      echo "ECS Clusters"
      for region in "${REGION_LIST[@]}"
      do
        RESOURCE_COUNT=$(aws_count_ecs_clusters "${region}")
        echo "  ECS Clusters in region ${region}: ${RESOURCE_COUNT}"
        ECS_CLUSTER_COUNT=$((ECS_CLUSTER_COUNT + RESOURCE_COUNT))
      done
      echo "Total ECS Clusters on all regions: ${ECS_CLUSTER_COUNT}"
      echo "-----------------------------------------------------------------------------------"

      echo ""
      echo "-----------------------------------------------------------------------------------"
      echo "DynamoDB Tables"
      for region in "${REGION_LIST[@]}"
      do
        RESOURCE_COUNT=$(aws_count_dynamodb_tables "${region}")
        echo "  DynamoDB Tables in region ${region}: ${RESOURCE_COUNT}"
        DYNAMODB_TABLE_COUNT=$((DYNAMODB_TABLE_COUNT + RESOURCE_COUNT))
      done
      echo "Total DynamoDB Tables on all regions: ${DYNAMODB_TABLE_COUNT}"
      echo "-----------------------------------------------------------------------------------"

      echo ""
      echo "-----------------------------------------------------------------------------------"
      echo "EMR Clusters"
      for region in "${REGION_LIST[@]}"
      do
        RESOURCE_COUNT=$(aws_count_emr_clusters "${region}")
        echo "  EMR Clusters in region ${region}: ${RESOURCE_COUNT}"
        EMR_CLUSTER_COUNT=$((EMR_CLUSTER_COUNT + RESOURCE_COUNT))
      done
      echo "Total EBR Clusters on all regions: ${EMR_CLUSTER_COUNT}"
      echo "-----------------------------------------------------------------------------------"

      echo ""
      echo "-----------------------------------------------------------------------------------"
      echo "Kinesis Streams"
      for region in "${REGION_LIST[@]}"
      do
        RESOURCE_COUNT=$(aws_count_kinesis_streams "${region}")
        echo "  Kinesis Streams in region ${region}: ${RESOURCE_COUNT}"
        KINESIS_STREAM_COUNT=$((KINESIS_STREAM_COUNT + RESOURCE_COUNT))
      done
      echo "Total Kinesis Streams on all regions: ${KINESIS_STREAM_COUNT}"
      echo "-----------------------------------------------------------------------------------"

      echo ""
      echo "-----------------------------------------------------------------------------------"
      echo "ElastiCache Clusters"
      for region in "${REGION_LIST[@]}"
      do
        RESOURCE_COUNT=$(aws_count_elasticache_clusters "${region}")
        echo "  Elasticache Clusters in Region ${region}: ${RESOURCE_COUNT}"
        ELASTICACHE_CLUSTER_COUNT=$((ELASTICACHE_CLUSTER_COUNT + RESOURCE_COUNT))
      done
      echo "Total ElastiCache Clusters on all regions: ${ELASTICACHE_CLUSTER_COUNT}"
      echo "-----------------------------------------------------------------------------------"

    fi

    EC2_INSTANCE_COUNT_GLOBAL=$((EC2_INSTANCE_COUNT_GLOBAL + EC2_INSTANCE_COUNT))
    RDS_INSTANCE_COUNT_GLOBAL=$((RDS_INSTANCE_COUNT_GLOBAL + RDS_INSTANCE_COUNT))
    S3_BUCKET_COUNT_GLOBAL=$((S3_BUCKET_COUNT_GLOBAL + S3_BUCKET_COUNT))
    LAMBDA_FUNCTION_COUNT_GLOBAL=$((LAMBDA_FUNCTION_COUNT_GLOBAL + LAMBDA_FUNCTION_COUNT))
    EKS_CLUSTER_COUNT_GLOBAL=$((EKS_CLUSTER_COUNT_GLOBAL + EKS_CLUSTER_COUNT))
    ECS_CLUSTER_COUNT_GLOBAL=$((ECS_CLUSTER_COUNT_GLOBAL + ECS_CLUSTER_COUNT))
    DYNAMODB_TABLE_COUNT_GLOBAL=$((DYNAMODB_TABLE_COUNT_GLOBAL + DYNAMODB_TABLE_COUNT))
    EMR_CLUSTER_COUNT_GLOBAL=$((EMR_CLUSTER_COUNT_GLOBAL + EMR_CLUSTER_COUNT))
    KINESIS_STREAM_COUNT_GLOBAL=$((KINESIS_STREAM_COUNT_GLOBAL + KINESIS_STREAM_COUNT))
    ELASTICACHE_CLUSTER_COUNT_GLOBAL=$((ELASTICACHE_CLUSTER_COUNT_GLOBAL + ELASTICACHE_CLUSTER_COUNT))

    reset_account_counters

    if [ "${USE_AWS_ORG}" = "true" ]; then
      unassume_role
    fi
  done
  
  EPM_COUNT_GLOBAL=$((EC2_INSTANCE_COUNT_GLOBAL + RDS_INSTANCE_COUNT_GLOBAL + LAMBDA_FUNCTION_COUNT_GLOBAL + EKS_CLUSTER_COUNT_GLOBAL + ECS_CLUSTER_COUNT_GLOBAL + DYNAMODB_TABLE_COUNT_GLOBAL + EMR_CLUSTER_COUNT_GLOBAL + ELASTICACHE_CLUSTER_COUNT_GLOBAL + KINESIS_STREAM_COUNT_GLOBAL + S3_BUCKET_COUNT_GLOBAL))
  DCSPM_COUNT_GLOBAL=$((EC2_INSTANCE_COUNT_GLOBAL + RDS_INSTANCE_COUNT_GLOBAL + S3_BUCKET_COUNT_GLOBAL))
  
  echo ""
  echo "###################################################################################"
  echo "List of Microsoft Defender CSPM Billable Resources"
  echo "  Total EC2 Instances: ${EC2_INSTANCE_COUNT_GLOBAL}"
  echo "  Total RDS Instances: ${RDS_INSTANCE_COUNT_GLOBAL}"
  echo "  Total S3 Buckets:    ${S3_BUCKET_COUNT_GLOBAL}"
  echo ""
  echo "Total DCSPM Resources: ${DCSPM_COUNT_GLOBAL}"
  echo "###################################################################################"

  if [ "${WITH_EPM}" = "true" ]; then
    echo ""
    echo "###################################################################################"
    echo "EPM Billable Resources:"
    echo "  Total EC2 Instances: ${EC2_INSTANCE_COUNT_GLOBAL}"
    echo "  Total RDS Instances: ${RDS_INSTANCE_COUNT_GLOBAL}"
    echo "  Total S3 Buckets: ${S3_BUCKET_COUNT_GLOBAL}"
    echo "  Total Lambda Functions: ${LAMBDA_FUNCTION_COUNT_GLOBAL}"
    echo "  Total EKS Clusters: ${EKS_CLUSTER_COUNT_GLOBAL}"
    echo "  Total ECS Clusters: ${ECS_CLUSTER_COUNT_GLOBAL}"
    echo "  Total DynamoDB Tables: ${DYNAMODB_TABLE_COUNT_GLOBAL}"
    echo "  Total EMR Cluster: ${EMR_CLUSTER_COUNT_GLOBAL}"
    echo "  Total Kinesis Streams: ${KINESIS_STREAM_COUNT_GLOBAL}"
    echo "  Total ElastiCache Clusters: ${ELASTICACHE_CLUSTER_COUNT_GLOBAL}"
    echo ""
    echo "Total EPM Resources:   ${EPM_COUNT_GLOBAL}"
    echo "###################################################################################"
  fi

  echo ""
  echo "The script outputs the count of various resources in the AWS environment, giving a detailed view of the resources in each region and account. The totals are based on resource counts at the time of script execution."

}

##########################################################################################
# Allow shellspec to source this script.
##########################################################################################

${__SOURCED__:+return}

##########################################################################################
# Main.
##########################################################################################

get_account_list
get_region_list
reset_account_counters
reset_global_counters
count_account_resources
