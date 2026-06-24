#!/usr/bin/env bash
# Runs inside the LocalStack container as an init hook (ready.d).
# Creates ONE symmetric KMS master key for KEK envelope encryption.
# HMAC keys are NOT created here — HMAC secrets are encrypted at app level under the KEK
# using AES-256-GCM (LocalStackKeySeeder / LocalStackSeedConfig handle HMAC seeding).
# Writes the KMS key ARN to a shared file so the Makefile can read it when starting the app.
set -euo pipefail

KEY_ARN=$(awslocal kms create-key \
    --region ap-southeast-2 \
    --description "card-tokenisation-kek" \
    --key-usage ENCRYPT_DECRYPT \
    --query 'KeyMetadata.Arn' \
    --output text)

awslocal kms create-alias \
    --region ap-southeast-2 \
    --alias-name "alias/card-tokenisation-kek" \
    --target-key-id "$KEY_ARN"

mkdir -p /tmp/localstack
echo "$KEY_ARN" > /tmp/localstack/kms-key-arn

echo "LocalStack KMS init complete. Key ARN: $KEY_ARN"
