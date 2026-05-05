#!/usr/bin/env bash
# landing/deploy.sh — deploy bolyra.ai
#
# bolyra.ai is hosted on S3 + CloudFront (no GitHub auto-deploy).
# This script uploads index.html and invalidates the CDN cache.
#
# Prereq: aws cli authenticated against the account that owns
#   - S3 bucket:           bolyra-ai-landing
#   - CloudFront dist ID:  E28JZX72HEYVTP
#
# Run from repo root:  ./landing/deploy.sh
# Or from landing/:    ./deploy.sh

set -euo pipefail

BUCKET="bolyra-ai-landing"
DISTRIBUTION_ID="E28JZX72HEYVTP"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INDEX="$SCRIPT_DIR/index.html"

if [ ! -f "$INDEX" ]; then
  echo "ERROR: $INDEX not found" >&2
  exit 1
fi

echo "→ uploading index.html to s3://$BUCKET/"
aws s3 cp "$INDEX" "s3://$BUCKET/index.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"

echo "→ invalidating CloudFront ($DISTRIBUTION_ID)"
INVALIDATION_ID=$(aws cloudfront create-invalidation \
  --distribution-id "$DISTRIBUTION_ID" \
  --paths "/index.html" "/" \
  --query 'Invalidation.Id' \
  --output text)

echo "  invalidation id: $INVALIDATION_ID"
echo -n "  waiting for completion"
for _ in $(seq 1 20); do
  STATUS=$(aws cloudfront get-invalidation \
    --distribution-id "$DISTRIBUTION_ID" \
    --id "$INVALIDATION_ID" \
    --query 'Invalidation.Status' \
    --output text 2>/dev/null || echo "Unknown")
  if [ "$STATUS" = "Completed" ]; then
    echo " ✓"
    break
  fi
  echo -n "."
  sleep 10
done

echo "→ live at https://bolyra.ai"
curl -sI https://bolyra.ai | grep -iE "last-modified|etag" || true
