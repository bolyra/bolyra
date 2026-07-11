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
PROTOCOL="$SCRIPT_DIR/402.html"
BLOG="$SCRIPT_DIR/blog.html"
BLOG1="$SCRIPT_DIR/blog-1.html"
BLOG2="$SCRIPT_DIR/blog-2.html"
BLOG3="$SCRIPT_DIR/blog-3.html"
BLOG4="$SCRIPT_DIR/blog-4.html"
BLOG5="$SCRIPT_DIR/blog-5.html"
VIDEO="$SCRIPT_DIR/video.html"
VIDEO2="$SCRIPT_DIR/video-receipts.html"
VIDEO3="$SCRIPT_DIR/video-delegation.html"
VIDEO4="$SCRIPT_DIR/video-handshake.html"
VIDEO5="$SCRIPT_DIR/video-devmode.html"
VIDEO6="$SCRIPT_DIR/video-offchain.html"
VIDEO7="$SCRIPT_DIR/video-frameworks.html"
VIDEO8="$SCRIPT_DIR/video-oauth.html"
PLAYGROUND="$SCRIPT_DIR/playground.html"

for f in "$INDEX" "$PROTOCOL" "$BLOG" "$BLOG1" "$BLOG2" "$BLOG3" "$BLOG4" "$BLOG5" "$VIDEO" "$VIDEO2" "$VIDEO3" "$VIDEO4" "$VIDEO5" "$VIDEO6" "$VIDEO7" "$VIDEO8" "$PLAYGROUND"; do
  if [ ! -f "$f" ]; then
    echo "ERROR: $f not found" >&2
    exit 1
  fi
done

# Pre-upload version drift gate — block stale copy from ever reaching S3.
# (verify.sh re-checks the LIVE page post-deploy; this catches it earlier.)
echo "→ pre-upload version drift gate (local index.html vs npm registry)"
preflight_version() { # $1=pkg  $2=literal prefix the page must show before the version
  local pkg="$1" prefix="$2" published
  published=$(npm view "$pkg" version 2>/dev/null) || { echo "ERROR: npm view $pkg failed — cannot verify advertised versions" >&2; exit 1; }
  if ! grep -qF "${prefix}${published}" "$INDEX"; then
    echo "ERROR: version drift — npm has $pkg@$published but landing/index.html lacks '${prefix}${published}'. Fix the copy before deploying." >&2
    exit 1
  fi
  echo "OK: local page advertises ${prefix}${published} ($pkg)"
}
preflight_version "@bolyra/gateway" "@bolyra/gateway@"
preflight_version "@bolyra/gateway" "npm v"
preflight_version "@bolyra/sdk"     "TS SDK at v"
preflight_version "@bolyra/cli"     "@bolyra/cli@"

echo "→ uploading index.html to s3://$BUCKET/"
aws s3 cp "$INDEX" "s3://$BUCKET/index.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"

echo "→ uploading 402.html to s3://$BUCKET/"
aws s3 cp "$PROTOCOL" "s3://$BUCKET/402.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
# Also publish at /402 (no extension) so bolyra.ai/402 resolves directly.
aws s3 cp "$PROTOCOL" "s3://$BUCKET/402" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"

echo "→ uploading blog.html to s3://$BUCKET/"
aws s3 cp "$BLOG" "s3://$BUCKET/blog.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
aws s3 cp "$BLOG" "s3://$BUCKET/blog" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"

echo "→ uploading blog-1.html to s3://$BUCKET/"
aws s3 cp "$BLOG1" "s3://$BUCKET/blog-1.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
aws s3 cp "$BLOG1" "s3://$BUCKET/blog-1" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"

echo "→ uploading blog-2.html to s3://$BUCKET/"
aws s3 cp "$BLOG2" "s3://$BUCKET/blog-2.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
aws s3 cp "$BLOG2" "s3://$BUCKET/blog-2" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"

echo "→ uploading blog-3.html to s3://$BUCKET/"
aws s3 cp "$BLOG3" "s3://$BUCKET/blog-3.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
aws s3 cp "$BLOG3" "s3://$BUCKET/blog-3" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"

echo "→ uploading blog-4.html to s3://$BUCKET/"
aws s3 cp "$BLOG4" "s3://$BUCKET/blog-4.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
aws s3 cp "$BLOG4" "s3://$BUCKET/blog-4" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"

echo "→ uploading blog-5.html to s3://$BUCKET/"
aws s3 cp "$BLOG5" "s3://$BUCKET/blog-5.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
aws s3 cp "$BLOG5" "s3://$BUCKET/blog-5" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"

for JSXF in animations.jsx system.jsx scenes_replaycheck.jsx scenes_cli.jsx; do
  echo "→ uploading $JSXF to s3://$BUCKET/"
  aws s3 cp "$SCRIPT_DIR/$JSXF" "s3://$BUCKET/$JSXF" \
    --content-type "application/javascript; charset=utf-8" \
    --cache-control "public, max-age=300"
done

echo "→ uploading benchmark.html to s3://$BUCKET/"
aws s3 cp "$SCRIPT_DIR/benchmark.html" "s3://$BUCKET/benchmark.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
aws s3 cp "$SCRIPT_DIR/benchmark.html" "s3://$BUCKET/benchmark" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"

echo "→ uploading agent-spend.html to s3://$BUCKET/"
aws s3 cp "$SCRIPT_DIR/agent-spend.html" "s3://$BUCKET/agent-spend.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
aws s3 cp "$SCRIPT_DIR/agent-spend.html" "s3://$BUCKET/agent-spend" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"

echo "→ uploading video-replay-check.html to s3://$BUCKET/"
aws s3 cp "$SCRIPT_DIR/video-replay-check.html" "s3://$BUCKET/video-replay-check.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
aws s3 cp "$SCRIPT_DIR/video-replay-check.html" "s3://$BUCKET/video-replay-check" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"

echo "→ uploading video-cli.html to s3://$BUCKET/"
aws s3 cp "$SCRIPT_DIR/video-cli.html" "s3://$BUCKET/video-cli.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
aws s3 cp "$SCRIPT_DIR/video-cli.html" "s3://$BUCKET/video-cli" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"

echo "→ uploading video.html to s3://$BUCKET/"
aws s3 cp "$VIDEO" "s3://$BUCKET/video.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
aws s3 cp "$VIDEO" "s3://$BUCKET/video" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"

echo "→ uploading video-receipts.html to s3://$BUCKET/"
aws s3 cp "$VIDEO2" "s3://$BUCKET/video-receipts.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
aws s3 cp "$VIDEO2" "s3://$BUCKET/video-receipts" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"

echo "→ uploading video-delegation.html to s3://$BUCKET/"
aws s3 cp "$VIDEO3" "s3://$BUCKET/video-delegation.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
aws s3 cp "$VIDEO3" "s3://$BUCKET/video-delegation" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"

echo "→ uploading video-handshake.html to s3://$BUCKET/"
aws s3 cp "$VIDEO4" "s3://$BUCKET/video-handshake.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
aws s3 cp "$VIDEO4" "s3://$BUCKET/video-handshake" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"

echo "→ uploading video-devmode.html to s3://$BUCKET/"
aws s3 cp "$VIDEO5" "s3://$BUCKET/video-devmode.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
aws s3 cp "$VIDEO5" "s3://$BUCKET/video-devmode" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"

echo "→ uploading video-offchain.html to s3://$BUCKET/"
aws s3 cp "$VIDEO6" "s3://$BUCKET/video-offchain.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
aws s3 cp "$VIDEO6" "s3://$BUCKET/video-offchain" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"

echo "→ uploading video-frameworks.html to s3://$BUCKET/"
aws s3 cp "$VIDEO7" "s3://$BUCKET/video-frameworks.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
aws s3 cp "$VIDEO7" "s3://$BUCKET/video-frameworks" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"

echo "→ uploading video-oauth.html to s3://$BUCKET/"
aws s3 cp "$VIDEO8" "s3://$BUCKET/video-oauth.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
aws s3 cp "$VIDEO8" "s3://$BUCKET/video-oauth" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"

echo "→ uploading playground.html to s3://$BUCKET/"
aws s3 cp "$PLAYGROUND" "s3://$BUCKET/playground.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
aws s3 cp "$PLAYGROUND" "s3://$BUCKET/playground" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"

echo "→ uploading school.html to s3://$BUCKET/"
aws s3 cp "$SCRIPT_DIR/school.html" "s3://$BUCKET/school.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
aws s3 cp "$SCRIPT_DIR/school.html" "s3://$BUCKET/school" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"

for SCHOOL_JSX in school-animations.jsx school-kit.jsx school-scenes.jsx; do
  echo "→ uploading $SCHOOL_JSX to s3://$BUCKET/"
  aws s3 cp "$SCRIPT_DIR/$SCHOOL_JSX" "s3://$BUCKET/$SCHOOL_JSX" \
    --content-type "application/javascript; charset=utf-8" \
    --cache-control "public, max-age=300"
done

echo "→ invalidating CloudFront ($DISTRIBUTION_ID)"
INVALIDATION_ID=$(aws cloudfront create-invalidation \
  --distribution-id "$DISTRIBUTION_ID" \
  --paths "/index.html" "/" "/402.html" "/402" "/blog.html" "/blog" "/blog-1.html" "/blog-1" "/blog-2.html" "/blog-2" "/blog-3.html" "/blog-3" "/blog-4.html" "/blog-4" "/blog-5.html" "/blog-5" "/benchmark.html" "/benchmark" "/agent-spend.html" "/agent-spend" "/video-replay-check.html" "/video-replay-check" "/video-cli.html" "/video-cli" "/animations.jsx" "/system.jsx" "/scenes_replaycheck.jsx" "/scenes_cli.jsx" "/video.html" "/video" "/video-receipts.html" "/video-receipts" "/video-delegation.html" "/video-delegation" "/video-handshake.html" "/video-handshake" "/video-devmode.html" "/video-devmode" "/video-offchain.html" "/video-offchain" "/video-frameworks.html" "/video-frameworks" "/video-oauth.html" "/video-oauth" "/playground.html" "/playground" "/school.html" "/school" "/school-animations.jsx" "/school-kit.jsx" "/school-scenes.jsx" \
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

echo "→ live at https://bolyra.ai and https://bolyra.ai/402"
curl -sI https://bolyra.ai      | grep -iE "last-modified|etag" || true
curl -sI https://bolyra.ai/402  | grep -iE "last-modified|etag|content-type" || true

# Post-deploy gate. Asserts the live pages return 200 and that every npm
# symbol the HTML advertises actually resolves on the published tarball.
# Catches the 2026-05-30 class of regression (page references a function
# that doesn't ship). Set BOLYRA_SKIP_VERIFY=1 to bypass — only for
# emergency redeploys where verify.sh itself is broken.
if [ "${BOLYRA_SKIP_VERIFY:-0}" = "1" ]; then
  echo "→ BOLYRA_SKIP_VERIFY=1 set, skipping post-deploy verification"
else
  echo "→ running post-deploy verification"
  bash "$SCRIPT_DIR/verify.sh"
fi
