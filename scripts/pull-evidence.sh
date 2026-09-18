#!/usr/bin/env bash
# scripts/pull-evidence.sh <run_id> [--vault <bucket>] [--profile <p>]
#
# Owner-side: pulls one pipeline run's signed evidence out of the Object Lock
# vault into evidence/<run_id>/, so it can be committed and checked by anyone
# with scripts/verify-evidence.sh (no AWS needed for that).
#
# Saves: the bundle, its .sha256, its .sig.bundle, receipt.json, and
# retention.json (what S3 itself says about the bundle: Object Lock mode and
# retain-until date, and the exact version id). Read-only AWS calls only.
# Needs live AWS (vault read + KMS decrypt).
set -euo pipefail

RUN_ID="${1:?usage: pull-evidence.sh <run_id> [--vault <bucket>] [--profile <p>]}"
shift || true
VAULT="${EVIDENCE_VAULT:-}"
PROFILE="${AWS_PROFILE:-default}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault)   VAULT="$2"; shift 2 ;;
    --profile) PROFILE="$2"; shift 2 ;;
    *) echo "unknown argument: $1"; exit 2 ;;
  esac
done
[[ -z "$VAULT" ]] && { echo "Set --vault or EVIDENCE_VAULT"; exit 2; }

cd "$(dirname "$0")/.."
AWS=(aws --profile "$PROFILE")
PREFIX="runs/${RUN_ID}"
OUT="evidence/${RUN_ID}"
mkdir -p "$OUT"

# receipt.json is written by the pipeline's upload step. It names the bundle
# and the exact version id, so we pull that version, not "whatever is latest".
"${AWS[@]}" s3 cp "s3://${VAULT}/${PREFIX}/receipt.json" "$OUT/receipt.json" --only-show-errors
BUNDLE_KEY=$(jq -r '.bundle_key' "$OUT/receipt.json")
VERSION_ID=$(jq -r '.version_id' "$OUT/receipt.json")
BUNDLE=$(basename "$BUNDLE_KEY")

"${AWS[@]}" s3api get-object --bucket "$VAULT" --key "$BUNDLE_KEY" \
  --version-id "$VERSION_ID" "$OUT/$BUNDLE" >/dev/null
for suffix in .sha256 .sig.bundle; do
  "${AWS[@]}" s3 cp "s3://${VAULT}/${BUNDLE_KEY}${suffix}" "$OUT/${BUNDLE}${suffix}" --only-show-errors
done

# S3's own answer about the bundle object, saved at pull time.
"${AWS[@]}" s3api get-object-retention --bucket "$VAULT" --key "$BUNDLE_KEY" \
  --version-id "$VERSION_ID" --output json \
| jq --arg vault "$VAULT" --arg key "$BUNDLE_KEY" --arg version "$VERSION_ID" \
     --arg pulled "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
     '{vault: $vault, key: $key, version_id: $version,
       mode: .Retention.Mode, retain_until: .Retention.RetainUntilDate,
       pulled_at: $pulled}' > "$OUT/retention.json"

echo "Pulled run ${RUN_ID} into ${OUT}/:"
ls -1 "$OUT"
