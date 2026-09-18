#!/usr/bin/env bash
# scripts/verify-evidence.sh <run_id>
#
# Grader-side: checks one pipeline run's signed evidence from the pulled copy in
# evidence/<run_id>/ (see scripts/pull-evidence.sh). No AWS needed.
# Needs: cosign, jq, shasum. Cosign needs no network for a bundle signed this way.
#
# Three checks:
#   1. SHA-256 of the bundle matches the .sha256 file and receipt.json
#   2. Cosign signature verifies, against the exact workflow that signs (no wildcard)
#   3. retention.json shows an Object Lock retain-until date still in the future
#
# Prints "CHAIN INTACT for run <run_id>" only if all three pass; otherwise exits non-zero.
# EVIDENCE_DIR overrides the base folder (default: evidence/ at the repo root); the tests use it.
set -uo pipefail

RUN_ID="${1:?usage: verify-evidence.sh <run_id>}"
BASE="${EVIDENCE_DIR:-$(dirname "$0")/../evidence}"
DIR="$BASE/$RUN_ID"

SIGNER='https://github.com/JanitaM/cge-p_capstone/.github/workflows/grc-gate.yml@refs/heads/main'
ISSUER='https://token.actions.githubusercontent.com'

FAILS=0
fail() { echo "FAIL: $1"; FAILS=$((FAILS + 1)); }
pass() { echo "PASS: $1"; }

for tool in cosign jq shasum; do
  command -v "$tool" >/dev/null || { echo "FAIL: $tool is not installed"; exit 2; }
done

[[ -d "$DIR" ]] || { echo "FAIL: no evidence found for run ${RUN_ID} (looked in ${DIR})"; exit 1; }

BUNDLE="$(find "$DIR" -maxdepth 1 -name 'evidence-*.tar.gz' | head -1)"
for f in "$BUNDLE" "${BUNDLE}.sha256" "${BUNDLE}.sig.bundle" "$DIR/receipt.json" "$DIR/retention.json"; do
  [[ -n "$f" && -f "$f" ]] || { echo "FAIL: missing file in ${DIR}: ${f:-evidence-*.tar.gz}"; exit 1; }
done

# --- 1. integrity ------------------------------------------------------------
ACTUAL="$(shasum -a 256 "$BUNDLE" | awk '{print $1}')"
FROM_FILE="$(tr -d '[:space:]' < "${BUNDLE}.sha256")"
FROM_RECEIPT="$(jq -r '.sha256' "$DIR/receipt.json")"
if [[ "$ACTUAL" == "$FROM_FILE" && "$ACTUAL" == "$FROM_RECEIPT" ]]; then
  pass "SHA-256 matches the .sha256 file and receipt.json (${ACTUAL})"
else
  fail "SHA-256 mismatch: bundle=${ACTUAL} .sha256=${FROM_FILE} receipt=${FROM_RECEIPT}"
fi

# --- 2. authenticity + timestamp ---------------------------------------------
if COSIGN_OUT="$(cosign verify-blob \
      --bundle "${BUNDLE}.sig.bundle" \
      --certificate-identity "$SIGNER" \
      --certificate-oidc-issuer "$ISSUER" \
      "$BUNDLE" 2>&1)"; then
  pass "Cosign signature verifies (signer: ${SIGNER})"
else
  fail "Cosign signature did not verify"
  echo "$COSIGN_OUT" | sed 's|^|      |'
fi

# --- 3. preservation ---------------------------------------------------------
MODE="$(jq -r '.mode' "$DIR/retention.json")"
RETAIN_UNTIL="$(jq -r '.retain_until' "$DIR/retention.json")"
# retain_until looks like 2026-12-17T17:01:04.386000+00:00; make it 2026-12-17T17:01:04Z
if jq -e --arg u "$RETAIN_UNTIL" -n \
     '($u | sub("\\.[0-9]+"; "") | sub("\\+00:00$"; "Z") | fromdateiso8601) > now' >/dev/null 2>&1 \
   && [[ "$MODE" == "GOVERNANCE" || "$MODE" == "COMPLIANCE" ]]; then
  pass "retention: Object Lock ${MODE}, retained until ${RETAIN_UNTIL}"
else
  fail "retention is missing, expired or not Object Lock (mode=${MODE}, retain_until=${RETAIN_UNTIL})"
fi

echo
if [[ "$FAILS" -eq 0 ]]; then
  echo "CHAIN INTACT for run ${RUN_ID}"
else
  echo "${FAILS} check(s) failed for run ${RUN_ID}"
  exit 1
fi
