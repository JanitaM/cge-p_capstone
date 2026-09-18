#!/usr/bin/env bash
# Proves scripts/verify-evidence.sh can both pass and fail, on the real pulled run:
#   - the real evidence/<run_id>/ folder passes and prints CHAIN INTACT
#   - a changed bundle fails the SHA-256 check
#   - a changed bundle with .sha256 and receipt.json also rewritten to match still fails,
#     at the Cosign signature check (the signature does not depend on files we can edit)
#   - a retain-until date in the past fails the retention check
#   - an unknown run id fails
# A verifier that can't fail proves nothing.
#
# No AWS needed. Needs cosign and jq.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

RUN_ID="${RUN_ID:-35371787746}"
SRC="evidence/${RUN_ID}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

FAILS=0
fail() { echo "FAIL: $1"; FAILS=$((FAILS + 1)); }
pass() { echo "PASS: $1"; }

# expect_fail <label> <keyword> <base-dir> <run-id>
# Runs the verifier against a base dir; it must exit non-zero and say why (keyword).
expect_fail() {
  local label="$1" keyword="$2" base="$3" run="$4" out
  out="$(EVIDENCE_DIR="$base" scripts/verify-evidence.sh "$run" 2>&1)"
  local rc=$?
  if [[ $rc -ne 0 ]] && echo "$out" | grep -qi "$keyword" && ! echo "$out" | grep -q "CHAIN INTACT"; then
    pass "$label"
  else
    fail "$label (exit $rc, wanted non-zero and a message containing '$keyword')"
    echo "$out" | sed 's|^|      |'
  fi
}

# fresh_copy <name>: copy the real folder into $TMP/<name>/<run_id>/, print the base dir
fresh_copy() {
  mkdir -p "$TMP/$1"
  cp -R "$SRC" "$TMP/$1/$RUN_ID"
  echo "$TMP/$1"
}
bundle_in() { find "$1/$RUN_ID" -maxdepth 1 -name 'evidence-*.tar.gz' | head -1; }

# --- 1. real folder passes ---------------------------------------------------
if out="$(scripts/verify-evidence.sh "$RUN_ID" 2>&1)" && echo "$out" | grep -q "CHAIN INTACT for run ${RUN_ID}"; then
  pass "real evidence/${RUN_ID}/ verifies and prints CHAIN INTACT"
else
  fail "real evidence/${RUN_ID}/ should verify and print CHAIN INTACT"
  echo "$out" | sed 's|^|      |'
fi

# --- 2. one changed byte fails the SHA-256 check -----------------------------
base="$(fresh_copy sha)"
printf 'x' >> "$(bundle_in "$base")"
expect_fail "changed bundle fails the SHA-256 check" "sha-256" "$base" "$RUN_ID"

# --- 3. changed bundle + matching .sha256/receipt still fails Cosign ---------
base="$(fresh_copy sig)"
b="$(bundle_in "$base")"
printf 'x' >> "$b"
new="$(shasum -a 256 "$b" | awk '{print $1}')"
echo "$new" > "$b.sha256"
jq --arg s "$new" '.sha256 = $s' "$base/$RUN_ID/receipt.json" > "$TMP/r.json" && mv "$TMP/r.json" "$base/$RUN_ID/receipt.json"
expect_fail "changed bundle with rewritten hashes fails the Cosign check" "cosign" "$base" "$RUN_ID"

# --- 4. retention date in the past fails -------------------------------------
base="$(fresh_copy ret)"
jq '.retain_until = "2020-01-01T00:00:00+00:00"' "$base/$RUN_ID/retention.json" > "$TMP/t.json" && mv "$TMP/t.json" "$base/$RUN_ID/retention.json"
expect_fail "retain-until date in the past fails the retention check" "retention" "$base" "$RUN_ID"

# --- 5. unknown run id fails -------------------------------------------------
expect_fail "unknown run id fails" "no evidence" "$TMP" "0000000000"

echo
if [[ "$FAILS" -eq 0 ]]; then echo "OK: all checks passed"; else echo "$FAILS check(s) failed"; exit 1; fi
