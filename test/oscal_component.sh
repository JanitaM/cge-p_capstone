#!/usr/bin/env bash
# Proves the OSCAL component is traceable, not just well-formed JSON:
#   - component + profile exist and parse
#   - every uuid is a valid v4 and unique across both files
#   - the profile selects exactly the control-ids the component implements
#   - every `terraform-resource` prop is a real address in applied state
#   - every implemented requirement has a soc2-criterion prop and an
#     evidence link; CC7.2 (si-4) is declared `planned`, not overclaimed
#   - every evidence link resolves to a real vault object at its VersionId,
#     and the linked bundle's SHA-256 + Cosign signature verify
#
# Needs live AWS (state + vault reads) — run before any teardown.
# Schema validation is a separate step (`trestle validate`, backlog item 19).
set -euo pipefail

AWS_PROFILE="${AWS_PROFILE:-default}"
eval "$(aws configure export-credentials --profile "$AWS_PROFILE" --format env)"

cd "$(dirname "$0")/.."

COMPONENT=oscal/components/acme-health-intake.json
PROFILE=oscal/profiles/acme-health-soc2.json
NIST_URL="https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
SIGNER_RE='^https://github\.com/JanitaM/cge-p_capstone/\.github/workflows/grc-gate\.yml@refs/heads/main$'

FAILS=0
fail() { echo "FAIL: $1"; FAILS=$((FAILS + 1)); }
pass() { echo "PASS: $1"; }

# --- 1. files exist and parse ------------------------------------------------
for f in "$COMPONENT" "$PROFILE"; do
  if [ ! -f "$f" ]; then
    echo "FAIL: $f does not exist"
    exit 1
  fi
  jq empty "$f" || { echo "FAIL: $f is not valid JSON"; exit 1; }
done
pass "component and profile exist and parse"

# --- 2. UUIDs: valid v4, unique across both files ----------------------------
UUIDS=$(jq -r '.. | objects | select(has("uuid")) | .uuid' "$COMPONENT" "$PROFILE")
BAD=$(echo "$UUIDS" | grep -Ev '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' || true)
DUPES=$(echo "$UUIDS" | sort | uniq -d)
[ -z "$BAD" ] && pass "every uuid is a valid v4" || fail "non-v4 uuid(s): $BAD"
[ -z "$DUPES" ] && pass "every uuid is unique" || fail "duplicate uuid(s): $DUPES"

# --- 3. metadata + source ----------------------------------------------------
[ "$(jq -r '."component-definition".metadata."oscal-version"' "$COMPONENT")" = "1.2.1" ] \
  && pass "component oscal-version is 1.2.1" || fail "component oscal-version is not 1.2.1"
SOURCES=$(jq -r '."component-definition".components[]."control-implementations"[].source' "$COMPONENT" | sort -u)
[ "$SOURCES" = "$NIST_URL" ] \
  && pass "control-implementation.source is the NIST 800-53 Rev 5 catalog" \
  || fail "unexpected control-implementation source(s): $SOURCES"

# --- 4. profile ids == component control-ids ---------------------------------
COMP_IDS=$(jq -r '."component-definition".components[]."control-implementations"[]."implemented-requirements"[]."control-id"' "$COMPONENT" | sort)
PROF_IDS=$(jq -r '.profile.imports[]."include-controls"[]."with-ids"[]' "$PROFILE" | sort)
[ "$COMP_IDS" = "$PROF_IDS" ] \
  && pass "profile selects exactly the component's control-ids ($(echo "$COMP_IDS" | tr '\n' ' '))" \
  || fail "profile ids != component ids
  component: $(echo "$COMP_IDS" | tr '\n' ' ')
  profile:   $(echo "$PROF_IDS" | tr '\n' ' ')"

# --- 5. terraform addresses exist in applied state ---------------------------
STATE=$(cd terraform && terraform init -input=false >/dev/null && terraform state list)
ADDRS=$(jq -r '.. | objects | select(.name? == "terraform-resource") | .value' "$COMPONENT")
[ -n "$ADDRS" ] || fail "no terraform-resource props found"
while IFS= read -r addr; do
  [ -z "$addr" ] && continue
  if echo "$STATE" | grep -Fxq -- "$addr"; then
    pass "state has $addr"
  else
    fail "cited address not in terraform state: $addr"
  fi
done <<< "$ADDRS"

# --- 5b. cited Rego policy files exist ---------------------------------------
POLICIES=$(jq -r '.. | objects | select(.name? == "rego-policy") | .value' "$COMPONENT")
while IFS= read -r p; do
  [ -z "$p" ] && continue
  [ -f "$p" ] && pass "policy file exists: $p" || fail "cited policy file missing: $p"
done <<< "$POLICIES"

# --- 6. per-requirement shape ------------------------------------------------
# Each requirement: soc2-criterion prop; implemented ones need >=1 evidence link.
jq -c '."component-definition".components[]."control-implementations"[]."implemented-requirements"[]' "$COMPONENT" |
while IFS= read -r ir; do
  id=$(echo "$ir" | jq -r '."control-id"')
  echo "$ir" | jq -e '[.props[]? | select(.name=="soc2-criterion")] | length == 1' >/dev/null \
    || { echo "FAIL: $id missing exactly one soc2-criterion prop"; exit 1; }
  status=$(echo "$ir" | jq -r '[.props[]? | select(.name=="implementation-status") | .value] | first // "none"')
  if [ "$status" = "implemented" ]; then
    echo "$ir" | jq -e '[.links[]? | select(.rel=="evidence")] | length >= 1' >/dev/null \
      || { echo "FAIL: $id is implemented but has no evidence link"; exit 1; }
  fi
  if [ "$id" = "si-4" ] && [ "$status" != "planned" ]; then
    echo "FAIL: si-4 (CC7.2) must be planned, got $status"
    exit 1
  fi
done && pass "every requirement has soc2-criterion; implemented ones have evidence; si-4 is planned" \
     || FAILS=$((FAILS + 1))

# --- 7. evidence links resolve; bundle integrity + signature verify ----------
LINKS=$(jq -r '.. | objects | select(.rel? == "evidence") | .href' "$COMPONENT" | sort -u)
[ -n "$LINKS" ] || fail "no evidence links found"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

while IFS= read -r href; do
  [ -z "$href" ] && continue
  case "$href" in
    s3://*\?versionId=*) ;;
    *) fail "evidence href not of the form s3://bucket/key?versionId=...: $href"; continue ;;
  esac
  rest=${href#s3://}
  bucket=${rest%%/*}
  keyver=${rest#*/}
  key=${keyver%%\?versionId=*}
  ver=${keyver##*\?versionId=}
  if aws s3api head-object --bucket "$bucket" --key "$key" --version-id "$ver" >/dev/null 2>&1; then
    pass "vault object resolves: $key"
    aws s3api get-object --bucket "$bucket" --key "$key" --version-id "$ver" "$WORK/$(basename "$key")" >/dev/null
  else
    fail "evidence link does not resolve: $href"
  fi
done <<< "$LINKS"

for bundle in "$WORK"/evidence-*.tar.gz; do
  [ -e "$bundle" ] || { fail "no linked evidence bundle downloaded to verify"; break; }
  expected=$(cat "$bundle.sha256")
  actual=$(shasum -a 256 "$bundle" | awk '{print $1}')
  [ "$expected" = "$actual" ] && pass "SHA-256 matches for $(basename "$bundle")" || fail "SHA-256 mismatch for $(basename "$bundle")"
  if cosign verify-blob \
      --bundle "$bundle.sig.bundle" \
      --certificate-identity-regexp "$SIGNER_RE" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
      "$bundle" >/dev/null 2>&1; then
    pass "cosign signature verifies (signed by grc-gate.yml on main)"
  else
    fail "cosign verify-blob failed for $(basename "$bundle")"
  fi
done

if [ "$FAILS" -eq 0 ]; then
  echo "ALL CHECKS PASSED"
else
  echo "$FAILS check(s) failed"
  exit 1
fi
