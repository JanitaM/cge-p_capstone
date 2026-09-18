#!/usr/bin/env bash
# Proves scripts/validate-oscal.sh can both pass and fail:
#   - the real oscal/ files validate (exit 0)
#   - a copy of the component with an unknown field is rejected (non-zero)
#   - a copy of the profile importing a nonexistent control is rejected
# A validator that can't fail proves nothing.
#
# Needs trestle and network (profile-resolve fetches the NIST catalog).
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

FAILS=0
fail() { echo "FAIL: $1"; FAILS=$((FAILS + 1)); }
pass() { echo "PASS: $1"; }

# --- 1. real files pass ------------------------------------------------------
if scripts/validate-oscal.sh >"$TMP/real.out" 2>&1; then
  pass "real oscal/ files validate"
else
  fail "real oscal/ files should validate"
  sed 's|^|      |' "$TMP/real.out"
fi

# --- 2. component with an unknown field is rejected --------------------------
python3 - "$TMP/bad-component.json" <<'PY'
import json, sys
p = "oscal/components/acme-health-intake.json"
d = json.load(open(p))
d["component-definition"]["not-a-real-field"] = "x"
json.dump(d, open(sys.argv[1], "w"))
PY
if COMPONENT="$TMP/bad-component.json" scripts/validate-oscal.sh >/dev/null 2>&1; then
  fail "component with an unknown field should be rejected"
else
  pass "component with an unknown field is rejected"
fi

# --- 3. profile selecting a control that isn't in the catalog ----------------
python3 - "$TMP/bad-profile.json" <<'PY'
import json, sys
d = json.load(open("oscal/profiles/acme-health-soc2.json"))
d["profile"]["imports"][0]["include-controls"][0]["with-ids"].append("zz-99")
json.dump(d, open(sys.argv[1], "w"))
PY
if PROFILE="$TMP/bad-profile.json" scripts/validate-oscal.sh >/dev/null 2>&1; then
  fail "profile with a nonexistent control id should be rejected"
else
  pass "profile with a nonexistent control id is rejected"
fi

echo
if [[ "$FAILS" -eq 0 ]]; then echo "OK: all checks passed"; else echo "$FAILS check(s) failed"; exit 1; fi
