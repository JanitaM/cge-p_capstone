#!/usr/bin/env bash
# Schema-validates the hand-written OSCAL files with trestle, and proves the
# profile's control ids exist in the real NIST 800-53 Rev 5 catalog:
#   1. `trestle validate` on the component definition and on the profile
#   2. `trestle author profile-resolve` on the profile (fetches the catalog
#      from the profile's import URL, so this step needs network access)
#   3. the resolved catalog holds exactly the component's control-ids
#
# trestle only validates inside a workspace with its own directory layout, so
# this builds a throwaway one in a temp dir and copies the files in. oscal/
# stays the single source of truth. No AWS needed.
#
# COMPONENT / PROFILE can be overridden (test/oscal_validate.sh uses this to
# prove the check is able to fail).
set -euo pipefail

cd "$(dirname "$0")/.."

COMPONENT="${COMPONENT:-oscal/components/acme-health-intake.json}"
PROFILE="${PROFILE:-oscal/profiles/acme-health-soc2.json}"
COMPONENT="$(cd "$(dirname "$COMPONENT")" && pwd)/$(basename "$COMPONENT")"
PROFILE="$(cd "$(dirname "$PROFILE")" && pwd)/$(basename "$PROFILE")"

command -v trestle >/dev/null || { echo "FAIL: trestle not installed (pip install compliance-trestle)"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
trestle init >/dev/null 2>&1

mkdir -p component-definitions/component profiles/profile
cp "$COMPONENT" component-definitions/component/component-definition.json
cp "$PROFILE" profiles/profile/profile.json

FAILS=0
fail() { echo "FAIL: $1"; FAILS=$((FAILS + 1)); }
pass() { echo "PASS: $1"; }

# --- 1. schema validation ----------------------------------------------------
# Capture output and check the exit code: trestle prints the reason to
# stderr, and a pipe here would swallow a failing status.
validate() { # <trestle model type> <model name>
  local out
  if out="$(trestle validate -t "$1" -n "$2" 2>&1)"; then
    pass "trestle validate $1"
    echo "$out" | grep '^VALID' | sed 's|^|      |' || true
  else
    fail "trestle validate $1"
    echo "$out" | sed 's|^|      |'
  fi
}
validate component-definition component
validate profile profile

# --- 2 + 3. profile resolves; resolved ids == component ids ------------------
if resolve_out="$(trestle author profile-resolve -n profile -o resolved 2>&1)"; then
  pass "trestle author profile-resolve"
  want="$(python3 - "$COMPONENT" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))["component-definition"]
ids = {r["control-id"]
       for c in d["components"]
       for ci in c.get("control-implementations", [])
       for r in ci.get("implemented-requirements", [])}
print("\n".join(sorted(ids)))
PY
)"
  got="$(python3 - catalogs/resolved/catalog.json <<'PY'
import json, sys
found = set()
def walk(x):
    if isinstance(x, dict):
        if x.get("class") == "SP800-53" and "id" in x:
            found.add(x["id"])
        for v in x.values():
            walk(v)
    elif isinstance(x, list):
        for v in x:
            walk(v)
walk(json.load(open(sys.argv[1])))
print("\n".join(sorted(found)))
PY
)"
  if [[ -n "$want" && "$want" == "$got" ]]; then
    pass "resolved catalog controls == component control-ids ($(echo "$want" | tr '\n' ' '))"
  else
    fail "resolved catalog controls != component control-ids"
    echo "      component: $(echo "$want" | tr '\n' ' ')"
    echo "      resolved:  $(echo "$got" | tr '\n' ' ')"
  fi
else
  fail "trestle author profile-resolve"
  echo "$resolve_out" | sed 's|^|      |'
fi

echo
if [[ "$FAILS" -eq 0 ]]; then
  echo "OK: OSCAL files are schema-valid and the profile resolves"
else
  echo "$FAILS check(s) failed"
  exit 1
fi
