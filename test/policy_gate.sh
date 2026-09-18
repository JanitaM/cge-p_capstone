#!/usr/bin/env bash
# Proves the Policy check step actually fails closed: `opa test ./policies`
# passes on the real suite, and a deliberately broken `_test.rego` fixture
# (mirrors the item-17 "red PR" case) makes the same invocation fail.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "== opa test ./policies (real suite) =="
opa test ./policies
echo "PASS: real policy suite is green."

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
cp -r policies "$WORKDIR/policies"

# Break a fixture the same way GAPS.md's "gap re-introduced" check would:
# flip the compliant case's expected violation count so the assertion no
# longer matches the policy's actual (correct) behavior.
sed -i.bak '/test_allow_when_sse_kms_with_cmk/,/^}/ s/count(violations) == 0/count(violations) == 1/' \
  "$WORKDIR/policies/cc61_s3_kms_test.rego"
rm -f "$WORKDIR/policies/cc61_s3_kms_test.rego.bak"

echo "== opa test ./policies (deliberately broken fixture) =="
if opa test "$WORKDIR/policies"; then
  echo "FAIL: broken fixture did not fail opa test — the gate would not fail closed."
  exit 1
fi
echo "PASS: broken fixture fails opa test — the gate fails closed."
