#!/usr/bin/env bash
# Proves Terraform state persisted to the remote backend, not just locally:
# re-init from a clean checkout (no .terraform/, no local .tfstate) and
# confirm `plan` reports zero drift against state written by a prior apply.
set -euo pipefail

AWS_PROFILE="${AWS_PROFILE:-default}"
eval "$(aws configure export-credentials --profile "$AWS_PROFILE" --format env)"

cd "$(dirname "$0")/.."

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

mkdir "$WORKDIR/terraform"
tar -C terraform --exclude='.terraform' --exclude='*.tfstate*' --exclude='bootstrap' -cf - . | tar -x -C "$WORKDIR/terraform"

cd "$WORKDIR/terraform"
terraform init -input=false
set +e
terraform plan -input=false -detailed-exitcode -out=/dev/null
STATUS=$?
set -e

if [ "$STATUS" -eq 0 ]; then
  echo "PASS: zero drift from a fresh checkout — state is remote."
  exit 0
elif [ "$STATUS" -eq 2 ]; then
  echo "FAIL: plan reported changes from a fresh checkout — state did not persist remotely."
  exit 1
else
  echo "FAIL: terraform plan errored (exit $STATUS) — backend likely not configured."
  exit 1
fi
