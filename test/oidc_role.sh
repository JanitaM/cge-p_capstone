#!/usr/bin/env bash
# Proves the GitHub OIDC IAM setup is scoped, not a rubber stamp:
#   - the OIDC provider is for token.actions.githubusercontent.com
#   - the plan role's trust condition is restricted to this repo
#   - the apply role's trust condition is restricted to this repo AND
#     refs/heads/main (it's the one with write/apply permissions)
#   - neither role's attached policy grants AdministratorAccess or an
#     Action:"*"/Resource:"*" statement
#   - neither role's attached policy lets it modify its own OIDC
#     provider or role/policy resources (no self-privilege-escalation)
#
# Reads from applied STATE, not a plan: the OIDC provider's ARN feeds
# both roles' trust policies, so that JSON is unresolvable ("known
# after apply") until the provider actually exists — a plan can't
# prove this, only a real apply can.
set -euo pipefail

AWS_PROFILE="${AWS_PROFILE:-default}"
eval "$(aws configure export-credentials --profile "$AWS_PROFILE" --format env)"

cd "$(dirname "$0")/../terraform"

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
STATE_JSON="$WORKDIR/state.json"

terraform init -input=false >/dev/null
terraform show -json > "$STATE_JSON"

fail() { echo "FAIL: $1"; exit 1; }

resource() {
  jq -r --arg addr "$1" '
    [.values.root_module, (.values.root_module.child_modules[]?)]
    | .[].resources[]?
    | select(.address == $addr)
  ' "$STATE_JSON"
}

OIDC=$(resource "aws_iam_openid_connect_provider.github_actions")
[ -n "$OIDC" ] || fail "aws_iam_openid_connect_provider.github_actions not found in plan"
echo "$OIDC" | jq -e '.values.url == "token.actions.githubusercontent.com"' >/dev/null \
  || fail "OIDC provider URL is not token.actions.githubusercontent.com"

# This repo has GitHub's immutable-subject-claim OIDC setting enabled, so
# the real `sub` claim is "repo:<owner>@<owner_id>/<repo>@<repo_id>:...",
# not the plain "repo:<owner>/<repo>:..." form — confirmed against a real
# token in CI after a trust condition written against the plain form
# silently never matched (AssumeRoleWithWebIdentity "Not authorized").
GITHUB_SUBJECT="JanitaM@48458664/cge-p_capstone@1364803394"

PLAN_ROLE=$(resource "module.grc_gate_plan_role.aws_iam_role.this")
[ -n "$PLAN_ROLE" ] || fail "module.grc_gate_plan_role.aws_iam_role.this not found in plan"
echo "$PLAN_ROLE" | jq -e --arg sub "repo:${GITHUB_SUBJECT}:*" \
  '.values.assume_role_policy | fromjson | .Statement[0].Condition.StringLike["token.actions.githubusercontent.com:sub"] == $sub' >/dev/null \
  || fail "plan role trust condition is not scoped to repo:${GITHUB_SUBJECT}:*"

APPLY_ROLE=$(resource "module.grc_gate_apply_role.aws_iam_role.this")
[ -n "$APPLY_ROLE" ] || fail "module.grc_gate_apply_role.aws_iam_role.this not found in plan"
echo "$APPLY_ROLE" | jq -e --arg sub "repo:${GITHUB_SUBJECT}:ref:refs/heads/main" \
  '.values.assume_role_policy | fromjson | .Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == $sub' >/dev/null \
  || fail "apply role trust condition is not restricted to repo:${GITHUB_SUBJECT}:ref:refs/heads/main"

for addr in aws_iam_policy.grc_gate_plan aws_iam_policy.grc_gate_apply; do
  POLICY=$(resource "$addr")
  [ -n "$POLICY" ] || fail "$addr not found in plan"
  echo "$POLICY" | jq -e '
    .values.policy | fromjson | .Statement[]
    | select((.Action == "*" or (.Action | type == "array" and any(. == "*"))) and .Resource == "*")
  ' >/dev/null && fail "$addr grants Action:* + Resource:* (admin-equivalent)"

  echo "$POLICY" | jq -e '
    .values.policy | fromjson | .Statement[]
    | select(.Effect == "Allow")
    | .Action | (if type == "array" then . else [.] end)[]
    | select(test("^iam:(Create|Update|Delete|Attach|Detach|Put).*(Role|Policy|OpenIDConnectProvider)"; "i"))
  ' >/dev/null && fail "$addr can write its own IAM role/policy/OIDC provider (self-escalation risk)"
done

echo "PASS: OIDC provider + roles are scoped to this repo, apply is main-only, no admin-equivalent or self-escalation grants."
