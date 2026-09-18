# policies/cc63_lambda_iam_least_privilege.rego
# METADATA
# title: GAP-07 — Intake Lambda least-privilege IAM
# description: >
#   Denies a Terraform plan where an IAM policy attached to the intake
#   Lambda's role grants wildcard dynamodb:* or s3:* actions instead of
#   scoped permissions.
# custom:
#   framework: SOC 2
#   control_id: SOC2-CC6.3
#   severity: high
#   remediation: >
#     Replace the wildcard inline policy with a scoped aws_iam_policy
#     (dynamodb:PutItem, s3:PutObject on the specific table/bucket) attached
#     via infra-modules' iam-role module (see terraform/lambda-iam-role.tf).
package policies.cc63_lambda_iam_least_privilege

wildcard_actions := {"dynamodb:*", "s3:*", "*"}

deny contains msg if {
	some policy in input.resource_changes
	policy.type in {"aws_iam_role_policy", "aws_iam_policy"}
	doc := json.unmarshal(policy.change.after.policy)
	some statement in doc.Statement
	statement.Effect == "Allow"
	some action in as_array(statement.Action)
	action in wildcard_actions

	msg := sprintf(
		"GAP-07 (SOC2-CC6.3): IAM policy %q grants wildcard action %q",
		[policy.address, action],
	)
}

as_array(x) := x if is_array(x)

as_array(x) := [x] if not is_array(x)
