# policies/cc61_dynamodb_kms.rego
# METADATA
# title: GAP-02 — DynamoDB submissions table CMK
# description: >
#   Denies a Terraform plan where the submissions DynamoDB table's
#   server-side encryption does not reference a customer-managed KMS key.
# custom:
#   framework: SOC 2
#   control_id: SOC2-CC6.1
#   severity: high
#   remediation: >
#     Pass kms_key_arn (the shared CMK) into the dynamodb-table module's
#     server_side_encryption block (see terraform/dynamodb-submissions.tf).
package policies.cc61_dynamodb_kms

deny contains msg if {
	some table in input.resource_changes
	table.type == "aws_dynamodb_table"

	not cmk_encrypted(table)

	msg := sprintf(
		"GAP-02 (SOC2-CC6.1): DynamoDB table %q is not encrypted with a customer-managed KMS key",
		[table.address],
	)
}

cmk_encrypted(table) if {
	some sse in table.change.after.server_side_encryption
	sse.enabled == true
	sse.kms_key_arn != null
	sse.kms_key_arn != ""
}
