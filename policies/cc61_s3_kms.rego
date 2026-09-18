# policies/cc61_s3_kms.rego
# METADATA
# title: GAP-01 — S3 uploads bucket SSE-KMS
# description: >
#   Denies a Terraform plan where the uploads S3 bucket is not encrypted
#   with SSE-KMS using a customer-managed key.
# custom:
#   framework: SOC 2
#   control_id: SOC2-CC6.1
#   severity: high
#   remediation: >
#     Add an aws_s3_bucket_server_side_encryption_configuration for the
#     uploads bucket with sse_algorithm = "aws:kms" and kms_master_key_id
#     set to the shared CMK (see terraform/uploads-bucket-kms-encryption.tf).
package policies.cc61_s3_kms

deny contains msg if {
	some bucket in input.resource_changes
	bucket.type == "aws_s3_bucket"
	resource_name(bucket.address) == "uploads"
	not kms_encrypted(resource_name(bucket.address))

	msg := sprintf(
		"GAP-01 (SOC2-CC6.1): S3 bucket %q is not encrypted with SSE-KMS using a customer-managed key",
		[bucket.address],
	)
}

kms_encrypted(bucket_name) if {
	some sse in input.resource_changes
	sse.type == "aws_s3_bucket_server_side_encryption_configuration"
	resource_name(sse.address) == bucket_name
	some rule in sse.change.after.rule

	# The AWS provider represents this nested block as a one-element list
	# in plan JSON even though HCL only ever configures a single block —
	# hand-written fixtures that model it as a bare object don't match a
	# real `terraform show -json` plan.
	some cfg in rule.apply_server_side_encryption_by_default
	cfg.sse_algorithm == "aws:kms"
	cfg.kms_master_key_id != null
	cfg.kms_master_key_id != ""
}

resource_name(address) := name if {
	parts := split(address, ".")
	name := parts[count(parts) - 1]
}
