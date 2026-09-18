# policies/cc67_s3_tls_deny.rego
# METADATA
# title: GAP-03 — S3 uploads bucket TLS enforcement
# description: >
#   Denies a Terraform plan where the uploads S3 bucket has no policy
#   denying non-TLS (aws:SecureTransport = false) requests.
# custom:
#   framework: SOC 2
#   control_id: SOC2-CC6.7
#   severity: medium
#   remediation: >
#     Attach an aws_s3_bucket_policy to the uploads bucket with a Deny
#     statement conditioned on aws:SecureTransport = "false"
#     (see terraform/uploads-bucket-policy.tf).
package policies.cc67_s3_tls_deny

deny contains msg if {
	some bucket in input.resource_changes
	bucket.type == "aws_s3_bucket"
	resource_name(bucket.address) == "uploads"
	not tls_denied(resource_name(bucket.address))

	msg := sprintf(
		"GAP-03 (SOC2-CC6.7): S3 bucket %q has no policy denying non-TLS requests",
		[bucket.address],
	)
}

tls_denied(bucket_name) if {
	some policy in input.resource_changes
	policy.type == "aws_s3_bucket_policy"
	resource_name(policy.address) == bucket_name
	doc := json.unmarshal(policy.change.after.policy)
	some statement in doc.Statement
	statement.Effect == "Deny"
	statement.Condition.Bool["aws:SecureTransport"] == "false"
}

resource_name(address) := name if {
	parts := split(address, ".")
	name := parts[count(parts) - 1]
}
