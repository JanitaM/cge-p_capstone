package policies.cc61_s3_kms

test_deny_when_encryption_resource_missing if {
	violations := deny with input as {"resource_changes": [uploads_bucket]}
	count(violations) == 1
}

test_deny_when_algorithm_is_aes256 if {
	sse := encryption_config("AES256", null)
	violations := deny with input as {"resource_changes": [uploads_bucket, sse]}
	count(violations) == 1
}

test_deny_when_kms_key_id_missing if {
	sse := encryption_config("aws:kms", "")
	violations := deny with input as {"resource_changes": [uploads_bucket, sse]}
	count(violations) == 1
}

test_allow_when_sse_kms_with_cmk if {
	sse := encryption_config("aws:kms", "arn:aws:kms:us-east-1:123456789012:key/shared-cmk")
	violations := deny with input as {"resource_changes": [uploads_bucket, sse]}
	count(violations) == 0
}

uploads_bucket := {
	"address": "aws_s3_bucket.uploads",
	"type": "aws_s3_bucket",
	"change": {"after": {"bucket": "acme-health-intake-uploads-abcd1234"}},
}

encryption_config(algorithm, kms_key_id) := {
	"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"change": {"after": {"rule": [{"apply_server_side_encryption_by_default": {
		"sse_algorithm": algorithm,
		"kms_master_key_id": kms_key_id,
	}}]}},
}
