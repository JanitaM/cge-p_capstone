package policies.cc61_dynamodb_kms

test_deny_when_server_side_encryption_missing if {
	violations := deny with input as {"resource_changes": [table(null)]}
	count(violations) == 1
}

test_deny_when_kms_key_arn_missing if {
	violations := deny with input as {"resource_changes": [table([{"enabled": true}])]}
	count(violations) == 1
}

test_allow_when_cmk_wired if {
	sse := [{"enabled": true, "kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/shared-cmk"}]
	violations := deny with input as {"resource_changes": [table(sse)]}
	count(violations) == 0
}

table(server_side_encryption) := {
	"address": "module.submissions.aws_dynamodb_table.this",
	"type": "aws_dynamodb_table",
	"change": {"after": {"server_side_encryption": server_side_encryption}},
}
