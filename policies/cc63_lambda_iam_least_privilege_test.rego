package policies.cc63_lambda_iam_least_privilege

test_deny_when_dynamodb_wildcard if {
	doc := {"Version": "2012-10-17", "Statement": [{
		"Effect": "Allow",
		"Action": "dynamodb:*",
		"Resource": "*",
	}]}
	violations := deny with input as {"resource_changes": [inline_policy(doc)]}
	count(violations) == 1
}

test_deny_when_s3_wildcard if {
	doc := {"Version": "2012-10-17", "Statement": [{
		"Effect": "Allow",
		"Action": "s3:*",
		"Resource": "*",
	}]}
	violations := deny with input as {"resource_changes": [inline_policy(doc)]}
	count(violations) == 1
}

test_allow_when_scoped_actions if {
	doc := {"Version": "2012-10-17", "Statement": [
		{"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/submissions"},
		{"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::acme-health-intake-uploads-abcd1234/*"},
	]}
	violations := deny with input as {"resource_changes": [attached_policy(doc)]}
	count(violations) == 0
}

inline_policy(doc) := {
	"address": "aws_iam_role_policy.lambda_inline",
	"type": "aws_iam_role_policy",
	"change": {"after": {"policy": json.marshal(doc)}},
}

attached_policy(doc) := {
	"address": "aws_iam_policy.intake_data_access",
	"type": "aws_iam_policy",
	"change": {"after": {"policy": json.marshal(doc)}},
}
