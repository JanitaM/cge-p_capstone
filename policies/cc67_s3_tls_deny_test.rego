package policies.cc67_s3_tls_deny

test_deny_when_policy_resource_missing if {
	violations := deny with input as {"resource_changes": [uploads_bucket]}
	count(violations) == 1
}

test_deny_when_policy_has_no_secure_transport_deny if {
	permissive := bucket_policy({
		"Version": "2012-10-17",
		"Statement": [{
			"Sid": "AllowRead",
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "*",
		}],
	})
	violations := deny with input as {"resource_changes": [uploads_bucket, permissive]}
	count(violations) == 1
}

test_allow_when_secure_transport_denied if {
	tls_deny := bucket_policy({
		"Version": "2012-10-17",
		"Statement": [{
			"Sid": "DenyInsecureTransport",
			"Effect": "Deny",
			"Principal": "*",
			"Action": "s3:*",
			"Resource": ["arn:aws:s3:::acme-health-intake-uploads-abcd1234", "arn:aws:s3:::acme-health-intake-uploads-abcd1234/*"],
			"Condition": {"Bool": {"aws:SecureTransport": "false"}},
		}],
	})
	violations := deny with input as {"resource_changes": [uploads_bucket, tls_deny]}
	count(violations) == 0
}

uploads_bucket := {
	"address": "aws_s3_bucket.uploads",
	"type": "aws_s3_bucket",
	"change": {"after": {"bucket": "acme-health-intake-uploads-abcd1234"}},
}

bucket_policy(doc) := {
	"address": "aws_s3_bucket_policy.uploads",
	"type": "aws_s3_bucket_policy",
	"change": {"after": {"policy": json.marshal(doc)}},
}
