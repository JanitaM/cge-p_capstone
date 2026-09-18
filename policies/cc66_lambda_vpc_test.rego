package policies.cc66_lambda_vpc

test_deny_when_vpc_config_missing if {
	violations := deny with input as {"resource_changes": [lambda(null)]}
	count(violations) == 1
}

test_deny_when_vpc_config_empty if {
	violations := deny with input as {"resource_changes": [lambda([])]}
	count(violations) == 1
}

test_deny_when_no_subnets if {
	cfg := [{"subnet_ids": [], "security_group_ids": ["sg-abc123"]}]
	violations := deny with input as {"resource_changes": [lambda(cfg)]}
	count(violations) == 1
}

test_allow_when_vpc_config_wired if {
	cfg := [{"subnet_ids": ["subnet-1", "subnet-2"], "security_group_ids": ["sg-abc123"]}]
	violations := deny with input as {"resource_changes": [lambda(cfg)]}
	count(violations) == 0
}

lambda(vpc_config) := {
	"address": "aws_lambda_function.intake",
	"type": "aws_lambda_function",
	"change": {"after": {"vpc_config": vpc_config}},
}
