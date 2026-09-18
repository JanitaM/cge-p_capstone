# policies/cc66_lambda_vpc.rego
# METADATA
# title: GAP-05 — Intake Lambda VPC placement
# description: >
#   Denies a Terraform plan where the intake Lambda does not run inside
#   the starter's private subnets with a security group attached.
# custom:
#   framework: SOC 2
#   control_id: SOC2-CC6.6
#   severity: high
#   remediation: >
#     Add a vpc_config block to aws_lambda_function.intake referencing the
#     private subnets and the hardened Lambda security group
#     (see terraform/lambda-vpc-config.tf).
package policies.cc66_lambda_vpc

deny contains msg if {
	some fn in input.resource_changes
	fn.type == "aws_lambda_function"

	not in_vpc(fn)

	msg := sprintf(
		"GAP-05 (SOC2-CC6.6): Lambda function %q is not deployed inside the private VPC subnets",
		[fn.address],
	)
}

in_vpc(fn) if {
	vpc_config := fn.change.after.vpc_config
	vpc_config != null
	some cfg in as_array(vpc_config)
	count(cfg.subnet_ids) > 0
	count(cfg.security_group_ids) > 0
}

as_array(x) := x if is_array(x)

as_array(x) := [x] if not is_array(x)
