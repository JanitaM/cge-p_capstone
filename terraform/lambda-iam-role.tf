######################################################################
# GAP-07: closed — the intake Lambda's role is built from a
# customer-authored least-privilege policy (dynamodb:PutItem on the
# submissions table, s3:PutObject on the uploads bucket — the only
# two calls handler.py makes) plus the two AWS-managed execution-role
# policies, attached via infra-modules' iam-role module. That module
# authors no policy document itself, so it can't be the source of a
# wildcard action/resource — see its README.
######################################################################

resource "aws_iam_policy" "intake_data_access" {
  name        = "${local.name_prefix}-intake-data-access-${local.suffix}"
  description = "Least-privilege data access for the intake Lambda: write-only to its own table and bucket."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "dynamodb:PutItem"
        Resource = module.submissions.table_arn
      },
      {
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.uploads.arn}/*"
      }
    ]
  })
}

module "lambda_role" {
  source = "github.com/JanitaM/infra-modules//modules/aws/iam-role?ref=v1.25.0"

  role_name = "${local.name_prefix}-lambda-${local.suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  policy_arns = [
    aws_iam_policy.intake_data_access.arn,
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole",
  ]
}
