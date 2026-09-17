######################################################################
# KMS — customer-managed key shared by the DynamoDB table and the S3
# uploads bucket. Closes GAP-01 (S3 SSE-S3 default) and GAP-02
# (DynamoDB AWS-owned key default). Wiring into those resources is
# separate backlog items #5/#6 — this key isn't referenced yet.
######################################################################

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "cmk" {
  description         = "${local.name_prefix} shared CMK for submissions data + evidence vault"
  enable_key_rotation = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountRootFullAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid    = "LambdaExecutionRoleUse"
        Effect = "Allow"
        Principal = {
          AWS = module.lambda_role.role_arn
        }
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "cmk" {
  name          = "alias/${local.name_prefix}-cmk"
  target_key_id = aws_kms_key.cmk.key_id
}
