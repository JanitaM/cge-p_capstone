######################################################################
# GitHub OIDC — lets the grc-gate.yml workflow authenticate to AWS via
# short-lived, federated credentials instead of a stored access key.
# Two roles, not one:
#   - grc_gate_plan:  read-only, trusted for any run in this repo (PRs
#     and pushes) — the Plan step needs to read current state to diff
#     against, nothing more.
#   - grc_gate_apply: read/write, trusted ONLY for runs on
#     refs/heads/main — the Apply/Upload steps, which only ever run
#     post-merge (see project-overview.md Decision #5: no manual
#     approval gate, so this trust condition is the actual gate).
#
# Bootstrapped by hand, like terraform/bootstrap/ — deliberately not
# self-managed by the apply role: neither policy below grants write
# access to this OIDC provider or either role/policy, so a compromised
# or over-broad future PR can't widen its own trust or permissions.
# Widening this file requires a human apply, same as the state bucket.
######################################################################

locals {
  # This account/repo has GitHub's "immutable subject claim" OIDC setting
  # enabled (confirmed via `gh api repos/JanitaM/cge-p_capstone/actions/oidc/
  # customization/sub`: use_immutable_subject=true), so the `sub` claim on
  # every token is "repo:<owner>@<owner_id>/<repo>@<repo_id>:...", not the
  # plain "repo:<owner>/<repo>:..." most examples show. Confirmed against a
  # real token via a throwaway debug step in a test PR — a trust condition
  # written against the plain form silently never matches, producing "Not
  # authorized to perform sts:AssumeRoleWithWebIdentity" with no indication
  # why. IDs are stable for the life of the repo (they change only on a
  # highly unusual event like account deletion/recreation), same durability
  # assumption as the account-ID-keyed tfstate bucket name elsewhere here.
  github_repo_subject = "JanitaM@48458664/cge-p_capstone@1364803394"
}

resource "aws_iam_openid_connect_provider" "github_actions" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd",
  ]
}

######################################################################
# Plan role — read-only, any ref/event in this repo.
######################################################################

data "aws_iam_policy_document" "grc_gate_plan_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github_actions.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${local.github_repo_subject}:*"]
    }
  }
}

resource "aws_iam_policy" "grc_gate_plan" {
  name        = "${local.name_prefix}-grc-gate-plan-${local.suffix}"
  description = "Read-only access for `terraform plan` in the GRC gate pipeline."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadWorkloadResources"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "s3:GetBucket*",
          "s3:GetObject*",
          "s3:GetEncryptionConfiguration",
          "s3:ListBucket",
          "s3:ListAllMyBuckets",
          "dynamodb:DescribeTable",
          "dynamodb:DescribeContinuousBackups",
          "dynamodb:ListTagsOfResource",
          "lambda:GetFunction*",
          "lambda:GetPolicy",
          "lambda:ListVersionsByFunction",
          "lambda:ListTags",
          "apigateway:GET",
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListPolicyVersions",
          "iam:GetOpenIDConnectProvider",
          "iam:ListOpenIDConnectProviders",
          "kms:DescribeKey",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
          "kms:ListResourceTags",
          "kms:ListAliases",
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:GetEventSelectors",
          "cloudtrail:ListTags",
        ]
        Resource = "*"
      },
      {
        Sid    = "TfstateLockAndRead"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
        Resource = [
          "arn:aws:s3:::acme-health-intake-tfstate-396322497825",
          "arn:aws:s3:::acme-health-intake-tfstate-396322497825/*",
        ]
      },
    ]
  })
}

module "grc_gate_plan_role" {
  source = "github.com/JanitaM/infra-modules//modules/aws/iam-role?ref=v1.25.0"

  role_name          = "${local.name_prefix}-grc-gate-plan-${local.suffix}"
  assume_role_policy = data.aws_iam_policy_document.grc_gate_plan_trust.json
  policy_arns        = [aws_iam_policy.grc_gate_plan.arn]
}

######################################################################
# Apply role — read/write, refs/heads/main only.
######################################################################

data "aws_iam_policy_document" "grc_gate_apply_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github_actions.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${local.github_repo_subject}:ref:refs/heads/main"]
    }
  }
}

resource "aws_iam_policy" "grc_gate_apply" {
  name        = "${local.name_prefix}-grc-gate-apply-${local.suffix}"
  description = "Read/write access for `terraform apply` + evidence upload, main-branch runs only."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadWorkloadResources"
        Effect   = "Allow"
        Action   = jsondecode(aws_iam_policy.grc_gate_plan.policy).Statement[0].Action
        Resource = "*"
      },
      {
        Sid    = "WriteWorkloadResources"
        Effect = "Allow"
        Action = [
          "ec2:CreateVpc", "ec2:DeleteVpc", "ec2:ModifyVpcAttribute",
          "ec2:CreateSubnet", "ec2:DeleteSubnet",
          "ec2:CreateInternetGateway", "ec2:DeleteInternetGateway", "ec2:AttachInternetGateway", "ec2:DetachInternetGateway",
          "ec2:CreateRouteTable", "ec2:DeleteRouteTable", "ec2:CreateRoute", "ec2:DeleteRoute",
          "ec2:AssociateRouteTable", "ec2:DisassociateRouteTable", "ec2:ReplaceRouteTableAssociation",
          "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup",
          "ec2:AuthorizeSecurityGroupEgress", "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress", "ec2:RevokeSecurityGroupIngress",
          "ec2:CreateVpcEndpoint", "ec2:DeleteVpcEndpoints", "ec2:ModifyVpcEndpoint",
          "ec2:CreateTags", "ec2:DeleteTags",
          "s3:CreateBucket", "s3:DeleteBucket",
          "s3:PutBucketVersioning", "s3:PutEncryptionConfiguration", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy",
          "s3:PutBucketPublicAccessBlock", "s3:PutObjectLockConfiguration", "s3:PutBucketTagging", "s3:PutBucketObjectLockConfiguration",
          "s3:PutObject", "s3:DeleteObject",
          "dynamodb:CreateTable", "dynamodb:DeleteTable", "dynamodb:UpdateTable",
          "dynamodb:UpdateContinuousBackups", "dynamodb:TagResource", "dynamodb:UntagResource",
          "lambda:CreateFunction", "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration", "lambda:DeleteFunction",
          "lambda:AddPermission", "lambda:RemovePermission", "lambda:TagResource", "lambda:UntagResource",
          "apigateway:POST", "apigateway:PUT", "apigateway:PATCH", "apigateway:DELETE",
          "kms:TagResource", "kms:UntagResource", "kms:EnableKeyRotation", "kms:CreateAlias", "kms:UpdateAlias", "kms:DeleteAlias",
          "cloudtrail:CreateTrail", "cloudtrail:UpdateTrail", "cloudtrail:DeleteTrail",
          "cloudtrail:StartLogging", "cloudtrail:StopLogging", "cloudtrail:PutEventSelectors",
          "cloudtrail:AddTags", "cloudtrail:RemoveTags",
        ]
        Resource = "*"
      },
      {
        Sid      = "PassLambdaRoleToLambdaOnly"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = module.lambda_role.role_arn
        Condition = {
          StringEquals = { "iam:PassedToService" = "lambda.amazonaws.com" }
        }
      },
      {
        Sid    = "TfstateLockAndReadWrite"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
        Resource = [
          "arn:aws:s3:::acme-health-intake-tfstate-396322497825",
          "arn:aws:s3:::acme-health-intake-tfstate-396322497825/*",
        ]
      },
      {
        Sid    = "UploadSignedEvidence"
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:GetObject", "s3:ListBucket", "s3:GetObjectRetention"]
        Resource = [
          "arn:aws:s3:::${module.evidence_vault.bucket_id}",
          "arn:aws:s3:::${module.evidence_vault.bucket_id}/*",
        ]
      },
      {
        # The vault bucket defaults to SSE-KMS with the shared CMK, so S3
        # calls into KMS on the caller's behalf for every Put/Get — without
        # this, UploadSignedEvidence's s3:PutObject above still fails with
        # KMS AccessDenied (verified via `aws iam simulate-principal-policy`
        # before this statement existed).
        Sid      = "EvidenceVaultKmsUse"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = aws_kms_key.cmk.arn
      },
    ]
  })
}

module "grc_gate_apply_role" {
  source = "github.com/JanitaM/infra-modules//modules/aws/iam-role?ref=v1.25.0"

  role_name          = "${local.name_prefix}-grc-gate-apply-${local.suffix}"
  assume_role_policy = data.aws_iam_policy_document.grc_gate_apply_trust.json
  policy_arns        = [aws_iam_policy.grc_gate_apply.arn]
}
