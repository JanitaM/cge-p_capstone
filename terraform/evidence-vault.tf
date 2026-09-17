######################################################################
# S3 evidence vault — where every pipeline run's signed evidence
# bundle (.tar.gz) lands. KMS-encrypted with the shared CMK, versioned,
# Object-Lock-capable with a governance-mode retention config.
# Backlog item 5; uploading into it is Layer 3, out of scope here.
######################################################################

module "evidence_vault" {
  source = "github.com/JanitaM/infra-modules//modules/aws/s3-bucket?ref=v1.25.0"

  bucket_name         = "${local.name_prefix}-evidence-${local.suffix}"
  kms_key_arn         = aws_kms_key.cmk.arn
  versioning_enabled  = true
  object_lock_enabled = true
}

resource "aws_s3_bucket_object_lock_configuration" "evidence_vault" {
  bucket = module.evidence_vault.bucket_id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 90
    }
  }
}
