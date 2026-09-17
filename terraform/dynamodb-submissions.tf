######################################################################
# DynamoDB — submissions table, via infra-modules' extended
# dynamodb-table module. Closes GAP-02 (AWS-owned key default) by
# wiring in the shared CMK from kms.tf.
######################################################################

module "submissions" {
  source = "github.com/JanitaM/infra-modules//modules/aws/dynamodb-table?ref=v1.25.0"

  table_name   = "${local.name_prefix}-submissions-${local.suffix}"
  hash_key     = "submission_id"
  billing_mode = "PAY_PER_REQUEST"
  kms_key_arn  = aws_kms_key.cmk.arn
}
