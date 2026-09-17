module "audit_trail" {
  source = "github.com/JanitaM/infra-modules//modules/aws/cloudtrail-trail?ref=v1.25.0"

  trail_name  = "${local.name_prefix}-trail-${local.suffix}"
  bucket_name = "${local.name_prefix}-audit-logs-${local.suffix}"

  tags = { project = local.name_prefix }
}
