output "api_url" {
  value       = "${aws_apigatewayv2_api.intake.api_endpoint}/intake"
  description = "POST /intake endpoint."
}

output "intake_table" {
  value       = aws_dynamodb_table.intake.name
  description = "DynamoDB table holding patient submissions."
}

output "uploads_bucket" {
  value       = aws_s3_bucket.uploads.id
  description = "S3 bucket where intake attachments land."
}

output "lambda_function_name" {
  value = aws_lambda_function.intake.function_name
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "kms_cmk_arn" {
  value       = aws_kms_key.cmk.arn
  description = "ARN of the shared customer-managed key (submissions table + evidence vault)."
}

output "evidence_vault_bucket" {
  value       = module.evidence_vault.bucket_id
  description = "S3 bucket where signed evidence bundles land."
}

output "evidence_vault_arn" {
  value       = module.evidence_vault.bucket_arn
  description = "ARN of the evidence vault bucket."
}
