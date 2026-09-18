######################################################################
# Bootstrap — remote Terraform state backend.
#
# Chicken-and-egg: this config provisions the S3 bucket the *main*
# config's backend points at, so it can't use that backend itself.
# Its own state stays local — it's applied once, by hand, and rarely
# touched again. See ../main.tf's `backend "s3"` block for the
# consumer side, and test/state_backend.sh for the zero-drift proof.
#
# Locking: native S3 conditional-writes locking (`use_lockfile` in the
# backend block), not a DynamoDB lock table — Terraform >= 1.10
# supports it directly, so no extra table to provision or pay for.
######################################################################

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "acme-health-intake"
      ManagedBy = "terraform"
      Purpose   = "tfstate-bootstrap"
    }
  }
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "tfstate" {
  bucket = "acme-health-intake-tfstate-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
