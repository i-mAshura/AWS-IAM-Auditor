variable "aws_region" {
  description = "AWS region for deploying the IAM sandbox"
  type        = string
  default     = "us-east-1"
}

variable "lab_prefix" {
  description = "Prefix applied to all IAM sandbox resources"
  type        = string
  default     = "iam-audit-lab"
}

variable "external_vendor_account_id" {
  description = "Dummy 12-digit external AWS Account ID for cross-account trust policy testing"
  type        = string
  default     = "111122223333"
}
