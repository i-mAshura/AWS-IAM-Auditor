# ==============================================================================
# Deliberately Misconfigured AWS IAM Sandbox Environment (CloudGoat-Style Lab)
# Purpose: Defensive testing target for the AWS IAM Auditor & Policy Generator.
# WARNING: Deploy ONLY in an isolated sandbox AWS account or LocalStack instance.
# ==============================================================================

terraform {
  required_version = ">= 1.3.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "AWS-IAM-Auditor-Test-Sandbox"
      Environment = "IsolatedSecurityLab"
      ManagedBy   = "Terraform"
    }
  }
}

# 1. Over-permissive Customer Managed Policy (Wildcards on S3, DynamoDB, SQS, SecretsManager)
resource "aws_iam_policy" "overpermissive_data_wildcard" {
  name        = "${var.lab_prefix}-OverpermissiveDataWildcard"
  description = "Deliberately broad service wildcards for testing Least-Privilege Policy synthesis"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "BroadWildcards"
        Effect   = "Allow"
        Action   = ["s3:*", "dynamodb:*", "sqs:*", "secretsmanager:*"]
        Resource = "*"
      }
    ]
  })
}

# 2. Privilege Escalation Policy #1: iam:CreatePolicyVersion
resource "aws_iam_policy" "custom_policy_manager" {
  name        = "${var.lab_prefix}-CustomPolicyManager"
  description = "Allows iam:CreatePolicyVersion on *, enabling privilege escalation to Admin"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowPolicyVersionManagement"
        Effect = "Allow"
        Action = [
          "iam:CreatePolicyVersion",
          "iam:SetDefaultPolicyVersion",
          "iam:ListPolicyVersions"
        ]
        Resource = "*"
      }
    ]
  })
}

# 3. IAM User #1: ci-deploy-bot (Escalation via CreatePolicyVersion + Stale Access Key)
resource "aws_iam_user" "ci_deploy_bot" {
  name = "${var.lab_prefix}-ci-deploy-bot"
}

resource "aws_iam_user_policy_attachment" "ci_bot_attach" {
  user       = aws_iam_user.ci_deploy_bot.name
  policy_arn = aws_iam_policy.custom_policy_manager.arn
}

# 4. IAM User #2: junior-dev-alex (Missing MFA + Escalation via iam:PassRole & lambda:CreateFunction)
resource "aws_iam_user" "junior_dev_alex" {
  name = "${var.lab_prefix}-junior-dev-alex"
}

resource "aws_iam_user_policy" "passrole_lambda_inline" {
  name = "PassRoleAndLambdaDeploy"
  user = aws_iam_user.junior_dev_alex.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:PassRole",
          "lambda:CreateFunction",
          "lambda:InvokeFunction"
        ]
        Resource = "*"
      }
    ]
  })
}

# 5. IAM User #3: helpdesk-support (Missing MFA + Escalation via iam:AttachUserPolicy)
resource "aws_iam_user" "helpdesk_support" {
  name = "${var.lab_prefix}-helpdesk-support"
}

resource "aws_iam_user_policy" "helpdesk_attach_user_policy" {
  name = "UserPolicyAttachment"
  user = aws_iam_user.helpdesk_support.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:AttachUserPolicy", "iam:ListPolicies"]
        Resource = "*"
      }
    ]
  })
}

# 6. IAM Role #1: AppDataProcessorRole (Over-privileged with s3:*, dynamodb:*; tightened via CloudTrail)
resource "aws_iam_role" "app_data_processor_role" {
  name = "${var.lab_prefix}-AppDataProcessorRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "app_data_proc_attach" {
  role       = aws_iam_role.app_data_processor_role.name
  policy_arn = aws_iam_policy.overpermissive_data_wildcard.arn
}

# 7. IAM Role #2: LambdaAdminExecRole (Target of PassRole escalation chain)
resource "aws_iam_role" "lambda_admin_exec_role" {
  name = "${var.lab_prefix}-LambdaAdminExecRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_admin_attach" {
  role       = aws_iam_role.lambda_admin_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# 8. IAM Role #3: LegacyVendorCrossAccountRole (Risky Cross-Account Trust without ExternalId + Stale Role)
resource "aws_iam_role" "legacy_vendor_role" {
  name = "${var.lab_prefix}-LegacyVendorCrossAccountRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.external_vendor_account_id}:root" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}
