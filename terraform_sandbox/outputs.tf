output "sandbox_users" {
  description = "ARNs of deliberately misconfigured sandbox IAM users"
  value = [
    aws_iam_user.ci_deploy_bot.arn,
    aws_iam_user.junior_dev_alex.arn,
    aws_iam_user.helpdesk_support.arn,
  ]
}

output "sandbox_roles" {
  description = "ARNs of deliberately misconfigured sandbox IAM roles"
  value = [
    aws_iam_role.app_data_processor_role.arn,
    aws_iam_role.lambda_admin_exec_role.arn,
    aws_iam_role.legacy_vendor_role.arn,
  ]
}
