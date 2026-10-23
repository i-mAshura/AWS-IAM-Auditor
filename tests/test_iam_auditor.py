"""Unit and integration test suite for the AWS IAM Auditor & Least-Privilege Policy Generator."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from iam_auditor.models import Finding
from iam_auditor.scanner import IAMAuditScanner
from iam_auditor.privesc_graph import PrivilegeEscalationAnalyzer, _CompatDiGraph, _CompatNX
from iam_auditor.cloudtrail_policy_gen import CloudTrailPolicyGenerator
from iam_auditor.remediator import IAMAutoRemediator
from iam_auditor.reporter import IAMAuditReporter
from iam_auditor.cli import run_audit_pipeline


ROOT_DIR = Path(__file__).resolve().parent.parent


class TestIAMAuditorSuite(unittest.TestCase):
    def setUp(self):
        snapshot_file = ROOT_DIR / "sample_data" / "sandbox_iam_snapshot.json"
        self.snapshot = json.loads(snapshot_file.read_text())
        self.scanner = IAMAuditScanner(snapshot_data=self.snapshot, stale_days_threshold=90)
        self.findings = self.scanner.run_all_checks()

    def test_wildcard_policies_detected(self):
        wildcard_findings = [f for f in self.findings if f.category == "WILDCARD_POLICY"]
        self.assertGreaterEqual(len(wildcard_findings), 3)
        principals = {f.principal_name for f in wildcard_findings}
        self.assertIn("OverpermissiveDataWildcard", principals)
        self.assertIn("DeprecatedMigrationRole", principals)

    def test_unused_roles_and_keys_detected(self):
        unused_roles = [f for f in self.findings if f.category == "UNUSED_ROLE"]
        unused_keys = [f for f in self.findings if f.category == "UNUSED_ACCESS_KEY"]
        self.assertEqual({f.principal_name for f in unused_roles}, {"LegacyVendorCrossAccountRole", "DeprecatedMigrationRole"})
        self.assertEqual({f.principal_name for f in unused_keys}, {"ci-deploy-bot", "junior-dev-alex"})

    def test_users_without_mfa_detected(self):
        mfa_findings = [f for f in self.findings if f.category == "MISSING_MFA"]
        self.assertEqual({f.principal_name for f in mfa_findings}, {"junior-dev-alex", "helpdesk-support"})

    def test_risky_trust_policies_detected(self):
        trust_findings = [f for f in self.findings if f.category == "RISKY_TRUST_POLICY"]
        self.assertEqual({f.principal_name for f in trust_findings}, {"LegacyVendorCrossAccountRole", "DeprecatedMigrationRole"})

    def test_privilege_escalation_paths_detected(self):
        analyzer = PrivilegeEscalationAnalyzer(self.snapshot)
        analyzer.build_graph()
        esc_sources = {e.source_principal for e in analyzer.escalation_paths}
        self.assertIn("User:ci-deploy-bot", esc_sources)
        self.assertIn("User:junior-dev-alex", esc_sources)
        self.assertIn("User:helpdesk-support", esc_sources)

        # Verify multi-hop PassRole + CreateFunction -> LambdaAdminExecRole -> AWS_ACCOUNT_ADMIN
        alex_paths = [e for e in analyzer.escalation_paths if e.source_principal == "User:junior-dev-alex"]
        self.assertTrue(any("Role:LambdaAdminExecRole" in e.hop_chain for e in alex_paths))

    def test_cloudtrail_least_privilege_generator(self):
        ct_gen = CloudTrailPolicyGenerator(account_id="998877665544")
        ct_gen.load_cloudtrail_directory(str(ROOT_DIR / "sample_data" / "cloudtrail_logs"))
        pol = ct_gen.generate_policy_for_role("AppDataProcessorRole")

        all_actions = []
        for stmt in pol["Statement"]:
            all_actions.extend(stmt["Action"])

        self.assertIn("s3:GetObject", all_actions)
        self.assertIn("dynamodb:PutItem", all_actions)
        self.assertIn("sqs:SendMessage", all_actions)
        # Ensure AccessDenied iam:CreateUser call was filtered out!
        self.assertNotIn("iam:CreateUser", all_actions)

    def test_dry_run_remediation_safety(self):
        remediator = IAMAutoRemediator(dry_run=True)
        actions = remediator.remediate_stale_keys(self.findings)
        self.assertEqual(len(actions), 2)
        self.assertTrue(all(a.dry_run and not a.executed for a in actions))

    def test_cli_pipeline_execution(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            res = run_audit_pipeline(
                snapshot_path=str(ROOT_DIR / "sample_data" / "sandbox_iam_snapshot.json"),
                cloudtrail_dir=str(ROOT_DIR / "sample_data" / "cloudtrail_logs"),
                output_dir=tmp_dir,
                stale_days=90,
                dry_run=True,
            )
            self.assertIn("report", res)
            self.assertTrue(Path(res["json_report_path"]).exists())
            self.assertTrue(Path(res["html_report_path"]).exists())
            self.assertTrue(Path(res["graph_png_path"]).exists())

            policies = list(Path(tmp_dir, "least_privilege_policies").glob("*.json"))
            self.assertGreaterEqual(len(policies), 1)

            summary = res["report"]["summary"]
            self.assertGreaterEqual(summary["risk_score"], 75)
            self.assertIn("CRITICAL", summary["posture_rating"])
            self.assertGreaterEqual(summary["total_findings"], 10)

    def test_reporter_json_and_html_export(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_file = Path(tmp_dir) / "report.json"
            html_file = Path(tmp_dir) / "report.html"
            reporter = IAMAuditReporter(
                account_id="112233445566",
                findings=self.findings,
                escalation_paths=[],
                policy_suggestions=[],
                remediation_actions=[],
            )
            payload = reporter.export_json(str(json_file))
            self.assertEqual(payload["summary"]["account_id"], "112233445566")
            self.assertTrue(json_file.exists())

            reporter.export_html(str(html_file))
            self.assertTrue(html_file.exists())
            html_content = html_file.read_text(encoding="utf-8")
            self.assertIn("AWS IAM Security Auditor", html_content)
            self.assertIn("112233445566", html_content)

    def test_risk_score_calculation(self):
        # Empty findings -> score 0, LOW RISK
        reporter = IAMAuditReporter("123", [], [], [], [])
        summary = reporter.calculate_risk_summary()
        self.assertEqual(summary["risk_score"], 0)
        self.assertIn("LOW RISK", summary["posture_rating"])

        # Critical finding -> minimum score 75
        crit_finding = Finding(
            finding_id="TEST-001",
            category="WILDCARD_POLICY",
            severity="CRITICAL",
            principal_type="Role",
            principal_name="TestRole",
            principal_arn="arn:aws:iam::123:role/TestRole",
            title="Crit",
            description="Crit desc",
        )
        reporter_crit = IAMAuditReporter("123", [crit_finding], [], [], [])
        summary_crit = reporter_crit.calculate_risk_summary()
        self.assertGreaterEqual(summary_crit["risk_score"], 75)

    def test_execute_remediation_mocked_boto3(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.client.return_value = mock_iam

        remediator = IAMAutoRemediator(dry_run=False, boto3_session=mock_session)
        actions = remediator.remediate_stale_keys(self.findings)
        self.assertEqual(len(actions), 2)
        self.assertTrue(all(a.executed and not a.dry_run and a.status == "EXECUTED_KEY_DISABLED" for a in actions))
        self.assertEqual(mock_iam.update_access_key.call_count, 2)

        # Policy remediation
        ct_gen = CloudTrailPolicyGenerator(account_id="998877665544")
        ct_gen.load_cloudtrail_directory(str(ROOT_DIR / "sample_data" / "cloudtrail_logs"))
        suggestions = ct_gen.build_suggestions(self.snapshot)
        pol_actions = remediator.remediate_policies(suggestions)
        self.assertTrue(all(a.executed and not a.dry_run and a.status == "EXECUTED_POLICY_APPLIED" for a in pol_actions))
        self.assertGreaterEqual(mock_iam.put_role_policy.call_count, 1)

    def test_cloudtrail_extended_services(self):
        generator = CloudTrailPolicyGenerator(account_id="998877665544")
        events = [
            {
                "userIdentity": {
                    "type": "AssumedRole",
                    "arn": "arn:aws:sts::998877665544:assumed-role/KmsRole/test",
                    "sessionContext": {"sessionIssuer": {"userName": "KmsRole"}}
                },
                "eventSource": "kms.amazonaws.com",
                "eventName": "Decrypt",
                "awsRegion": "us-east-1",
                "requestParameters": {"keyId": "12345678-1234-1234-1234-123456789012"}
            },
            {
                "userIdentity": {
                    "type": "AssumedRole",
                    "arn": "arn:aws:sts::998877665544:assumed-role/SnsRole/test",
                    "sessionContext": {"sessionIssuer": {"userName": "SnsRole"}}
                },
                "eventSource": "sns.amazonaws.com",
                "eventName": "Publish",
                "awsRegion": "us-east-1",
                "requestParameters": {"topicArn": "arn:aws:sns:us-east-1:998877665544:alerts-topic"}
            },
            {
                "userIdentity": {
                    "type": "AssumedRole",
                    "arn": "arn:aws:sts::998877665544:assumed-role/LogsRole/test",
                    "sessionContext": {"sessionIssuer": {"userName": "LogsRole"}}
                },
                "eventSource": "logs.amazonaws.com",
                "eventName": "CreateLogStream",
                "awsRegion": "us-east-1",
                "requestParameters": {"logGroupName": "/aws/lambda/data-worker"}
            }
        ]
        generator.ingest_events(events)

        kms_pol = generator.generate_policy_for_role("KmsRole")
        self.assertEqual(kms_pol["Statement"][0]["Action"], ["kms:Decrypt"])
        self.assertIn("arn:aws:kms:us-east-1:998877665544:key/12345678-1234-1234-1234-123456789012", kms_pol["Statement"][0]["Resource"])

        sns_pol = generator.generate_policy_for_role("SnsRole")
        self.assertEqual(sns_pol["Statement"][0]["Action"], ["sns:Publish"])
        self.assertIn("arn:aws:sns:us-east-1:998877665544:alerts-topic", sns_pol["Statement"][0]["Resource"])

        logs_pol = generator.generate_policy_for_role("LogsRole")
        self.assertEqual(logs_pol["Statement"][0]["Action"], ["logs:CreateLogStream"])
        self.assertIn("arn:aws:logs:us-east-1:998877665544:log-group:/aws/lambda/data-worker:*", logs_pol["Statement"][0]["Resource"])

    def test_compat_nx_graph(self):
        g = _CompatDiGraph()
        g.add_node("A", label="Node A")
        g.add_node("B", label="Node B")
        g.add_node("C", label="Node C")
        g.add_edge("A", "B", vector="Vector1", permissions=["perm1"])
        g.add_edge("B", "C", vector="Vector2", permissions=["perm2"])

        self.assertTrue(_CompatNX.has_path(g, "A", "C"))
        self.assertFalse(_CompatNX.has_path(g, "C", "A"))

        paths = _CompatNX.all_simple_paths(g, "A", "C")
        self.assertEqual(paths, [["A", "B", "C"]])
        self.assertEqual(g.get_edge_data("A", "B")["vector"], "Vector1")

    def test_additional_privesc_vectors(self):
        snapshot = {
            "account_id": "123456789012",
            "users": [
                {
                    "UserName": "key-creator-user",
                    "Arn": "arn:aws:iam::123456789012:user/key-creator-user",
                    "PasswordEnabled": False,
                    "MFADevices": [],
                    "AccessKeys": [],
                    "AttachedPolicies": [],
                    "InlinePolicies": {
                        "KeyCreator": {
                            "Version": "2012-10-17",
                            "Statement": [{"Effect": "Allow", "Action": ["iam:CreateAccessKey"], "Resource": "*"}]
                        }
                    }
                },
                {
                    "UserName": "target-admin-user",
                    "Arn": "arn:aws:iam::123456789012:user/target-admin-user",
                    "PasswordEnabled": True,
                    "MFADevices": [],
                    "AccessKeys": [],
                    "AttachedPolicies": ["arn:aws:iam::aws:policy/AdministratorAccess"],
                    "InlinePolicies": {}
                }
            ],
            "roles": [],
            "managed_policies": {}
        }
        analyzer = PrivilegeEscalationAnalyzer(snapshot)
        analyzer.build_graph()
        esc = [e for e in analyzer.escalation_paths if e.source_principal == "User:key-creator-user"]
        self.assertEqual(len(esc), 1)
        self.assertIn("CreateAccessKey", esc[0].vector)

    def test_scanner_clean_account(self):
        clean_snapshot = {
            "account_id": "123456789012",
            "users": [
                {
                    "UserName": "safe-dev",
                    "Arn": "arn:aws:iam::123456789012:user/safe-dev",
                    "PasswordEnabled": True,
                    "MFADevices": ["arn:aws:iam::123456789012:mfa/safe-dev"],
                    "AccessKeys": [
                        {
                            "AccessKeyId": "AKIAFRESH123",
                            "Status": "Active",
                            "CreateDate": "2026-10-20T12:00:00Z",
                            "LastUsedDate": "2026-10-22T12:00:00Z"
                        }
                    ],
                    "AttachedPolicies": [],
                    "InlinePolicies": {
                        "ScopedS3": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": ["s3:GetObject"],
                                "Resource": ["arn:aws:s3:::safe-bucket/*"]
                            }]
                        }
                    }
                }
            ],
            "roles": [
                {
                    "RoleName": "SafeAppRole",
                    "Arn": "arn:aws:iam::123456789012:role/SafeAppRole",
                    "CreateDate": "2026-10-01T12:00:00Z",
                    "LastUsedDate": "2026-10-22T15:00:00Z",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }]
                    },
                    "AttachedPolicies": [],
                    "InlinePolicies": {}
                }
            ],
            "managed_policies": {}
        }
        scanner = IAMAuditScanner(snapshot_data=clean_snapshot, stale_days_threshold=90)
        findings = scanner.run_all_checks()
        self.assertEqual(findings, [])

    def test_live_boto3_scanner_mocked(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_sts = MagicMock()
        mock_session.client.side_effect = lambda service: mock_sts if service == "sts" else mock_iam

        mock_sts.get_caller_identity.return_value = {"Account": "111222333444"}

        # Users paginator
        user_paginator = MagicMock()
        user_paginator.paginate.return_value = [
            {"Users": [{"UserName": "boto-user", "Arn": "arn:aws:iam::111222333444:user/boto-user"}]}
        ]
        # Roles paginator
        role_paginator = MagicMock()
        role_paginator.paginate.return_value = [
            {"Roles": [{"RoleName": "boto-role", "Arn": "arn:aws:iam::111222333444:role/boto-role"}]}
        ]
        # Policies paginator
        pol_paginator = MagicMock()
        pol_paginator.paginate.return_value = []

        def get_paginator_side_effect(operation):
            if operation == "list_users":
                return user_paginator
            elif operation == "list_roles":
                return role_paginator
            elif operation == "list_policies":
                return pol_paginator
            return MagicMock()

        mock_iam.get_paginator.side_effect = get_paginator_side_effect
        mock_iam.list_mfa_devices.return_value = {"MFADevices": []}
        mock_iam.list_access_keys.return_value = {"AccessKeyMetadata": []}
        mock_iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}
        mock_iam.list_user_policies.return_value = {"PolicyNames": []}
        mock_iam.get_login_profile.return_value = {"LoginProfile": {}}

        mock_iam.get_role.return_value = {
            "Role": {
                "RoleName": "boto-role",
                "Arn": "arn:aws:iam::111222333444:role/boto-role",
                "CreateDate": "2026-01-01T00:00:00Z",
                "AssumeRolePolicyDocument": {
                    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
                }
            }
        }
        mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
        mock_iam.list_role_policies.return_value = {"PolicyNames": []}

        scanner = IAMAuditScanner(boto3_session=mock_session)
        snapshot = scanner.collect_from_boto3()
        self.assertEqual(snapshot["account_id"], "111222333444")
        self.assertEqual(len(snapshot["users"]), 1)
        self.assertEqual(snapshot["users"][0]["UserName"], "boto-user")
        self.assertTrue(snapshot["users"][0]["PasswordEnabled"])
        self.assertEqual(len(snapshot["roles"]), 1)


if __name__ == "__main__":
    unittest.main()
