"""Command-Line Interface for the AWS IAM Auditor & Least-Privilege Policy Generator."""
import argparse
import json
from pathlib import Path
from typing import Optional

from .scanner import IAMAuditScanner
from .privesc_graph import PrivilegeEscalationAnalyzer
from .cloudtrail_policy_gen import CloudTrailPolicyGenerator
from .remediator import IAMAutoRemediator
from .reporter import IAMAuditReporter


def run_audit_pipeline(
    snapshot_path: Optional[str],
    cloudtrail_dir: str,
    output_dir: str,
    stale_days: int = 90,
    dry_run: bool = True,
) -> dict:
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    snapshot_data = None
    if snapshot_path:
        snapshot_data = json.loads(Path(snapshot_path).read_text())

    # 1. Run core IAM security checks
    scanner = IAMAuditScanner(snapshot_data=snapshot_data, stale_days_threshold=stale_days)
    findings = scanner.run_all_checks()
    active_snapshot = scanner.snapshot_data

    # 2. Build NetworkX privilege escalation graph & merge escalation findings
    privesc = PrivilegeEscalationAnalyzer(active_snapshot)
    privesc.build_graph()
    findings.extend(privesc.to_findings())

    graph_png = str(out_path / "privilege_escalation_graph.png")
    privesc.export_graph_image(graph_png)

    # 3. Parse CloudTrail logs & generate tightened least-privilege policies
    ct_gen = CloudTrailPolicyGenerator(account_id=active_snapshot.get("account_id", "123456789012"))
    if cloudtrail_dir and Path(cloudtrail_dir).exists():
        ct_gen.load_cloudtrail_directory(cloudtrail_dir)
    suggestions = ct_gen.build_suggestions(active_snapshot)

    # Save individual generated least-privilege policy JSON files
    policies_dir = out_path / "least_privilege_policies"
    policies_dir.mkdir(parents=True, exist_ok=True)
    for s in suggestions:
        pol_file = policies_dir / f"{s.role_name}_least_privilege.json"
        pol_file.write_text(json.dumps(s.generated_policy, indent=2))

    # 4. Run Auto-Remediation (Dry-Run by default)
    remediator = IAMAutoRemediator(dry_run=dry_run, boto3_session=scanner.boto3_session)
    remediator.remediate_stale_keys(findings)
    remediator.remediate_policies(suggestions)

    # 5. Export JSON and HTML Reports
    reporter = IAMAuditReporter(
        account_id=active_snapshot.get("account_id", "123456789012"),
        findings=findings,
        escalation_paths=privesc.escalation_paths,
        policy_suggestions=suggestions,
        remediation_actions=remediator.actions_log,
    )
    json_report_path = str(out_path / "iam_audit_report.json")
    html_report_path = str(out_path / "iam_audit_report.html")
    report_payload = reporter.export_json(json_report_path)
    reporter.export_html(html_report_path, graph_png_path=graph_png)

    return {
        "report": report_payload,
        "json_report_path": json_report_path,
        "html_report_path": html_report_path,
        "graph_png_path": graph_png,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AWS IAM Auditor with CloudTrail Least-Privilege Policy Generator & NetworkX Escalation Graph"
    )
    parser.add_argument(
        "--snapshot",
        type=str,
        default="sample_data/sandbox_iam_snapshot.json",
        help="Path to offline IAM snapshot JSON (omit with --live-aws to query live boto3 account)",
    )
    parser.add_argument(
        "--live-aws",
        action="store_true",
        help="Query live AWS account via boto3 instead of offline snapshot JSON",
    )
    parser.add_argument(
        "--cloudtrail-dir",
        type=str,
        default="sample_data/cloudtrail_logs",
        help="Directory containing CloudTrail JSON event logs",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="reports",
        help="Directory to write HTML/JSON reports, least-privilege policies, and graph PNG",
    )
    parser.add_argument(
        "--stale-days",
        type=int,
        default=90,
        help="Inactivity threshold in days for flagging unused roles and access keys (default: 90)",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        default=True,
        help="Preview remediation actions without mutating IAM resources (DEFAULT)",
    )
    mode_group.add_argument(
        "--execute-remediation",
        dest="dry_run",
        action="store_false",
        help="Execute auto-remediation (disable stale keys and apply least-privilege role policies)",
    )

    args = parser.parse_args()
    snapshot_arg = None if args.live_aws else args.snapshot
    res = run_audit_pipeline(
        snapshot_path=snapshot_arg,
        cloudtrail_dir=args.cloudtrail_dir,
        output_dir=args.output_dir,
        stale_days=args.stale_days,
        dry_run=args.dry_run,
    )
    summary = res["report"]["summary"]
    print(f"[+] AWS IAM Audit Complete for Account {summary['account_id']}")
    print(f"    Risk Score       : {summary['risk_score']}/100 ({summary['posture_rating']})")
    print(f"    Total Findings   : {summary['total_findings']} {summary['severity_breakdown']}")
    print(f"    Escalation Paths : {summary['escalation_paths_count']}")
    print(f"    JSON Report      : {res['json_report_path']}")
    print(f"    HTML Report      : {res['html_report_path']}")
    print(f"    Escalation Graph : {res['graph_png_path']}")


if __name__ == "__main__":
    main()
