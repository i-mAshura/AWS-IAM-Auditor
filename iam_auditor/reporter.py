"""Risk-Scored JSON and Executive HTML Report Generator."""
import json
import base64
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from .models import Finding, EscalationPath, LeastPrivilegeSuggestion, RemediationAction, SEVERITY_WEIGHTS


class IAMAuditReporter:
    """Produces risk-scored JSON and self-contained interactive HTML security reports."""

    def __init__(
        self,
        account_id: str,
        findings: List[Finding],
        escalation_paths: List[EscalationPath],
        policy_suggestions: List[LeastPrivilegeSuggestion],
        remediation_actions: List[RemediationAction],
    ):
        self.account_id = account_id
        self.findings = findings
        self.escalation_paths = escalation_paths
        self.policy_suggestions = policy_suggestions
        self.remediation_actions = remediation_actions

    def calculate_risk_summary(self) -> Dict[str, Any]:
        """Computes overall account risk score (0-100) and breakdown by severity & category."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        cat_counts: Dict[str, int] = {}
        raw_points = 0

        for f in self.findings:
            sev = f.severity.upper()
            counts[sev] = counts.get(sev, 0) + 1
            cat_counts[f.category] = cat_counts.get(f.category, 0) + 1
            raw_points += SEVERITY_WEIGHTS.get(sev, 5)

        normalized_score = min(100, int(round((raw_points / 250.0) * 100)))
        if counts["CRITICAL"] > 0:
            normalized_score = max(normalized_score, 75)

        if normalized_score >= 80:
            posture_grade = "CRITICAL RISK (Grade: F)"
        elif normalized_score >= 60:
            posture_grade = "HIGH RISK (Grade: D)"
        elif normalized_score >= 35:
            posture_grade = "MODERATE RISK (Grade: C)"
        else:
            posture_grade = "LOW RISK (Grade: A)"

        return {
            "account_id": self.account_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "risk_score": normalized_score,
            "raw_risk_points": raw_points,
            "posture_rating": posture_grade,
            "total_findings": len(self.findings),
            "severity_breakdown": counts,
            "category_breakdown": cat_counts,
            "escalation_paths_count": len(self.escalation_paths),
            "least_privilege_policies_generated": len(self.policy_suggestions),
            "remediation_actions_count": len(self.remediation_actions),
        }

    def export_json(self, output_path: str) -> Dict[str, Any]:
        """Writes the full structured report to JSON."""
        payload = {
            "summary": self.calculate_risk_summary(),
            "findings": [f.to_dict() for f in self.findings],
            "privilege_escalation_paths": [e.to_dict() for e in self.escalation_paths],
            "least_privilege_suggestions": [s.to_dict() for s in self.policy_suggestions],
            "remediation_plan": [r.to_dict() for r in self.remediation_actions],
        }
        Path(output_path).write_text(json.dumps(payload, indent=2))
        return payload

    def export_html(self, output_path: str, graph_png_path: Optional[str] = None) -> str:
        """Generates a dark-themed executive HTML report with embedded attack graph and diff policies."""
        summary = self.calculate_risk_summary()
        sev_counts = summary["severity_breakdown"]
        score = summary["risk_score"]
        if score >= 80:
            dial_color = "#F43F5E"
            dial_bg = "rgba(244, 63, 94, 0.12)"
        elif score >= 60:
            dial_color = "#FB923C"
            dial_bg = "rgba(251, 146, 60, 0.12)"
        elif score >= 35:
            dial_color = "#FACC15"
            dial_bg = "rgba(250, 204, 21, 0.12)"
        else:
            dial_color = "#10B981"
            dial_bg = "rgba(16, 185, 129, 0.12)"

        graph_img_tag = ""
        if graph_png_path and Path(graph_png_path).exists():
            b64_img = base64.b64encode(Path(graph_png_path).read_bytes()).decode("ascii")
            graph_img_tag = (
                f'<img src="data:image/png;base64,{b64_img}" '
                'alt="Privilege Escalation Graph" style="width:100%; border-radius:10px; border:1px solid #334155;" />'
            )

        findings_rows = []
        for f in self.findings:
            badge_cls = f"badge-{f.severity.lower()}"
            findings_rows.append(f"""
            <tr>
                <td><code>{f.finding_id}</code></td>
                <td><span class="badge {badge_cls}">{f.severity}</span></td>
                <td><code>{f.category}</code></td>
                <td><strong>{f.principal_type}:</strong> {f.principal_name}</td>
                <td>
                    <div class="finding-title">{f.title}</div>
                    <div class="finding-desc">{f.description}</div>
                    <div class="finding-rem"><strong>Remediation:</strong> {f.remediation}</div>
                </td>
                <td><span class="cis-tag">{f.cis_benchmark}</span></td>
            </tr>
            """)

        esc_cards = []
        for esc in self.escalation_paths:
            hops_html = " &rarr; ".join(f'<span class="hop-pill">{h}</span>' for h in esc.hop_chain)
            perms_html = ", ".join(f"<code>{p}</code>" for p in esc.required_permissions)
            esc_cards.append(f"""
            <div class="esc-card">
                <div class="esc-header">
                    <span class="badge badge-critical">PRIVILEGE ESCALATION</span>
                    <span class="esc-vector">Vector: {esc.vector}</span>
                </div>
                <div class="esc-chain">{hops_html}</div>
                <p><strong>Required Permissions:</strong> {perms_html}</p>
                <p><strong>Mitigation:</strong> {esc.mitigation}</p>
            </div>
            """)

        policy_cards = []
        for s in self.policy_suggestions:
            pol_json = json.dumps(s.generated_policy, indent=2)
            wildcards = ", ".join(f"<code>{w}</code>" for w in s.current_wildcard_actions) or "None"
            policy_cards.append(f"""
            <div class="pol-card">
                <div class="pol-header">
                    <div>
                        <h4>Role: <code>{s.role_name}</code></h4>
                        <span class="sub-arn">{s.role_arn}</span>
                    </div>
                    <div class="pol-stats">
                        <span>CloudTrail Events Analyzed: <strong>{s.observed_event_count}</strong></span> |
                        <span>Wildcards Eliminated: {wildcards}</span>
                    </div>
                </div>
                <pre class="code-block">{pol_json}</pre>
            </div>
            """)

        rem_rows = []
        for r in self.remediation_actions:
            params_str = json.dumps(r.details.get("parameters", {}), indent=2)
            rem_rows.append(f"""
            <tr>
                <td><code>{r.action_type}</code></td>
                <td><strong>{r.principal_name}</strong></td>
                <td><code>{r.target_id}</code></td>
                <td><span class="badge badge-medium">{r.status}</span></td>
                <td><pre class="code-inline">{params_str}</pre></td>
            </tr>
            """)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>AWS IAM Security Posture & Privilege Escalation Audit Report</title>
<style>
    :root {{
        --bg: #0B1120;
        --card: #1E293B;
        --border: #334155;
        --text: #F8FAFC;
        --muted: #94A3B8;
        --critical: #F43F5E;
        --high: #FB923C;
        --medium: #FACC15;
        --low: #38BDF8;
        --accent: #10B981;
    }}
    * {{ box-sizing: border-box; }}
    body {{
        margin: 0;
        padding: 32px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        background-color: var(--bg);
        color: var(--text);
        line-height: 1.55;
    }}
    .container {{ max-width: 1280px; margin: 0 auto; }}
    .header {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        background: linear-gradient(135deg, #1E293B 0%, #0F172A 100%);
        padding: 28px 32px;
        border-radius: 12px;
        border: 1px solid var(--border);
        margin-bottom: 28px;
    }}
    .header h1 {{ margin: 0 0 6px 0; font-size: 24px; }}
    .header p {{ margin: 0; color: var(--muted); font-size: 14px; }}
    .risk-dial {{
        text-align: right;
        background: rgba(244, 63, 94, 0.12);
        border: 1px solid var(--critical);
        padding: 14px 22px;
        border-radius: 10px;
    }}
    .risk-score {{ font-size: 34px; font-weight: 800; color: var(--critical); }}
    .kpi-grid {{
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 16px;
        margin-bottom: 28px;
    }}
    .kpi-card {{
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 18px 22px;
    }}
    .kpi-card .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; }}
    .kpi-card .val {{ font-size: 28px; font-weight: 700; margin-top: 6px; }}
    .section {{
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 24px 28px;
        margin-bottom: 28px;
    }}
    .section h2 {{ margin-top: 0; font-size: 19px; border-bottom: 1px solid var(--border); padding-bottom: 12px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13.5px; }}
    th, td {{ text-align: left; padding: 12px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 11.5px; }}
    .badge {{
        display: inline-block;
        padding: 3px 9px;
        border-radius: 999px;
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
    }}
    .badge-critical {{ background: rgba(244, 63, 94, 0.2); color: #FDA4AF; border: 1px solid #F43F5E; }}
    .badge-high {{ background: rgba(251, 146, 60, 0.2); color: #FDBA74; border: 1px solid #FB923C; }}
    .badge-medium {{ background: rgba(250, 204, 21, 0.18); color: #FDE047; border: 1px solid #FACC15; }}
    .badge-low {{ background: rgba(56, 189, 248, 0.2); color: #7DD3FC; border: 1px solid #38BDF8; }}
    .finding-title {{ font-weight: 600; margin-bottom: 4px; color: #F8FAFC; }}
    .finding-desc {{ color: var(--muted); margin-bottom: 6px; }}
    .finding-rem {{ color: #6EE7B7; font-size: 12.5px; }}
    .cis-tag {{ font-size: 11.5px; color: #CBD5E1; background: #0F172A; padding: 3px 7px; border-radius: 4px; }}
    .esc-card, .pol-card {{
        background: #0F172A;
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 16px 20px;
        margin-bottom: 14px;
    }}
    .esc-header, .pol-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }}
    .esc-vector {{ font-weight: 600; color: #FDA4AF; }}
    .hop-pill {{
        display: inline-block;
        background: #1E293B;
        border: 1px solid #475569;
        padding: 4px 10px;
        border-radius: 6px;
        font-family: monospace;
        font-weight: 600;
    }}
    .code-block {{
        background: #020617;
        color: #A7F3D0;
        padding: 14px;
        border-radius: 6px;
        overflow-x: auto;
        font-size: 12.5px;
        border: 1px solid #1E293B;
        margin: 0;
    }}
    .code-inline {{
        background: #020617;
        color: #E2E8F0;
        padding: 8px;
        border-radius: 4px;
        font-size: 11.5px;
        margin: 0;
    }}
    .sub-arn {{ font-size: 12px; color: var(--muted); font-family: monospace; }}
    h4 {{ margin: 0 0 2px 0; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1>AWS IAM Security Auditor &amp; Least-Privilege Policy Report</h1>
            <p>Account ID: <code>{self.account_id}</code> &bull; Generated: <code>{summary['generated_at']}</code> &bull; Mode: <strong>Dry-Run Enabled</strong></p>
        </div>
        <div class="risk-dial" style="background: {dial_bg}; border: 1px solid {dial_color};">
            <div class="risk-score" style="color: {dial_color};">{summary['risk_score']} / 100</div>
            <div style="font-size:12px; font-weight:600; color:{dial_color};">{summary['posture_rating']}</div>
        </div>
    </div>

    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="label">Critical Findings</div>
            <div class="val" style="color: var(--critical);">{sev_counts['CRITICAL']}</div>
        </div>
        <div class="kpi-card">
            <div class="label">High Findings</div>
            <div class="val" style="color: var(--high);">{sev_counts['HIGH']}</div>
        </div>
        <div class="kpi-card">
            <div class="label">Medium Findings</div>
            <div class="val" style="color: var(--medium);">{sev_counts['MEDIUM']}</div>
        </div>
        <div class="kpi-card">
            <div class="label">Escalation Paths to Admin</div>
            <div class="val" style="color: #F43F5E;">{len(self.escalation_paths)}</div>
        </div>
    </div>

    <div class="section">
        <h2>1. IAM Privilege Escalation Graph (NetworkX Analysis)</h2>
        <p style="color: var(--muted); font-size: 13.5px; margin-bottom: 16px;">
            Directed graph mapping non-admin IAM principals (red) capable of escalating to effective full account administration (dark red) via transitive <code>iam:PassRole</code>, <code>iam:CreatePolicyVersion</code>, <code>iam:AttachUserPolicy</code>, and <code>sts:AssumeRole</code> chains.
        </p>
        {graph_img_tag}
        <div style="margin-top: 20px;">
            {''.join(esc_cards)}
        </div>
    </div>

    <div class="section">
        <h2>2. Detailed Security Posture Findings ({len(self.findings)} Total)</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Severity</th>
                    <th>Category</th>
                    <th>Principal</th>
                    <th>Finding &amp; Remediation</th>
                    <th>Benchmark</th>
                </tr>
            </thead>
            <tbody>
                {''.join(findings_rows)}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>3. CloudTrail-Synthesized Least-Privilege Policies ({len(self.policy_suggestions)} Roles)</h2>
        <p style="color: var(--muted); font-size: 13.5px; margin-bottom: 16px;">
            Tightened IAM policy documents generated automatically from observed successful CloudTrail API calls and resource ARNs.
        </p>
        {''.join(policy_cards)}
    </div>

    <div class="section">
        <h2>4. Auto-Remediation Execution Plan (Dry-Run Guarded)</h2>
        <table>
            <thead>
                <tr>
                    <th>Action Type</th>
                    <th>Principal</th>
                    <th>Target Resource</th>
                    <th>Status</th>
                    <th>Boto3 API Payload</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rem_rows)}
            </tbody>
        </table>
    </div>
</div>
</body>
</html>
"""
        Path(output_path).write_text(html)
        return output_path
