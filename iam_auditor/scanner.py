"""Core IAM Posture Scanner supporting both live AWS boto3 sessions and offline snapshot fixtures."""
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from .models import Finding

try:
    import boto3
except ImportError:
    boto3 = None


HIGH_RISK_IAM_ACTIONS = {
    "iam:PassRole",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:CreateAccessKey",
    "iam:UpdateAssumeRolePolicy",
}


class IAMAuditScanner:
    """Scans AWS IAM configuration for security misconfigurations and CIS benchmark violations."""

    def __init__(
        self,
        snapshot_data: Optional[Dict[str, Any]] = None,
        boto3_session: Optional[Any] = None,
        stale_days_threshold: int = 90,
        reference_time: Optional[datetime] = None,
    ):
        self.stale_days_threshold = stale_days_threshold
        self.reference_time = reference_time or datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)
        self.snapshot_data = snapshot_data
        self.boto3_session = boto3_session
        self.findings: List[Finding] = []
        self._finding_counter = 0

    def _next_id(self, prefix: str = "IAM") -> str:
        self._finding_counter += 1
        return f"{prefix}-{self._finding_counter:03d}"

    def collect_from_boto3(self) -> Dict[str, Any]:
        """Collects IAM posture data from a live AWS account using boto3."""
        if self.boto3_session is None:
            if boto3 is None:
                raise RuntimeError("boto3 is not installed and no snapshot_data was provided.")
            self.boto3_session = boto3.Session()

        iam = self.boto3_session.client("iam")
        sts = self.boto3_session.client("sts")
        account_id = sts.get_caller_identity()["Account"]

        users_out = []
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for u in page.get("Users", []):
                uname = u["UserName"]
                mfa = iam.list_mfa_devices(UserName=uname).get("MFADevices", [])
                keys = []
                for k in iam.list_access_keys(UserName=uname).get("AccessKeyMetadata", []):
                    kid = k["AccessKeyId"]
                    last_used_resp = iam.get_access_key_last_used(AccessKeyId=kid).get("AccessKeyLastUsed", {})
                    keys.append({
                        "AccessKeyId": kid,
                        "Status": k["Status"],
                        "CreateDate": k["CreateDate"].isoformat() if hasattr(k["CreateDate"], "isoformat") else str(k["CreateDate"]),
                        "LastUsedDate": last_used_resp.get("LastUsedDate").isoformat()
                        if last_used_resp.get("LastUsedDate") and hasattr(last_used_resp.get("LastUsedDate"), "isoformat")
                        else None,
                    })
                attached = iam.list_attached_user_policies(UserName=uname).get("AttachedPolicies", [])
                inline_names = iam.list_user_policies(UserName=uname).get("PolicyNames", [])
                inline_docs = {}
                for iname in inline_names:
                    doc = iam.get_user_policy(UserName=uname, PolicyName=iname)["PolicyDocument"]
                    inline_docs[iname] = doc

                pwd_enabled = False
                try:
                    iam.get_login_profile(UserName=uname)
                    pwd_enabled = True
                except Exception:
                    pwd_enabled = False

                users_out.append({
                    "UserName": uname,
                    "Arn": u["Arn"],
                    "PasswordEnabled": pwd_enabled,
                    "MFADevices": [m["SerialNumber"] for m in mfa],
                    "AccessKeys": keys,
                    "AttachedPolicies": [a["PolicyArn"] for a in attached],
                    "InlinePolicies": inline_docs,
                })

        roles_out = []
        role_paginator = iam.get_paginator("list_roles")
        for page in role_paginator.paginate():
            for r in page.get("Roles", []):
                rname = r["RoleName"]
                role_detail = iam.get_role(RoleName=rname)["Role"]
                last_used = role_detail.get("RoleLastUsed", {}).get("LastUsedDate")
                attached = iam.list_attached_role_policies(RoleName=rname).get("AttachedPolicies", [])
                inline_names = iam.list_role_policies(RoleName=rname).get("PolicyNames", [])
                inline_docs = {}
                for iname in inline_names:
                    inline_docs[iname] = iam.get_role_policy(RoleName=rname, PolicyName=iname)["PolicyDocument"]

                cdate = r.get("CreateDate")
                cdate_str = cdate.isoformat() if hasattr(cdate, "isoformat") else str(cdate) if cdate else None
                roles_out.append({
                    "RoleName": rname,
                    "Arn": r.get("Arn", f"arn:aws:iam::{account_id}:role/{rname}"),
                    "CreateDate": cdate_str,
                    "LastUsedDate": last_used.isoformat() if last_used and hasattr(last_used, "isoformat") else None,
                    "AssumeRolePolicyDocument": r.get("AssumeRolePolicyDocument", {}),
                    "AttachedPolicies": [a.get("PolicyArn", str(a)) for a in attached],
                    "InlinePolicies": inline_docs,
                })

        policies_out = {}
        pol_paginator = iam.get_paginator("list_policies")
        for page in pol_paginator.paginate(Scope="Local"):
            for p in page.get("Policies", []):
                parn = p["Arn"]
                ver = iam.get_policy_version(PolicyArn=parn, VersionId=p["DefaultVersionId"])["PolicyVersion"]
                policies_out[parn] = {
                    "PolicyName": p["PolicyName"],
                    "Arn": parn,
                    "DefaultVersionId": p["DefaultVersionId"],
                    "Document": ver["Document"],
                }

        self.snapshot_data = {
            "account_id": account_id,
            "users": users_out,
            "roles": roles_out,
            "managed_policies": policies_out,
        }
        return self.snapshot_data

    def run_all_checks(self) -> List[Finding]:
        """Executes all security checks and returns list of findings."""
        if self.snapshot_data is None:
            self.collect_from_boto3()

        self.findings = []
        self.check_wildcard_policies()
        self.check_unused_roles()
        self.check_unused_access_keys()
        self.check_users_without_mfa()
        self.check_risky_trust_policies()
        return self.findings

    @staticmethod
    def _normalize_list(val: Any) -> List[Any]:
        if val is None:
            return []
        if isinstance(val, list):
            return val
        return [val]

    def _inspect_policy_document(
        self,
        doc: Dict[str, Any],
        principal_type: str,
        principal_name: str,
        principal_arn: str,
        policy_label: str,
    ) -> None:
        statements = self._normalize_list(doc.get("Statement", []))
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            actions = self._normalize_list(stmt.get("Action", []))
            resources = self._normalize_list(stmt.get("Resource", []))

            has_star_action = "*" in actions or "iam:*" in actions
            service_wildcards = [a for a in actions if a.endswith(":*") and a != "*"]
            has_star_resource = "*" in resources

            if "*" in actions and has_star_resource:
                self.findings.append(
                    Finding(
                        finding_id=self._next_id("WLD"),
                        category="WILDCARD_POLICY",
                        severity="CRITICAL",
                        principal_type=principal_type,
                        principal_name=principal_name,
                        principal_arn=principal_arn,
                        title=f"Full Administrative Wildcard (*:*) in {policy_label}",
                        description=(
                            f"{principal_type} '{principal_name}' grants Action '*' on Resource '*' via {policy_label}, "
                            "providing unrestricted administrative control across all AWS services."
                        ),
                        evidence={"policy": policy_label, "statement": stmt},
                        remediation="Replace '*' actions and resources with scoped service-level permissions generated from CloudTrail history.",
                        cis_benchmark="CIS AWS Foundations 1.16",
                    )
                )
            elif service_wildcards and has_star_resource:
                sev = "CRITICAL" if "iam:*" in service_wildcards else "HIGH"
                self.findings.append(
                    Finding(
                        finding_id=self._next_id("WLD"),
                        category="WILDCARD_POLICY",
                        severity=sev,
                        principal_type=principal_type,
                        principal_name=principal_name,
                        principal_arn=principal_arn,
                        title=f"Service-Level Wildcard ({', '.join(service_wildcards)}) on '*' in {policy_label}",
                        description=(
                            f"{principal_type} '{principal_name}' grants broad wildcard actions "
                            f"({', '.join(service_wildcards)}) across all resources ('*') in {policy_label}."
                        ),
                        evidence={"policy": policy_label, "wildcard_actions": service_wildcards, "statement": stmt},
                        remediation="Scope actions to exact API calls and restrict Resource ARNs to specific buckets, tables, or roles.",
                        cis_benchmark="CIS AWS Foundations 1.16",
                    )
                )

    def check_wildcard_policies(self) -> None:
        """Flags customer-managed and inline policies with '*' actions or resources."""
        managed = self.snapshot_data.get("managed_policies", {})
        for arn, pol in managed.items():
            self._inspect_policy_document(
                pol["Document"],
                principal_type="Policy",
                principal_name=pol["PolicyName"],
                principal_arn=arn,
                policy_label=f"ManagedPolicy:{pol['PolicyName']}",
            )

        for user in self.snapshot_data.get("users", []):
            for iname, doc in user.get("InlinePolicies", {}).items():
                self._inspect_policy_document(
                    doc,
                    principal_type="User",
                    principal_name=user["UserName"],
                    principal_arn=user["Arn"],
                    policy_label=f"InlinePolicy:{iname}",
                )
            for parn in user.get("AttachedPolicies", []):
                if parn.endswith(":policy/AdministratorAccess"):
                    self.findings.append(
                        Finding(
                            finding_id=self._next_id("WLD"),
                            category="WILDCARD_POLICY",
                            severity="CRITICAL",
                            principal_type="User",
                            principal_name=user["UserName"],
                            principal_arn=user["Arn"],
                            title=f"Full AdministratorAccess Managed Policy attached to User '{user['UserName']}'",
                            description=(
                                f"User '{user['UserName']}' has AWS-managed 'AdministratorAccess' attached, "
                                "granting unrestricted full administrative control across all AWS resources."
                            ),
                            evidence={"AttachedPolicyArn": parn},
                            remediation="Replace AdministratorAccess with scoped least-privilege policies.",
                            cis_benchmark="CIS AWS Foundations 1.16",
                        )
                    )

        for role in self.snapshot_data.get("roles", []):
            for iname, doc in role.get("InlinePolicies", {}).items():
                self._inspect_policy_document(
                    doc,
                    principal_type="Role",
                    principal_name=role["RoleName"],
                    principal_arn=role["Arn"],
                    policy_label=f"InlinePolicy:{iname}",
                )
            for parn in role.get("AttachedPolicies", []):
                if parn.endswith(":policy/AdministratorAccess"):
                    self.findings.append(
                        Finding(
                            finding_id=self._next_id("WLD"),
                            category="WILDCARD_POLICY",
                            severity="CRITICAL",
                            principal_type="Role",
                            principal_name=role["RoleName"],
                            principal_arn=role["Arn"],
                            title=f"Full AdministratorAccess Managed Policy attached to Role '{role['RoleName']}'",
                            description=(
                                f"Role '{role['RoleName']}' has AWS-managed 'AdministratorAccess' attached, "
                                "granting unrestricted full administrative control across all AWS resources."
                            ),
                            evidence={"AttachedPolicyArn": parn},
                            remediation="Replace AdministratorAccess with scoped least-privilege policies derived from CloudTrail.",
                            cis_benchmark="CIS AWS Foundations 1.16",
                        )
                    )

    def _days_since(self, iso_str: Optional[str]) -> Optional[int]:
        if not iso_str:
            return None
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return max(0, (self.reference_time - dt).days)

    def check_unused_roles(self) -> None:
        """Flags IAM roles that have never been used or have been inactive beyond threshold."""
        for role in self.snapshot_data.get("roles", []):
            last_used = role.get("LastUsedDate")
            create_days = self._days_since(role.get("CreateDate")) or 0
            unused_days = self._days_since(last_used)

            if last_used is None and create_days >= self.stale_days_threshold:
                self.findings.append(
                    Finding(
                        finding_id=self._next_id("ROL"),
                        category="UNUSED_ROLE",
                        severity="MEDIUM",
                        principal_type="Role",
                        principal_name=role["RoleName"],
                        principal_arn=role["Arn"],
                        title=f"Dormant IAM Role Never Used ({create_days} days old)",
                        description=(
                            f"Role '{role['RoleName']}' was created {create_days} days ago and has never been assumed."
                        ),
                        evidence={"CreateDate": role.get("CreateDate"), "LastUsedDate": None, "AgeDays": create_days},
                        remediation=f"Detach policies and delete unused role '{role['RoleName']}' after owner verification.",
                        cis_benchmark="CIS AWS Foundations 1.12",
                    )
                )
            elif unused_days is not None and unused_days >= self.stale_days_threshold:
                self.findings.append(
                    Finding(
                        finding_id=self._next_id("ROL"),
                        category="UNUSED_ROLE",
                        severity="MEDIUM",
                        principal_type="Role",
                        principal_name=role["RoleName"],
                        principal_arn=role["Arn"],
                        title=f"Stale IAM Role Inactive for {unused_days} Days",
                        description=(
                            f"Role '{role['RoleName']}' has not been assumed for {unused_days} days "
                            f"(threshold: {self.stale_days_threshold} days)."
                        ),
                        evidence={"LastUsedDate": last_used, "InactiveDays": unused_days},
                        remediation=f"Review and decommission stale role '{role['RoleName']}'.",
                        cis_benchmark="CIS AWS Foundations 1.12",
                    )
                )

    def check_unused_access_keys(self) -> None:
        """Flags active IAM user access keys that are unused or unrotated past threshold."""
        for user in self.snapshot_data.get("users", []):
            for key in user.get("AccessKeys", []):
                if key.get("Status") != "Active":
                    continue
                kid = key["AccessKeyId"]
                age_days = self._days_since(key.get("CreateDate")) or 0
                last_used = key.get("LastUsedDate")
                inactive_days = self._days_since(last_used)

                if last_used is None and age_days >= self.stale_days_threshold:
                    self.findings.append(
                        Finding(
                            finding_id=self._next_id("KEY"),
                            category="UNUSED_ACCESS_KEY",
                            severity="HIGH",
                            principal_type="User",
                            principal_name=user["UserName"],
                            principal_arn=user["Arn"],
                            title=f"Active Access Key ({kid}) Never Used ({age_days} days old)",
                            description=(
                                f"User '{user['UserName']}' has an active access key '{kid}' created {age_days} days ago "
                                "that has never been used."
                            ),
                            evidence={"AccessKeyId": kid, "CreateDate": key.get("CreateDate"), "LastUsedDate": None, "AgeDays": age_days},
                            remediation=f"aws iam update-access-key --user-name {user['UserName']} --access-key-id {kid} --status Inactive",
                            cis_benchmark="CIS AWS Foundations 1.12 / 1.14",
                        )
                    )
                elif inactive_days is not None and inactive_days >= self.stale_days_threshold:
                    self.findings.append(
                        Finding(
                            finding_id=self._next_id("KEY"),
                            category="UNUSED_ACCESS_KEY",
                            severity="HIGH",
                            principal_type="User",
                            principal_name=user["UserName"],
                            principal_arn=user["Arn"],
                            title=f"Stale Access Key ({kid}) Unused for {inactive_days} Days",
                            description=(
                                f"User '{user['UserName']}' has an active access key '{kid}' last used {inactive_days} days ago "
                                f"(created {age_days} days ago)."
                            ),
                            evidence={"AccessKeyId": kid, "LastUsedDate": last_used, "InactiveDays": inactive_days, "AgeDays": age_days},
                            remediation=f"aws iam update-access-key --user-name {user['UserName']} --access-key-id {kid} --status Inactive",
                            cis_benchmark="CIS AWS Foundations 1.12 / 1.14",
                        )
                    )

    def check_users_without_mfa(self) -> None:
        """Flags console-enabled IAM users lacking an active MFA device."""
        for user in self.snapshot_data.get("users", []):
            if user.get("PasswordEnabled", False) and not user.get("MFADevices"):
                self.findings.append(
                    Finding(
                        finding_id=self._next_id("MFA"),
                        category="MISSING_MFA",
                        severity="HIGH",
                        principal_type="User",
                        principal_name=user["UserName"],
                        principal_arn=user["Arn"],
                        title=f"Console User '{user['UserName']}' Lacks Multi-Factor Authentication (MFA)",
                        description=(
                            f"IAM User '{user['UserName']}' has an active console password login profile "
                            "without any registered virtual or hardware MFA device."
                        ),
                        evidence={"PasswordEnabled": True, "MFADevices": []},
                        remediation=f"Enforce MFA via IAM condition 'aws:MultiFactorAuthPresent' and enroll MFA for '{user['UserName']}'.",
                        cis_benchmark="CIS AWS Foundations 1.10",
                    )
                )

    def check_risky_trust_policies(self) -> None:
        """Flags AssumeRole trust policies allowing wildcard principals or external cross-account access without ExternalId/MFA."""
        account_id = self.snapshot_data.get("account_id", "123456789012")
        for role in self.snapshot_data.get("roles", []):
            trust_doc = role.get("AssumeRolePolicyDocument", {})
            for stmt in self._normalize_list(trust_doc.get("Statement", [])):
                if stmt.get("Effect") != "Allow":
                    continue
                principal = stmt.get("Principal", {})
                aws_principals = []
                if principal == "*":
                    aws_principals = ["*"]
                elif isinstance(principal, dict):
                    aws_principals = self._normalize_list(principal.get("AWS", []))

                condition = stmt.get("Condition", {})
                has_external_id = "sts:ExternalId" in str(condition)
                has_mfa_cond = "aws:MultiFactorAuthPresent" in str(condition)

                for p in aws_principals:
                    if p == "*":
                        self.findings.append(
                            Finding(
                                finding_id=self._next_id("TRS"),
                                category="RISKY_TRUST_POLICY",
                                severity="CRITICAL",
                                principal_type="Role",
                                principal_name=role["RoleName"],
                                principal_arn=role["Arn"],
                                title=f"Public Wildcard Principal ('*') in Trust Policy for '{role['RoleName']}'",
                                description=(
                                    f"Role '{role['RoleName']}' allows ANY AWS account or principal ('*') to assume the role!"
                                ),
                                evidence={"Principal": p, "Condition": condition},
                                remediation="Restrict AssumeRolePolicyDocument Principal to explicit trusted ARNs and require sts:ExternalId.",
                                cis_benchmark="AWS IAM Best Practices - Trust Policies",
                            )
                        )
                    elif f":{account_id}:" not in p and p.startswith("arn:aws:iam::"):
                        if not has_external_id and not has_mfa_cond:
                            self.findings.append(
                                Finding(
                                    finding_id=self._next_id("TRS"),
                                    category="RISKY_TRUST_POLICY",
                                    severity="HIGH",
                                    principal_type="Role",
                                    principal_name=role["RoleName"],
                                    principal_arn=role["Arn"],
                                    title=f"Unconstrained Cross-Account Trust on '{role['RoleName']}'",
                                    description=(
                                        f"Role '{role['RoleName']}' trusts external principal '{p}' (especially broad ':root') "
                                        "without requiring 'sts:ExternalId' or 'aws:MultiFactorAuthPresent' conditions."
                                    ),
                                    evidence={"ExternalPrincipal": p, "Condition": condition},
                                    remediation="Add a Condition block requiring sts:ExternalId and scope Principal from ':root' to a specific role ARN.",
                                    cis_benchmark="AWS Security Incident Response Guide - Confused Deputy",
                                )
                            )
