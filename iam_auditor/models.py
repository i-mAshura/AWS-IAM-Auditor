"""Data models and risk scoring structures for the AWS IAM Auditor."""
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional


SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 12,
    "LOW": 5,
}


@dataclass
class Finding:
    finding_id: str
    category: str  # WILDCARD_POLICY, UNUSED_ROLE, UNUSED_ACCESS_KEY, MISSING_MFA, RISKY_TRUST_POLICY, PRIV_ESC_PATH
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    principal_type: str  # User, Role, Policy
    principal_name: str
    principal_arn: str
    title: str
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    cis_benchmark: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EscalationPath:
    source_principal: str
    target_principal: str
    vector: str
    required_permissions: List[str]
    hop_chain: List[str]
    severity: str = "CRITICAL"
    mitigation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LeastPrivilegeSuggestion:
    role_name: str
    role_arn: str
    observed_event_count: int
    current_wildcard_actions: List[str]
    generated_policy: Dict[str, Any]
    removed_high_risk_permissions: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RemediationAction:
    action_type: str  # DISABLE_ACCESS_KEY, REPLACE_ROLE_POLICY
    principal_name: str
    target_id: str
    dry_run: bool
    executed: bool
    status: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
