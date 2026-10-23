"""CloudTrail Log Parser and Least-Privilege IAM Policy Synthesizer."""
import json
from pathlib import Path
from typing import Dict, List, Any, Set, Tuple
from collections import defaultdict
from .models import LeastPrivilegeSuggestion


# Mapping between AWS eventSource domains and IAM service prefixes where they differ
EVENT_SOURCE_TO_IAM_PREFIX = {
    "monitoring.amazonaws.com": "cloudwatch",
    "logs.amazonaws.com": "logs",
    "signin.amazonaws.com": "signin",
    "sts.amazonaws.com": "sts",
    "s3.amazonaws.com": "s3",
    "dynamodb.amazonaws.com": "dynamodb",
    "ec2.amazonaws.com": "ec2",
    "lambda.amazonaws.com": "lambda",
    "iam.amazonaws.com": "iam",
    "kms.amazonaws.com": "kms",
    "sqs.amazonaws.com": "sqs",
    "sns.amazonaws.com": "sns",
    "secretsmanager.amazonaws.com": "secretsmanager",
}


class CloudTrailPolicyGenerator:
    """Parses AWS CloudTrail events and synthesizes scoped least-privilege IAM policies per role."""

    def __init__(self, account_id: str = "123456789012", default_region: str = "us-east-1"):
        self.account_id = account_id
        self.default_region = default_region
        self.role_actions: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
        self.role_event_counts: Dict[str, int] = defaultdict(int)

    @staticmethod
    def _service_prefix(event_source: str) -> str:
        if event_source in EVENT_SOURCE_TO_IAM_PREFIX:
            return EVENT_SOURCE_TO_IAM_PREFIX[event_source]
        return event_source.split(".")[0]

    def _extract_resource_arns(self, event: Dict[str, Any], service: str, event_name: str) -> Set[str]:
        arns: Set[str] = set()
        region = event.get("awsRegion", self.default_region)

        # 1. Explicit resources array in CloudTrail event
        for r in event.get("resources", []) or []:
            if isinstance(r, dict) and r.get("ARN"):
                arns.add(r["ARN"])

        # 2. RequestParameters extraction for common AWS services
        req = event.get("requestParameters") or {}
        if service == "s3":
            bucket = req.get("bucketName")
            key = req.get("key")
            if bucket:
                if key or event_name.lower().startswith(("getobject", "putobject", "deleteobject")):
                    arns.add(f"arn:aws:s3:::{bucket}/*")
                else:
                    arns.add(f"arn:aws:s3:::{bucket}")
        elif service == "dynamodb":
            table_name = req.get("tableName")
            if table_name:
                arns.add(f"arn:aws:dynamodb:{region}:{self.account_id}:table/{table_name}")
        elif service == "sqs":
            queue_url = req.get("queueUrl", "")
            if queue_url:
                qname = queue_url.rstrip("/").split("/")[-1]
                arns.add(f"arn:aws:sqs:{region}:{self.account_id}:{qname}")
        elif service == "secretsmanager":
            secret_id = req.get("secretId")
            if secret_id:
                if secret_id.startswith("arn:aws:"):
                    arns.add(secret_id)
                else:
                    arns.add(f"arn:aws:secretsmanager:{region}:{self.account_id}:secret:{secret_id}*")
        elif service == "lambda":
            fn_name = req.get("functionName")
            if fn_name:
                if fn_name.startswith("arn:aws:"):
                    arns.add(fn_name)
                else:
                    arns.add(f"arn:aws:lambda:{region}:{self.account_id}:function:{fn_name}")
        elif service == "kms":
            key_id = req.get("keyId")
            if key_id:
                if key_id.startswith("arn:aws:"):
                    arns.add(key_id)
                else:
                    arns.add(f"arn:aws:kms:{region}:{self.account_id}:key/{key_id}")
        elif service == "sns":
            topic_arn = req.get("topicArn")
            if topic_arn:
                arns.add(topic_arn)
        elif service == "logs":
            log_group = req.get("logGroupName")
            if log_group:
                arns.add(f"arn:aws:logs:{region}:{self.account_id}:log-group:{log_group}:*")

        # 3. Fallback when API action does not support resource-level permissions (e.g., Describe*, List*)
        if not arns:
            arns.add("*")

        return arns

    def ingest_events(self, events: List[Dict[str, Any]]) -> None:
        """Ingests a list of CloudTrail event records, filtering out denied/failed calls."""
        for ev in events:
            # Skip failed/unauthorized API calls so attackers probing permissions don't get added to policy
            if ev.get("errorCode") or ev.get("errorMessage"):
                continue

            user_identity = ev.get("userIdentity", {})
            role_name = None

            if user_identity.get("type") == "AssumedRole":
                session_issuer = user_identity.get("sessionContext", {}).get("sessionIssuer", {})
                role_name = session_issuer.get("userName")
                if not role_name and user_identity.get("arn"):
                    parts = user_identity["arn"].split("/")
                    if len(parts) >= 2:
                        role_name = parts[1]
            elif user_identity.get("type") == "IAMUser":
                continue

            if not role_name:
                continue

            event_source = ev.get("eventSource", "")
            event_name = ev.get("eventName", "")
            if not event_source or not event_name:
                continue

            service = self._service_prefix(event_source)
            action = f"{service}:{event_name}"
            resources = self._extract_resource_arns(ev, service, event_name)

            self.role_event_counts[role_name] += 1
            for r_arn in resources:
                self.role_actions[role_name][action].add(r_arn)

    def load_cloudtrail_directory(self, directory_path: str) -> None:
        """Loads all JSON CloudTrail log files from a directory."""
        p = Path(directory_path)
        for jf in sorted(p.glob("*.json")):
            try:
                data = json.loads(jf.read_text())
                if isinstance(data, dict):
                    records = data.get("Records", [data] if "eventSource" in data else [])
                elif isinstance(data, list):
                    records = data
                else:
                    records = []
                self.ingest_events(records)
            except Exception:
                continue

    def generate_policy_for_role(self, role_name: str) -> Dict[str, Any]:
        """Generates a clean, grouped IAM policy document for a given role."""
        action_map = self.role_actions.get(role_name, {})
        # Group actions that share the exact same sorted tuple of resource ARNs and service prefix
        grouped: Dict[Tuple[str, Tuple[str, ...]], List[str]] = defaultdict(list)
        for action, res_set in sorted(action_map.items()):
            service = action.split(":")[0]
            res_tuple = tuple(sorted(res_set))
            grouped[(service, res_tuple)].append(action)

        statements = []
        for idx, ((service, res_tuple), actions) in enumerate(sorted(grouped.items()), start=1):
            sid = f"LeastPrivilege{service.capitalize()}{idx}"
            statements.append({
                "Sid": sid,
                "Effect": "Allow",
                "Action": sorted(actions),
                "Resource": list(res_tuple),
            })

        return {
            "Version": "2012-10-17",
            "Statement": statements,
        }

    def build_suggestions(self, snapshot_data: Dict[str, Any]) -> List[LeastPrivilegeSuggestion]:
        """Compares current role policies against CloudTrail usage to produce tightening suggestions."""
        suggestions: List[LeastPrivilegeSuggestion] = []
        managed_map = snapshot_data.get("managed_policies", {})

        for role in snapshot_data.get("roles", []):
            rname = role["RoleName"]
            if rname not in self.role_actions:
                continue

            # Gather current wildcard or broad actions on the role
            current_wildcards: List[str] = []
            removed_high_risk: List[str] = []

            all_stmts = []
            for parn in role.get("AttachedPolicies", []):
                if parn.endswith(":policy/AdministratorAccess"):
                    all_stmts.append({"Effect": "Allow", "Action": ["*"], "Resource": ["*"]})
                elif parn in managed_map:
                    doc = managed_map[parn]["Document"]
                    stmts = doc.get("Statement", [])
                    all_stmts.extend(stmts if isinstance(stmts, list) else [stmts])
            for _, doc in role.get("InlinePolicies", {}).items():
                stmts = doc.get("Statement", [])
                all_stmts.extend(stmts if isinstance(stmts, list) else [stmts])

            observed_actions = set(self.role_actions[rname].keys())

            for s in all_stmts:
                if s.get("Effect") != "Allow":
                    continue
                acts = s.get("Action", [])
                acts = acts if isinstance(acts, list) else [acts]
                for a in acts:
                    if "*" in a:
                        current_wildcards.append(a)
                    elif a not in observed_actions:
                        removed_high_risk.append(a)

            if current_wildcards:
                removed_high_risk.extend([
                    f"Wildcard '{w}' replaced with {len(observed_actions)} explicit CloudTrail-verified actions"
                    for w in sorted(set(current_wildcards))
                ])

            gen_policy = self.generate_policy_for_role(rname)
            suggestions.append(
                LeastPrivilegeSuggestion(
                    role_name=rname,
                    role_arn=role["Arn"],
                    observed_event_count=self.role_event_counts[rname],
                    current_wildcard_actions=sorted(set(current_wildcards)),
                    generated_policy=gen_policy,
                    removed_high_risk_permissions=removed_high_risk,
                )
            )

        return suggestions
