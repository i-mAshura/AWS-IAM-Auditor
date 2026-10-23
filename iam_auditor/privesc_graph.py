"""Privilege Escalation Graph Analyzer using NetworkX and Matplotlib."""
from typing import Dict, List, Any, Set, Tuple, Iterator
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

class _CompatDiGraph:
    """NetworkX-compatible DiGraph fallback for restricted/offline Python environments."""
    def __init__(self):
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._adj: Dict[str, Dict[str, Dict[str, Any]]] = {}

    def clear(self) -> None:
        self._nodes.clear()
        self._adj.clear()

    def add_node(self, node_id: str, **attrs: Any) -> None:
        if node_id not in self._nodes:
            self._nodes[node_id] = {}
            self._adj[node_id] = {}
        self._nodes[node_id].update(attrs)

    def add_edge(self, u: str, v: str, **attrs: Any) -> None:
        if u not in self._nodes:
            self.add_node(u)
        if v not in self._nodes:
            self.add_node(v)
        self._adj[u][v] = dict(attrs)

    @property
    def nodes(self):
        outer = self
        class _NodeView:
            def __call__(self, data: bool = False):
                if data:
                    return list(outer._nodes.items())
                return list(outer._nodes.keys())
            def __len__(self):
                return len(outer._nodes)
            def __getitem__(self, item: str):
                return outer._nodes[item]
            def __iter__(self):
                return iter(outer._nodes)
        return _NodeView()

    def edges(self, data: bool = False):
        res = []
        for u, nbrs in self._adj.items():
            for v, d in nbrs.items():
                res.append((u, v, d) if data else (u, v))
        return res

    def get_edge_data(self, u: str, v: str, default=None):
        return self._adj.get(u, {}).get(v, default)

    def neighbors(self, u: str) -> Iterator[str]:
        return iter(self._adj.get(u, {}).keys())


class _CompatNX:
    DiGraph = _CompatDiGraph

    @staticmethod
    def has_path(G: _CompatDiGraph, source: str, target: str) -> bool:
        visited = set()
        stack = [source]
        while stack:
            curr = stack.pop()
            if curr == target:
                return True
            if curr not in visited:
                visited.add(curr)
                stack.extend(G.neighbors(curr))
        return False

    @staticmethod
    def all_simple_paths(G: _CompatDiGraph, source: str, target: str, cutoff: int = 5) -> List[List[str]]:
        paths: List[List[str]] = []
        def _dfs(curr: str, path: List[str]):
            if len(path) - 1 > cutoff:
                return
            if curr == target:
                paths.append(list(path))
                return
            for nbr in G.neighbors(curr):
                if nbr not in path:
                    path.append(nbr)
                    _dfs(nbr, path)
                    path.pop()
        _dfs(source, [source])
        return paths


try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False
    nx = _CompatNX()

from .models import EscalationPath, Finding


class PrivilegeEscalationAnalyzer:
    """Builds a directed graph of IAM principals, permissions, and escalation paths to Admin."""

    def __init__(self, snapshot_data: Dict[str, Any]):
        self.snapshot_data = snapshot_data
        self.graph = nx.DiGraph()
        self.escalation_paths: List[EscalationPath] = []
        self.admin_nodes: Set[str] = set()

    @staticmethod
    def _normalize_list(val: Any) -> List[Any]:
        if val is None:
            return []
        return val if isinstance(val, list) else [val]

    def _get_effective_statements(self, principal: Dict[str, Any]) -> List[Dict[str, Any]]:
        managed_map = self.snapshot_data.get("managed_policies", {})
        stmts = []
        for pol_arn in principal.get("AttachedPolicies", []):
            if pol_arn.endswith(":policy/AdministratorAccess"):
                stmts.append({"Effect": "Allow", "Action": ["*"], "Resource": ["*"], "_source": "AdministratorAccess"})
            elif pol_arn in managed_map:
                doc = managed_map[pol_arn]["Document"]
                for s in self._normalize_list(doc.get("Statement", [])):
                    s_copy = dict(s)
                    s_copy["_source"] = managed_map[pol_arn]["PolicyName"]
                    stmts.append(s_copy)
        for iname, doc in principal.get("InlinePolicies", {}).items():
            for s in self._normalize_list(doc.get("Statement", [])):
                s_copy = dict(s)
                s_copy["_source"] = f"Inline:{iname}"
                stmts.append(s_copy)
        return stmts

    @staticmethod
    def _action_matches(granted_actions: List[str], target_action: str) -> bool:
        target_service, _ = target_action.split(":", 1)
        for a in granted_actions:
            if a == "*" or a.lower() == target_action.lower() or a.lower() == f"{target_service.lower()}:*":
                return True
        return False

    def build_graph(self):
        """Constructs the IAM privilege graph and identifies direct and multi-hop paths to Admin."""
        self.graph.clear()
        self.admin_nodes.clear()
        self.escalation_paths.clear()

        admin_target = "AWS_ACCOUNT_ADMIN"
        self.graph.add_node(admin_target, node_type="AdminTarget", label="AWS Account Admin\n(*:*)", is_admin=True)
        self.admin_nodes.add(admin_target)

        principals: List[Tuple[str, Dict[str, Any]]] = []
        for u in self.snapshot_data.get("users", []):
            principals.append(("User", u))
        for r in self.snapshot_data.get("roles", []):
            principals.append(("Role", r))

        principal_stmts: Dict[str, List[Dict[str, Any]]] = {}
        role_trust_services: Dict[str, List[str]] = {}

        for ptype, p in principals:
            name = p["UserName"] if ptype == "User" else p["RoleName"]
            node_id = f"{ptype}:{name}"
            stmts = self._get_effective_statements(p)
            principal_stmts[node_id] = stmts

            is_admin = False
            for s in stmts:
                if s.get("Effect") == "Allow":
                    acts = self._normalize_list(s.get("Action", []))
                    res = self._normalize_list(s.get("Resource", []))
                    if ("*" in acts or "iam:*" in acts) and "*" in res:
                        is_admin = True
                        break

            self.graph.add_node(
                node_id,
                node_type=ptype,
                label=f"{ptype}\n{name}",
                arn=p["Arn"],
                is_admin=is_admin,
            )
            if is_admin:
                self.admin_nodes.add(node_id)
                self.graph.add_edge(
                    node_id,
                    admin_target,
                    vector="DirectAdminPolicy",
                    permissions=["*:*"],
                    label="Full Admin (*:*)",
                )

            if ptype == "Role":
                trust = p.get("AssumeRolePolicyDocument", {})
                services = []
                allows_all = False
                for ts in self._normalize_list(trust.get("Statement", [])):
                    if ts.get("Effect") == "Allow":
                        princ = ts.get("Principal", {})
                        if princ == "*":
                            allows_all = True
                        elif isinstance(princ, dict):
                            if princ.get("AWS") == "*" or "*" in self._normalize_list(princ.get("AWS", [])):
                                allows_all = True
                            if "Service" in princ:
                                services.extend(self._normalize_list(princ["Service"]))
                role_trust_services[node_id] = (services, allows_all)

        for ptype, p in principals:
            name = p["UserName"] if ptype == "User" else p["RoleName"]
            node_id = f"{ptype}:{name}"
            if node_id in self.admin_nodes:
                continue

            stmts = principal_stmts[node_id]
            allowed_actions: List[str] = []
            allowed_resources_by_action: List[Tuple[List[str], List[str]]] = []
            for s in stmts:
                if s.get("Effect") == "Allow":
                    acts = self._normalize_list(s.get("Action", []))
                    res = self._normalize_list(s.get("Resource", []))
                    allowed_actions.extend(acts)
                    allowed_resources_by_action.append((acts, res))

            if self._action_matches(allowed_actions, "iam:CreatePolicyVersion"):
                self.graph.add_edge(
                    node_id,
                    admin_target,
                    vector="CreatePolicyVersion",
                    permissions=["iam:CreatePolicyVersion"],
                    label="iam:CreatePolicyVersion\n(SetAsDefault=true)",
                )
            elif self._action_matches(allowed_actions, "iam:SetDefaultPolicyVersion"):
                self.graph.add_edge(
                    node_id,
                    admin_target,
                    vector="SetDefaultPolicyVersion",
                    permissions=["iam:SetDefaultPolicyVersion"],
                    label="iam:SetDefaultPolicyVersion",
                )

            for attach_act in ("iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:AttachGroupPolicy"):
                if self._action_matches(allowed_actions, attach_act):
                    self.graph.add_edge(
                        node_id,
                        admin_target,
                        vector=attach_act.split(":")[1],
                        permissions=[attach_act],
                        label=attach_act,
                    )

            if self._action_matches(allowed_actions, "iam:CreateAccessKey"):
                for other_u in self.snapshot_data.get("users", []):
                    target_uid = f"User:{other_u['UserName']}"
                    if target_uid != node_id:
                        self.graph.add_edge(
                            node_id,
                            target_uid,
                            vector="CreateAccessKey",
                            permissions=["iam:CreateAccessKey"],
                            label="iam:CreateAccessKey",
                        )

            for acts, res_list in allowed_resources_by_action:
                if self._action_matches(acts, "sts:AssumeRole"):
                    for r in self.snapshot_data.get("roles", []):
                        target_rid = f"Role:{r['RoleName']}"
                        r_arn = r["Arn"]
                        if "*" in res_list or r_arn in res_list:
                            trust_str = str(r.get("AssumeRolePolicyDocument", {}))
                            if self.snapshot_data.get("account_id", "") in trust_str or '"*"' in trust_str or "'*'" in trust_str:
                                self.graph.add_edge(
                                    node_id,
                                    target_rid,
                                    vector="AssumeRole",
                                    permissions=["sts:AssumeRole"],
                                    label="sts:AssumeRole",
                                )

            if self._action_matches(allowed_actions, "iam:PassRole"):
                compute_triggers = []
                for trigger_act, svc_domain in [
                    ("lambda:CreateFunction", "lambda.amazonaws.com"),
                    ("ec2:RunInstances", "ec2.amazonaws.com"),
                    ("ecs:RunTask", "ecs-tasks.amazonaws.com"),
                    ("glue:CreateDevEndpoint", "glue.amazonaws.com"),
                ]:
                    if self._action_matches(allowed_actions, trigger_act):
                        compute_triggers.append((trigger_act, svc_domain))

                if compute_triggers:
                    passable_roles = []
                    for acts, res_list in allowed_resources_by_action:
                        if self._action_matches(acts, "iam:PassRole"):
                            for r in self.snapshot_data.get("roles", []):
                                r_id = f"Role:{r['RoleName']}"
                                if "*" in res_list or r["Arn"] in res_list:
                                    passable_roles.append(r_id)

                    for target_rid in set(passable_roles):
                        trusted_svcs, allows_all = role_trust_services.get(target_rid, ([], False))
                        for trigger_act, svc_domain in compute_triggers:
                            if svc_domain in trusted_svcs or allows_all:
                                perms = ["iam:PassRole", trigger_act]
                                self.graph.add_edge(
                                    node_id,
                                    target_rid,
                                    vector=f"PassRole+{trigger_act.split(':')[1]}",
                                    permissions=perms,
                                    label=f"iam:PassRole +\n{trigger_act}",
                                )

        for node_id, data in self.graph.nodes(data=True):
            if node_id == admin_target or data.get("is_admin", False):
                continue
            if nx.has_path(self.graph, node_id, admin_target):
                for path in nx.all_simple_paths(self.graph, source=node_id, target=admin_target, cutoff=5):
                    vectors = []
                    perms = []
                    for i in range(len(path) - 1):
                        edge_data = self.graph.get_edge_data(path[i], path[i + 1])
                        vectors.append(edge_data.get("vector", "Unknown"))
                        perms.extend(edge_data.get("permissions", []))

                    vector_chain = " -> ".join(vectors)
                    self.escalation_paths.append(
                        EscalationPath(
                            source_principal=node_id,
                            target_principal=path[-1],
                            vector=vector_chain,
                            required_permissions=list(dict.fromkeys(perms)),
                            hop_chain=path,
                            severity="CRITICAL",
                            mitigation=(
                                f"Restrict {', '.join(list(dict.fromkeys(perms)))} on '{node_id}' "
                                "with explicit resource ARNs and IAM Permissions Boundaries."
                            ),
                        )
                    )

        return self.graph

    def to_findings(self) -> List[Finding]:
        """Converts discovered privilege escalation paths into standard scanner Findings."""
        findings: List[Finding] = []
        for idx, esc in enumerate(self.escalation_paths, start=1):
            ptype, pname = esc.source_principal.split(":", 1)
            node_meta = self.graph.nodes[esc.source_principal]
            findings.append(
                Finding(
                    finding_id=f"ESC-{idx:03d}",
                    category="PRIV_ESC_PATH",
                    severity="CRITICAL",
                    principal_type=ptype,
                    principal_name=pname,
                    principal_arn=node_meta.get("arn", ""),
                    title=f"Privilege Escalation Path to Admin via {esc.vector}",
                    description=(
                        f"Principal '{esc.source_principal}' can escalate to full administrative privileges "
                        f"through hop chain: {' -> '.join(esc.hop_chain)} using ({', '.join(esc.required_permissions)})."
                    ),
                    evidence={
                        "hop_chain": esc.hop_chain,
                        "vector": esc.vector,
                        "required_permissions": esc.required_permissions,
                    },
                    remediation=esc.mitigation,
                    cis_benchmark="MITRE ATT&CK Cloud T1078 / Rhino Security Labs IAM Escalation Matrix",
                )
            )
        return findings

    def export_graph_image(self, output_png_path: str) -> str:
        """Renders the privilege escalation graph to a clean high-DPI PNG image."""
        if len(self.graph.nodes) == 0:
            self.build_graph()

        fig, ax = plt.subplots(figsize=(12.5, 7.5), dpi=180)
        fig.patch.set_facecolor("#0F172A")
        ax.set_facecolor("#0F172A")

        admin_target = "AWS_ACCOUNT_ADMIN"
        escalating_sources = {esc.source_principal for esc in self.escalation_paths}

        layers: Dict[int, List[str]] = {0: [], 1: [], 2: [], 3: []}
        for node, data in self.graph.nodes(data=True):
            if node == admin_target:
                layers[3].append(node)
            elif data.get("is_admin"):
                layers[2].append(node)
            elif node in escalating_sources:
                layers[0].append(node)
            else:
                layers[1].append(node)

        pos: Dict[str, Tuple[float, float]] = {}
        x_coords = {0: 0.14, 1: 0.40, 2: 0.66, 3: 0.90}
        for layer_idx, nodes in layers.items():
            nodes_sorted = sorted(nodes)
            count = len(nodes_sorted)
            for i, n in enumerate(nodes_sorted):
                y = 0.52 if count == 1 else 0.18 + 0.68 * (i / (count - 1))
                pos[n] = (x_coords[layer_idx], y)

        escalation_edges = set()
        for esc in self.escalation_paths:
            for i in range(len(esc.hop_chain) - 1):
                escalation_edges.add((esc.hop_chain[i], esc.hop_chain[i + 1]))

        # Draw edges and labels using Matplotlib FancyArrowPatch for crisp rendering
        for u, v, d in self.graph.edges(data=True):
            x1, y1 = pos[u]
            x2, y2 = pos[v]
            is_esc = (u, v) in escalation_edges
            color = "#F43F5E" if is_esc else "#64748B"
            lw = 2.4 if is_esc else 1.5

            ax.annotate(
                "",
                xy=(x2, y2),
                xytext=(x1, y1),
                arrowprops=dict(
                    arrowstyle="-|>,head_length=0.9,head_width=0.5",
                    color=color,
                    lw=lw,
                    shrinkA=38,
                    shrinkB=38,
                    connectionstyle="arc3,rad=0.07",
                ),
                zorder=2,
            )

            mx = (x1 + x2) / 2.0
            my = (y1 + y2) / 2.0 + 0.035
            edge_lbl = d.get("label", d.get("vector", ""))
            if edge_lbl:
                ax.text(
                    mx,
                    my,
                    edge_lbl,
                    fontsize=7.5,
                    color="#FDE047",
                    ha="center",
                    va="center",
                    bbox=dict(boxstyle="round,pad=0.25", fc="#1E293B", ec="#475569", alpha=0.94),
                    zorder=4,
                )

        # Draw nodes
        for n, data in self.graph.nodes(data=True):
            x, y = pos[n]
            if n == admin_target:
                fc, ec = "#991B1B", "#FCA5A5"
            elif data.get("is_admin"):
                fc, ec = "#B45309", "#FCD34D"
            elif n in escalating_sources:
                fc, ec = "#BE123C", "#FDA4AF"
            else:
                fc, ec = "#1E3A8A", "#93C5FD"

            ax.scatter(
                [x],
                [y],
                s=3600,
                c=[fc],
                edgecolors=[ec],
                linewidths=2.5,
                zorder=3,
            )
            ax.text(
                x,
                y,
                data.get("label", n),
                fontsize=8.2,
                fontweight="bold",
                color="#F8FAFC",
                ha="center",
                va="center",
                zorder=5,
            )

        ax.set_title(
            "AWS IAM Privilege Escalation Attack Graph (NetworkX Analysis)",
            fontsize=14,
            fontweight="bold",
            color="#F8FAFC",
            pad=16,
        )

        legend_handles = [
            mpatches.Patch(facecolor="#BE123C", edgecolor="#FDA4AF", label="Escalation Source Principal (Non-Admin)"),
            mpatches.Patch(facecolor="#B45309", edgecolor="#FCD34D", label="Privileged / Admin Role (Intermediate Hop)"),
            mpatches.Patch(facecolor="#991B1B", edgecolor="#FCA5A5", label="Effective Account Admin Target (*:*)"),
            mpatches.Patch(facecolor="#1E3A8A", edgecolor="#93C5FD", label="Non-Escalating Principal"),
        ]
        ax.legend(
            handles=legend_handles,
            loc="lower left",
            frameon=True,
            facecolor="#1E293B",
            edgecolor="#334155",
            labelcolor="#F8FAFC",
            fontsize=8.5,
        )

        ax.set_xlim(0.0, 1.04)
        ax.set_ylim(0.02, 0.98)
        ax.axis("off")
        plt.tight_layout()
        plt.savefig(output_png_path, dpi=180, facecolor=fig.get_facecolor())
        plt.close(fig)
        return output_png_path
