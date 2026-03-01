from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

import yaml


@dataclass(frozen=True)
class Subject:
    kind: str
    name: str
    namespace: str | None = None

    def key(self) -> str:
        ns = self.namespace or "*"
        return f"{self.kind}:{ns}:{self.name}"


@dataclass
class Rule:
    api_groups: list[str]
    resources: list[str]
    verbs: list[str]
    resource_names: list[str]
    non_resource_urls: list[str]


@dataclass
class BindingGrant:
    source_kind: str
    source_name: str
    binding_namespace: str | None
    role_ref_kind: str
    role_ref_name: str


RISKY_CAPABILITIES = [
    ("", "pods/exec", "create", "exec into pods"),
    ("", "pods/attach", "create", "attach to pods"),
    ("", "pods", "create", "create pods"),
    ("", "secrets", "get", "read secrets"),
    ("", "serviceaccounts/token", "create", "mint SA token"),
    ("rbac.authorization.k8s.io", "clusterrolebindings", "create", "bind cluster roles"),
    ("rbac.authorization.k8s.io", "rolebindings", "create", "bind roles"),
    ("", "pods", "impersonate", "impersonate via pod context"),
]


class RBACAnalyzer:
    def __init__(self, objects: list[dict[str, Any]]):
        self.objects = [obj for obj in objects if isinstance(obj, dict)]

        self.roles: dict[tuple[str, str], list[Rule]] = {}
        self.cluster_roles: dict[str, list[Rule]] = {}
        self.role_bindings: list[dict[str, Any]] = []
        self.cluster_role_bindings: list[dict[str, Any]] = []
        self.service_accounts: set[tuple[str, str]] = set()

        self._ingest()

    @classmethod
    def from_manifest(cls, manifest: str) -> "RBACAnalyzer":
        objects = [doc for doc in yaml.safe_load_all(manifest) if isinstance(doc, dict)]
        return cls(objects)

    @classmethod
    def from_objects(cls, objects: list[dict[str, Any]]) -> "RBACAnalyzer":
        return cls(objects)

    def _parse_rules(self, obj: dict[str, Any]) -> list[Rule]:
        out: list[Rule] = []
        for r in obj.get("rules", []) or []:
            out.append(
                Rule(
                    api_groups=r.get("apiGroups", [""]) or [""],
                    resources=r.get("resources", []) or [],
                    verbs=r.get("verbs", []) or [],
                    resource_names=r.get("resourceNames", []) or [],
                    non_resource_urls=r.get("nonResourceURLs", []) or [],
                )
            )
        return out

    def _ingest(self) -> None:
        for obj in self.objects:
            kind = obj.get("kind")
            meta = obj.get("metadata", {})
            name = meta.get("name")
            namespace = meta.get("namespace")

            if not kind or not name:
                continue

            if kind == "Role":
                if namespace:
                    self.roles[(namespace, name)] = self._parse_rules(obj)
            elif kind == "ClusterRole":
                self.cluster_roles[name] = self._parse_rules(obj)
            elif kind == "RoleBinding":
                self.role_bindings.append(obj)
            elif kind == "ClusterRoleBinding":
                self.cluster_role_bindings.append(obj)
            elif kind == "ServiceAccount" and namespace:
                self.service_accounts.add((namespace, name))

    @staticmethod
    def _subjects(binding: dict[str, Any], fallback_namespace: str | None) -> list[Subject]:
        out: list[Subject] = []
        for s in binding.get("subjects", []) or []:
            kind = s.get("kind", "")
            name = s.get("name", "")
            if not kind or not name:
                continue

            subject_ns = s.get("namespace")
            if kind == "ServiceAccount" and not subject_ns:
                subject_ns = fallback_namespace

            out.append(Subject(kind=kind, name=name, namespace=subject_ns))
        return out

    def _binding_grants(self) -> dict[str, list[BindingGrant]]:
        grants: dict[str, list[BindingGrant]] = defaultdict(list)

        for rb in self.role_bindings:
            meta = rb.get("metadata", {})
            rb_name = meta.get("name", "")
            rb_ns = meta.get("namespace")
            role_ref = rb.get("roleRef", {})

            for sub in self._subjects(rb, rb_ns):
                grants[sub.key()].append(
                    BindingGrant(
                        source_kind="RoleBinding",
                        source_name=rb_name,
                        binding_namespace=rb_ns,
                        role_ref_kind=role_ref.get("kind", ""),
                        role_ref_name=role_ref.get("name", ""),
                    )
                )

        for crb in self.cluster_role_bindings:
            meta = crb.get("metadata", {})
            crb_name = meta.get("name", "")
            role_ref = crb.get("roleRef", {})

            for sub in self._subjects(crb, None):
                grants[sub.key()].append(
                    BindingGrant(
                        source_kind="ClusterRoleBinding",
                        source_name=crb_name,
                        binding_namespace=None,
                        role_ref_kind=role_ref.get("kind", ""),
                        role_ref_name=role_ref.get("name", ""),
                    )
                )

        return grants

    def _resolve_rules(self, grant: BindingGrant) -> tuple[str, list[Rule], str | None]:
        if grant.role_ref_kind == "Role":
            if grant.binding_namespace is None:
                return (f"Role/{grant.role_ref_name}", [], None)
            rules = self.roles.get((grant.binding_namespace, grant.role_ref_name), [])
            return (f"Role/{grant.role_ref_name}", rules, grant.binding_namespace)

        if grant.role_ref_kind == "ClusterRole":
            rules = self.cluster_roles.get(grant.role_ref_name, [])
            return (f"ClusterRole/{grant.role_ref_name}", rules, None)

        return (f"{grant.role_ref_kind}/{grant.role_ref_name}", [], None)

    @staticmethod
    def _rule_allows(rule: Rule, api_group: str, resource: str, verb: str) -> bool:
        groups_ok = "*" in rule.api_groups or api_group in rule.api_groups
        resources_ok = "*" in rule.resources or resource in rule.resources
        verbs_ok = "*" in rule.verbs or verb in rule.verbs
        return groups_ok and resources_ok and verbs_ok

    def analyze(self) -> dict[str, Any]:
        grants_by_subject = self._binding_grants()
        effective: dict[str, dict[str, Any]] = {}

        nodes: list[dict[str, str]] = []
        edges: list[dict[str, str]] = []

        for key, grants in grants_by_subject.items():
            kind, namespace, name = key.split(":", 2)
            subject_node = key
            nodes.append({"id": subject_node, "type": "subject", "label": f"{kind}:{name}"})

            resolved_rules: list[dict[str, Any]] = []
            risky: list[dict[str, str]] = []

            for grant in grants:
                role_node = f"{grant.role_ref_kind}:{grant.role_ref_name}:{grant.binding_namespace or '*'}"
                edges.append({"from": subject_node, "to": role_node, "type": grant.source_kind})
                nodes.append(
                    {
                        "id": role_node,
                        "type": "role",
                        "label": f"{grant.role_ref_kind}/{grant.role_ref_name}",
                    }
                )

                role_label, rules, scope_ns = self._resolve_rules(grant)
                for rule in rules:
                    rule_entry = {
                        "from": role_label,
                        "scope_namespace": scope_ns,
                        "apiGroups": rule.api_groups,
                        "resources": rule.resources,
                        "verbs": rule.verbs,
                    }
                    resolved_rules.append(rule_entry)

                    for api_group, resource, verb, description in RISKY_CAPABILITIES:
                        if self._rule_allows(rule, api_group, resource, verb):
                            risky.append(
                                {
                                    "risk": description,
                                    "apiGroup": api_group,
                                    "resource": resource,
                                    "verb": verb,
                                    "scope_namespace": scope_ns,
                                }
                            )

            effective[key] = {
                "subject": {"kind": kind, "name": name, "namespace": None if namespace == "*" else namespace},
                "grants": [grant.__dict__ for grant in grants],
                "rules": resolved_rules,
                "risky_capabilities": _dedupe_dicts(risky),
            }

        who_can_exec_prod = []
        for subject_key, info in effective.items():
            for cap in info["risky_capabilities"]:
                if cap["resource"] == "pods/exec" and cap["verb"] == "create":
                    scope = cap.get("scope_namespace")
                    if scope in (None, "prod"):
                        who_can_exec_prod.append(subject_key)
                        break

        blast_radius = {}
        for sa_ns, sa_name in self.service_accounts:
            skey = f"ServiceAccount:{sa_ns}:{sa_name}"
            info = effective.get(skey)
            if not info:
                continue

            risks = [r["risk"] for r in info["risky_capabilities"]]
            attack_paths = []

            if "create pods" in risks:
                attack_paths.append("Create pod -> mount high-privilege SA -> pivot")
            if "read secrets" in risks:
                attack_paths.append("Read secrets -> extract credentials -> lateral movement")
            if "bind cluster roles" in risks or "bind roles" in risks:
                attack_paths.append("Create binding -> grant self elevated role")
            if "mint SA token" in risks:
                attack_paths.append("Mint token for SA -> assume SA identity")
            if "exec into pods" in risks:
                attack_paths.append("Exec into workload -> credential theft / command execution")

            blast_radius[skey] = {
                "risky_capabilities": risks,
                "attack_paths": attack_paths,
            }

        return {
            "summary": {
                "rbac_objects": {
                    "roles": len(self.roles),
                    "cluster_roles": len(self.cluster_roles),
                    "role_bindings": len(self.role_bindings),
                    "cluster_role_bindings": len(self.cluster_role_bindings),
                    "service_accounts": len(self.service_accounts),
                },
                "subjects_analyzed": len(effective),
                "who_can_exec_prod": sorted(set(who_can_exec_prod)),
            },
            "effective_permissions": effective,
            "blast_radius": blast_radius,
            "graph": {
                "nodes": _dedupe_dicts(nodes),
                "edges": _dedupe_dicts(edges),
            },
        }

    def graphviz_dot(self) -> str:
        analysis = self.analyze()
        lines = ["digraph AuthVector {", "  rankdir=LR;"]

        for n in analysis["graph"]["nodes"]:
            node_id = _dot_escape(n["id"])
            label = _dot_escape(n["label"])
            shape = "ellipse" if n["type"] == "subject" else "box"
            lines.append(f'  "{node_id}" [label="{label}", shape={shape}];')

        for e in analysis["graph"]["edges"]:
            frm = _dot_escape(e["from"])
            to = _dot_escape(e["to"])
            etype = _dot_escape(e["type"])
            lines.append(f'  "{frm}" -> "{to}" [label="{etype}"];')

        lines.append("}")
        return "\n".join(lines)


def _dedupe_dicts(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for item in items:
        token = repr(sorted(item.items()))
        if token in seen:
            continue
        seen.add(token)
        out.append(item)
    return out


def _dot_escape(value: str) -> str:
    return value.replace('"', '\\"')
