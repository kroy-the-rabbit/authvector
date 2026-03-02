from app.rbac import RBACAnalyzer


SAMPLE = """
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app
  namespace: prod
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pod-exec-role
rules:
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: app-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: pod-exec-role
subjects:
  - kind: ServiceAccount
    name: app
    namespace: prod
"""


def test_exec_detection():
    out = RBACAnalyzer.from_manifest(SAMPLE).analyze()
    assert "ServiceAccount:prod:app" in out["summary"]["who_can_exec_prod"]


def test_graphviz_has_nodes():
    dot = RBACAnalyzer.from_manifest(SAMPLE).graphviz_dot()
    assert "digraph AuthVector" in dot
    assert "ServiceAccount:prod:app" in dot


def test_unbound_service_accounts_are_included():
    manifest = """
apiVersion: v1
kind: ServiceAccount
metadata:
  name: lonely
  namespace: prod
"""

    out = RBACAnalyzer.from_manifest(manifest).analyze()
    key = "ServiceAccount:prod:lonely"
    assert key in out["effective_permissions"]
    assert out["effective_permissions"][key]["grants"] == []
