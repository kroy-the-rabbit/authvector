from app.main import create_app


SAMPLE_OBJECTS = [
    {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {"name": "app", "namespace": "prod"},
    },
    {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {"name": "worker", "namespace": "kube-system"},
    },
    {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {"name": "pod-exec-role"},
        "rules": [{"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]}],
    },
    {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {"name": "app-binding"},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "pod-exec-role"},
        "subjects": [
            {"kind": "ServiceAccount", "name": "app", "namespace": "prod"},
            {"kind": "ServiceAccount", "name": "worker", "namespace": "kube-system"},
        ],
    },
]


def test_sources_endpoint(monkeypatch):
    app = create_app()
    monkeypatch.setattr("app.main.InClusterRBACLoader.is_in_cluster", lambda _self: True)

    client = app.test_client()
    resp = client.get("/api/sources")
    assert resp.status_code == 200
    assert resp.json["in_cluster"] is True


def test_analyze_manifest_mode():
    app = create_app()
    client = app.test_client()

    manifest = """
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

    resp = client.post("/api/analyze", json={"source": "manifest", "manifest": manifest})
    assert resp.status_code == 200
    assert "ServiceAccount:prod:app" in resp.json["summary"]["who_can_exec_prod"]


def test_analyze_cluster_mode(monkeypatch):
    app = create_app()

    def fake_fetch(_self, namespaces=None):
        assert namespaces == ["kube-system", "prod"]
        return SAMPLE_OBJECTS

    monkeypatch.setattr("app.main.InClusterRBACLoader.fetch_objects", fake_fetch)

    client = app.test_client()
    resp = client.post(
        "/api/analyze",
        json={"source": "cluster", "namespaces": "kube-system,prod"},
    )

    assert resp.status_code == 200
    assert resp.json["summary"]["source"] == "cluster"
    assert "ServiceAccount:prod:app" in resp.json["summary"]["who_can_exec_prod"]


def test_analyze_cluster_pagination(monkeypatch):
    app = create_app()

    monkeypatch.setattr("app.main.InClusterRBACLoader.fetch_objects", lambda _self, namespaces=None: SAMPLE_OBJECTS)

    client = app.test_client()
    resp = client.post(
        "/api/analyze",
        json={"source": "cluster", "page": 1, "page_size": 1, "max_subjects": 2},
    )

    assert resp.status_code == 200
    summary = resp.json["summary"]
    assert summary["subjects_analyzed"] == 1
    assert summary["pagination"]["total_subjects"] == 2
    assert summary["pagination"]["total_pages"] == 2
    assert len(resp.json["effective_permissions"]) == 1


def test_graphviz_honors_pagination(monkeypatch):
    app = create_app()

    monkeypatch.setattr("app.main.InClusterRBACLoader.fetch_objects", lambda _self, namespaces=None: SAMPLE_OBJECTS)

    client = app.test_client()
    resp = client.post(
        "/api/graphviz",
        json={"source": "cluster", "page": 1, "page_size": 1, "max_subjects": 1},
    )

    assert resp.status_code == 200
    dot = resp.json["dot"]
    assert "digraph AuthVector" in dot
    assert "ServiceAccount:kube-system:worker" in dot
    assert "ServiceAccount:prod:app" not in dot
