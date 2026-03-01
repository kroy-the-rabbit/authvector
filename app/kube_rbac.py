from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from typing import Any


SERVICEACCOUNT_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
SERVICEACCOUNT_CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"


class KubeAPIError(RuntimeError):
    pass


class InClusterRBACLoader:
    def __init__(self, timeout_seconds: int = 10):
        self.timeout_seconds = timeout_seconds
        self.api_host = os.getenv("KUBERNETES_SERVICE_HOST")
        self.api_port = os.getenv("KUBERNETES_SERVICE_PORT", "443")
        self.api_base = f"https://{self.api_host}:{self.api_port}" if self.api_host else None

    def is_in_cluster(self) -> bool:
        return bool(
            self.api_base
            and os.path.exists(SERVICEACCOUNT_TOKEN_PATH)
            and os.path.exists(SERVICEACCOUNT_CA_PATH)
        )

    def fetch_objects(self, namespaces: list[str] | None = None) -> list[dict[str, Any]]:
        if not self.is_in_cluster():
            raise KubeAPIError("not running in a Kubernetes cluster (missing in-cluster service account context)")

        namespace_filter = set(namespaces or [])

        cluster_roles = self._list_items("/apis/rbac.authorization.k8s.io/v1/clusterroles")
        cluster_role_bindings = self._list_items("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings")
        roles = self._list_items("/apis/rbac.authorization.k8s.io/v1/roles")
        role_bindings = self._list_items("/apis/rbac.authorization.k8s.io/v1/rolebindings")
        service_accounts = self._list_items("/api/v1/serviceaccounts")

        if namespace_filter:
            roles = [obj for obj in roles if _in_namespaces(obj, namespace_filter)]
            role_bindings = [obj for obj in role_bindings if _in_namespaces(obj, namespace_filter)]
            service_accounts = [obj for obj in service_accounts if _in_namespaces(obj, namespace_filter)]

        return [*cluster_roles, *cluster_role_bindings, *roles, *role_bindings, *service_accounts]

    def _list_items(self, path: str) -> list[dict[str, Any]]:
        response = self._get(path)
        data = json.loads(response.decode("utf-8"))
        items = data.get("items", [])
        if not isinstance(items, list):
            return []
        return [item for item in items if isinstance(item, dict)]

    def _get(self, path: str) -> bytes:
        assert self.api_base is not None

        with open(SERVICEACCOUNT_TOKEN_PATH, "r", encoding="utf-8") as f:
            token = f.read().strip()

        ctx = ssl.create_default_context(cafile=SERVICEACCOUNT_CA_PATH)
        req = urllib.request.Request(
            f"{self.api_base}{path}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
            method="GET",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds, context=ctx) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise KubeAPIError(f"Kubernetes API returned {exc.code} for {path}: {body}") from exc
        except urllib.error.URLError as exc:
            raise KubeAPIError(f"failed to reach Kubernetes API for {path}: {exc}") from exc


def _in_namespaces(obj: dict[str, Any], namespaces: set[str]) -> bool:
    namespace = (obj.get("metadata") or {}).get("namespace")
    return isinstance(namespace, str) and namespace in namespaces
