from __future__ import annotations

import json
import os
import re
import ssl
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any


SERVICEACCOUNT_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
SERVICEACCOUNT_CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
SERVICEACCOUNT_NAMESPACE_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

VALID_VIEW_NAME = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")


class SavedViewStoreError(RuntimeError):
    pass


class SavedViewNotFound(SavedViewStoreError):
    pass


class SavedViewStore(ABC):
    backend_name = "unknown"
    shared = False

    @abstractmethod
    def list_views(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def get_view(self, name: str) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def upsert_view(self, name: str, settings: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def delete_view(self, name: str) -> None:
        raise NotImplementedError


class MemorySavedViewStore(SavedViewStore):
    backend_name = "memory"
    shared = False

    def __init__(self):
        self._views: dict[str, dict[str, Any]] = {}

    def list_views(self) -> list[dict[str, Any]]:
        return [self._views[name] for name in sorted(self._views.keys())]

    def get_view(self, name: str) -> dict[str, Any]:
        key = normalize_view_name(name)
        if key not in self._views:
            raise SavedViewNotFound(f"view not found: {name}")
        return self._views[key]

    def upsert_view(self, name: str, settings: dict[str, Any]) -> dict[str, Any]:
        key = normalize_view_name(name)
        view = {
            "name": key,
            "settings": settings,
            "updated_at": now_iso(),
        }
        self._views[key] = view
        return view

    def delete_view(self, name: str) -> None:
        key = normalize_view_name(name)
        if key not in self._views:
            raise SavedViewNotFound(f"view not found: {name}")
        del self._views[key]


class CRDSavedViewStore(SavedViewStore):
    backend_name = "crd"
    shared = True

    def __init__(self, timeout_seconds: int = 10):
        self.timeout_seconds = timeout_seconds
        self.api_host = os.getenv("KUBERNETES_SERVICE_HOST")
        self.api_port = os.getenv("KUBERNETES_SERVICE_PORT", "443")
        self.api_base = f"https://{self.api_host}:{self.api_port}" if self.api_host else None
        self.namespace = self._read_namespace()

    def list_views(self) -> list[dict[str, Any]]:
        path = self._collection_path()
        data = self._request_json("GET", path)
        items = data.get("items", []) if isinstance(data, dict) else []
        out: list[dict[str, Any]] = []

        for item in items:
            if not isinstance(item, dict):
                continue
            out.append(self._from_resource(item))

        out.sort(key=lambda x: x["name"])
        return out

    def get_view(self, name: str) -> dict[str, Any]:
        key = normalize_view_name(name)
        path = self._resource_path(key)
        data = self._request_json("GET", path)
        return self._from_resource(data)

    def upsert_view(self, name: str, settings: dict[str, Any]) -> dict[str, Any]:
        key = normalize_view_name(name)
        now = now_iso()
        body = {
            "apiVersion": "authvector.io/v1alpha1",
            "kind": "SavedView",
            "metadata": {"name": key},
            "spec": {
                "settings": settings,
                "updatedAt": now,
            },
        }

        path = self._resource_path(key)
        try:
            self._request_json("PUT", path, body=body)
        except SavedViewNotFound:
            self._request_json("POST", self._collection_path(), body=body)

        return {
            "name": key,
            "settings": settings,
            "updated_at": now,
        }

    def delete_view(self, name: str) -> None:
        key = normalize_view_name(name)
        self._request_json("DELETE", self._resource_path(key))

    def _from_resource(self, resource: dict[str, Any]) -> dict[str, Any]:
        metadata = resource.get("metadata", {})
        spec = resource.get("spec", {})
        return {
            "name": metadata.get("name", ""),
            "settings": spec.get("settings", {}) if isinstance(spec.get("settings", {}), dict) else {},
            "updated_at": spec.get("updatedAt") or metadata.get("creationTimestamp") or "",
        }

    def _collection_path(self) -> str:
        self._assert_ready()
        return f"/apis/authvector.io/v1alpha1/namespaces/{self.namespace}/savedviews"

    def _resource_path(self, name: str) -> str:
        return f"{self._collection_path()}/{name}"

    def _assert_ready(self) -> None:
        if not self.api_base:
            raise SavedViewStoreError("Kubernetes API host is unavailable")
        if not self.namespace:
            raise SavedViewStoreError("in-cluster namespace is unavailable")
        if not os.path.exists(SERVICEACCOUNT_TOKEN_PATH) or not os.path.exists(SERVICEACCOUNT_CA_PATH):
            raise SavedViewStoreError("in-cluster service account credentials are unavailable")

    def _read_namespace(self) -> str | None:
        try:
            with open(SERVICEACCOUNT_NAMESPACE_PATH, "r", encoding="utf-8") as f:
                value = f.read().strip()
            return value or None
        except OSError:
            return None

    def _request_json(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        self._assert_ready()
        assert self.api_base is not None

        with open(SERVICEACCOUNT_TOKEN_PATH, "r", encoding="utf-8") as f:
            token = f.read().strip()

        data = None
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(
            url=f"{self.api_base}{path}",
            data=data,
            headers=headers,
            method=method,
        )

        ctx = ssl.create_default_context(cafile=SERVICEACCOUNT_CA_PATH)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds, context=ctx) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            text = exc.read().decode("utf-8", errors="replace")
            if exc.code == 404:
                raise SavedViewNotFound(text or "not found") from exc
            raise SavedViewStoreError(f"saved views API error {exc.code}: {text}") from exc
        except urllib.error.URLError as exc:
            raise SavedViewStoreError(f"saved views API connection error: {exc}") from exc


def normalize_view_name(name: str) -> str:
    lowered = name.strip().lower().replace(" ", "-").replace("_", "-")
    lowered = re.sub(r"[^a-z0-9-]", "", lowered)
    lowered = lowered.strip("-")
    if len(lowered) > 63:
        lowered = lowered[:63].rstrip("-")

    if not lowered or not VALID_VIEW_NAME.match(lowered):
        raise SavedViewStoreError(
            "invalid view name: use lowercase letters, numbers, and '-', up to 63 chars"
        )

    return lowered


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def build_saved_view_store() -> SavedViewStore:
    mode = (os.getenv("AUTHVECTOR_VIEW_STORE") or "").strip().lower()

    if mode == "memory":
        return MemorySavedViewStore()

    if mode == "crd":
        return CRDSavedViewStore()

    # Auto mode: in-cluster CRD first, memory fallback.
    try:
        store = CRDSavedViewStore()
        store._assert_ready()
        return store
    except Exception:  # noqa: BLE001
        return MemorySavedViewStore()
