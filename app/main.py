from __future__ import annotations

from math import ceil
from typing import Any

from flask import Flask, jsonify, render_template, request

from .kube_rbac import InClusterRBACLoader, KubeAPIError
from .rbac import RBACAnalyzer
from .saved_views import (
    SavedViewNotFound,
    SavedViewStore,
    SavedViewStoreError,
    build_saved_view_store,
    normalize_view_name,
)


def create_app(
    loader: InClusterRBACLoader | None = None,
    saved_view_store: SavedViewStore | None = None,
) -> Flask:
    app = Flask(__name__)
    loader = loader or InClusterRBACLoader()
    saved_view_store = saved_view_store or build_saved_view_store()

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/sources")
    def sources():
        return jsonify(
            {
                "in_cluster": loader.is_in_cluster(),
                "saved_view_backend": saved_view_store.backend_name,
                "saved_view_shared": saved_view_store.shared,
            }
        )

    @app.post("/api/analyze")
    def analyze():
        payload = request.get_json(silent=True) or {}
        source = str(payload.get("source") or "manifest").strip().lower()

        try:
            analyzer = _build_analyzer(payload, source, loader)
            result = analyzer.analyze()
            result = _apply_result_window(result, payload)
            result["summary"]["source"] = source
            return jsonify(result)
        except KubeAPIError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:  # noqa: BLE001
            return jsonify({"error": f"failed to analyze input: {exc}"}), 400

    @app.post("/api/graphviz")
    def graphviz():
        payload = request.get_json(silent=True) or {}
        source = str(payload.get("source") or "manifest").strip().lower()

        try:
            analyzer = _build_analyzer(payload, source, loader)
            result = _apply_result_window(analyzer.analyze(), payload)
            return jsonify({"dot": _analysis_to_dot(result), "source": source})
        except KubeAPIError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:  # noqa: BLE001
            return jsonify({"error": f"failed to render graph: {exc}"}), 400

    @app.get("/api/views")
    def list_views():
        try:
            return jsonify(
                {
                    "views": saved_view_store.list_views(),
                    "backend": saved_view_store.backend_name,
                    "shared": saved_view_store.shared,
                }
            )
        except SavedViewStoreError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/views/<name>")
    def get_view(name: str):
        try:
            key = normalize_view_name(name)
            return jsonify(saved_view_store.get_view(key))
        except SavedViewNotFound as exc:
            return jsonify({"error": str(exc)}), 404
        except SavedViewStoreError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.put("/api/views/<name>")
    def upsert_view(name: str):
        payload = request.get_json(silent=True) or {}
        settings = payload.get("settings")

        if not isinstance(settings, dict):
            return jsonify({"error": "Field 'settings' must be an object"}), 400

        try:
            key = normalize_view_name(name)
            view = saved_view_store.upsert_view(key, settings)
            return jsonify(view)
        except SavedViewStoreError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.delete("/api/views/<name>")
    def delete_view(name: str):
        try:
            key = normalize_view_name(name)
            saved_view_store.delete_view(key)
            return jsonify({"status": "deleted", "name": key})
        except SavedViewNotFound as exc:
            return jsonify({"error": str(exc)}), 404
        except SavedViewStoreError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/healthz")
    def healthz():
        return jsonify({"status": "ok"})

    return app


def _build_analyzer(payload: dict[str, Any], source: str, loader: InClusterRBACLoader) -> RBACAnalyzer:
    if source == "cluster":
        namespaces = _parse_namespaces(payload.get("namespaces"))
        objects = loader.fetch_objects(namespaces=namespaces)
        return RBACAnalyzer.from_objects(objects)

    manifest = str(payload.get("manifest", ""))
    if not manifest.strip():
        raise ValueError("Field 'manifest' is required when source=manifest")

    return RBACAnalyzer.from_manifest(manifest)


def _parse_namespaces(value: object) -> list[str] | None:
    if value is None:
        return None

    if isinstance(value, str):
        parsed = [ns.strip() for ns in value.split(",") if ns.strip()]
        return parsed or None

    if isinstance(value, list):
        parsed = [str(ns).strip() for ns in value if str(ns).strip()]
        return parsed or None

    return None


def _parse_positive_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _apply_result_window(result: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    effective = result.get("effective_permissions", {})
    if not isinstance(effective, dict):
        return result

    all_subjects = sorted(effective.keys())
    max_subjects = _parse_positive_int(payload.get("max_subjects"), default=2000, minimum=1, maximum=10000)
    limited_subjects = all_subjects[:max_subjects]

    page_size = _parse_positive_int(payload.get("page_size"), default=200, minimum=1, maximum=2000)
    total_pages = max(1, ceil(len(limited_subjects) / page_size))
    page = _parse_positive_int(payload.get("page"), default=1, minimum=1, maximum=total_pages)

    start = (page - 1) * page_size
    end = start + page_size
    page_subjects = limited_subjects[start:end]

    page_subject_set = set(page_subjects)
    result["effective_permissions"] = {k: v for k, v in effective.items() if k in page_subject_set}

    blast = result.get("blast_radius", {})
    if isinstance(blast, dict):
        result["blast_radius"] = {k: v for k, v in blast.items() if k in page_subject_set}

    graph = result.get("graph", {})
    if isinstance(graph, dict):
        edges = graph.get("edges", [])
        nodes = graph.get("nodes", [])
        if isinstance(edges, list) and isinstance(nodes, list):
            page_edges = [edge for edge in edges if edge.get("from") in page_subject_set]
            role_nodes = {edge.get("to") for edge in page_edges if isinstance(edge.get("to"), str)}
            node_allow = set(page_subjects) | role_nodes
            page_nodes = [node for node in nodes if node.get("id") in node_allow]
            result["graph"] = {"nodes": page_nodes, "edges": page_edges}

    summary = result.setdefault("summary", {})
    if isinstance(summary, dict):
        summary["subjects_analyzed"] = len(page_subjects)
        summary["pagination"] = {
            "page": page,
            "page_size": page_size,
            "max_subjects": max_subjects,
            "total_subjects": len(all_subjects),
            "subjects_after_limit": len(limited_subjects),
            "page_subjects": len(page_subjects),
            "total_pages": total_pages,
        }

    return result


def _analysis_to_dot(analysis: dict[str, Any]) -> str:
    lines = ["digraph AuthVector {", "  rankdir=LR;"]

    graph = analysis.get("graph", {}) if isinstance(analysis, dict) else {}
    nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
    edges = graph.get("edges", []) if isinstance(graph, dict) else []

    for node in nodes:
        node_id = _dot_escape(str(node.get("id", "")))
        label = _dot_escape(str(node.get("label", "")))
        shape = "ellipse" if node.get("type") == "subject" else "box"
        lines.append(f'  "{node_id}" [label="{label}", shape={shape}];')

    for edge in edges:
        frm = _dot_escape(str(edge.get("from", "")))
        to = _dot_escape(str(edge.get("to", "")))
        etype = _dot_escape(str(edge.get("type", "")))
        lines.append(f'  "{frm}" -> "{to}" [label="{etype}"];')

    lines.append("}")
    return "\n".join(lines)


def _dot_escape(value: str) -> str:
    return value.replace('"', '\\"')


app = create_app()
