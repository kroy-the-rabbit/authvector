# AuthVector

AuthVector is a Flask web app for live Kubernetes RBAC analysis.

It helps answer questions like:
- What effective permissions does a subject have?
- Who can `exec` into production pods?
- What is the blast radius if a ServiceAccount token leaks?
- Which privilege-escalation paths exist?

## Features

- Live in-cluster RBAC ingestion from Kubernetes API server
- Optional namespace scoping, defaulting to all namespaces (including `kube-system`)
- Manifest mode for local/offline analysis
- Effective permissions by subject and scope
- Blast-radius simulation for ServiceAccount token compromise
- Graph export in JSON and Graphviz DOT
- Workable GUI with visualization options:
  - Interactive relationship graph (pan/zoom, layered/radial layouts)
  - Graph filters (namespace, subject search, risky-only)
  - Clickable node inspector for subject/role details
  - Risk table and blast-radius views
  - Raw JSON and DOT tabs
- Server-side pagination/limits for large clusters
- Server-side saved investigation views via Kubernetes CRD (`SavedView`), shared across users

## Quick Start (Local)

```bash
PYENV_VERSION=authvector-3.13.7 python -m pip install -r requirements.txt
PYENV_VERSION=authvector-3.13.7 python wsgi.py
```

Open: http://localhost:8080

Local mode defaults to `source=manifest` because in-cluster credentials are unavailable.
Saved views use in-memory backend locally.

## API

- `GET /api/sources`
  - Returns in-cluster mode and saved-view backend info
- `POST /api/analyze`
- `POST /api/graphviz`
- `GET /api/views`
- `GET /api/views/<name>`
- `PUT /api/views/<name>`
- `DELETE /api/views/<name>`

## Helm Deployment (Recommended)

AuthVector is packaged as a Helm chart in `charts/authvector`.

Install/upgrade:

```bash
helm upgrade --install authvector charts/authvector \
  --namespace authvector \
  --create-namespace \
  --set image.repository=ghcr.io/your-org/authvector \
  --set image.tag=latest
```

Port-forward:

```bash
kubectl -n authvector port-forward svc/authvector 8080:80
```

Notes:
- The chart installs the `SavedView` CRD from `charts/authvector/crds/`
- `AUTHVECTOR_VIEW_STORE=crd` is enabled by default
- Saved views are persisted as namespaced `SavedView` CRs and shared across users

## Optional Raw Manifests

Raw manifests are also available under `k8s/`, but Helm is the primary deployment path.

## Required Kubernetes Access

AuthVector needs cluster-wide read access to:
- `roles`, `rolebindings`, `clusterroles`, `clusterrolebindings`
- `serviceaccounts`, `namespaces`

AuthVector also needs namespaced CRUD access to:
- `savedviews.authvector.io` in the release namespace

This includes `kube-system` visibility by default for RBAC analysis.
