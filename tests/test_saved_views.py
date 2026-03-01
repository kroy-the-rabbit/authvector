from app.main import create_app
from app.saved_views import MemorySavedViewStore


def test_saved_views_crud_api():
    app = create_app(saved_view_store=MemorySavedViewStore())
    client = app.test_client()

    create = client.put(
        "/api/views/prod-risky",
        json={"settings": {"source": "cluster", "namespaces": "kube-system,prod", "layout": "radial"}},
    )
    assert create.status_code == 200
    assert create.json["name"] == "prod-risky"

    listed = client.get("/api/views")
    assert listed.status_code == 200
    assert listed.json["backend"] == "memory"
    assert listed.json["shared"] is False
    assert any(v["name"] == "prod-risky" for v in listed.json["views"])

    fetched = client.get("/api/views/prod-risky")
    assert fetched.status_code == 200
    assert fetched.json["settings"]["layout"] == "radial"

    deleted = client.delete("/api/views/prod-risky")
    assert deleted.status_code == 200

    missing = client.get("/api/views/prod-risky")
    assert missing.status_code == 404


def test_saved_view_name_validation():
    app = create_app(saved_view_store=MemorySavedViewStore())
    client = app.test_client()

    bad = client.put("/api/views/---", json={"settings": {"a": 1}})
    assert bad.status_code == 400
