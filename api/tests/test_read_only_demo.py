"""
The shared public demo tenant is read-only through the API (see
app/auth/read_only.py): reads stay open, every write is refused unless it
carries the server's maintenance token, and other tenants are unaffected.
"""
import pytest

from app.config import settings

RISK = {"title": "Test Risk", "likelihood": 3, "impact": 4}


@pytest.fixture
def demo_locked(monkeypatch):
    monkeypatch.setattr(settings, "read_only_tenants", "demo")
    monkeypatch.setattr(settings, "maintenance_token", "")


def test_demo_tenant_refuses_writes(client, fake_graph, as_user, demo_locked):
    as_user(graph_tenant_id="demo")
    resp = client.post("/api/v1/risks/", json=RISK)
    assert resp.status_code == 403
    assert "read-only" in resp.json()["detail"]
    fake_graph.write.assert_not_called()


def test_demo_tenant_refuses_saving_connector_credentials(client, fake_graph, as_user, demo_locked):
    # The main thing the lock exists for: a visitor storing their own
    # credentials in the shared tenant for the next visitor to run.
    as_user(graph_tenant_id="demo")
    resp = client.put("/api/v1/connectors/wazuh/config", json={"config": {"api_url": "https://example.com"}})
    assert resp.status_code == 403


def test_demo_tenant_still_allows_reads(client, fake_graph, as_user, demo_locked):
    as_user(graph_tenant_id="demo")
    assert client.get("/api/v1/risks/").status_code == 200


def test_maintenance_token_allows_writes(client, fake_graph, as_user, demo_locked, monkeypatch):
    monkeypatch.setattr(settings, "maintenance_token", "reseed-token")
    as_user(graph_tenant_id="demo")
    resp = client.post("/api/v1/risks/", json=RISK, headers={"X-Maintenance-Token": "reseed-token"})
    assert resp.status_code == 201


def test_wrong_maintenance_token_is_refused(client, fake_graph, as_user, demo_locked, monkeypatch):
    monkeypatch.setattr(settings, "maintenance_token", "reseed-token")
    as_user(graph_tenant_id="demo")
    resp = client.post("/api/v1/risks/", json=RISK, headers={"X-Maintenance-Token": "guess"})
    assert resp.status_code == 403


def test_no_bypass_when_no_maintenance_token_is_configured(client, fake_graph, as_user, demo_locked):
    # An empty server-side token must not mean "an empty header matches".
    as_user(graph_tenant_id="demo")
    resp = client.post("/api/v1/risks/", json=RISK, headers={"X-Maintenance-Token": ""})
    assert resp.status_code == 403


def test_other_tenants_can_still_write(client, fake_graph, as_user, demo_locked):
    as_user(graph_tenant_id="acme")
    assert client.post("/api/v1/risks/", json=RISK).status_code == 201


def test_login_response_flags_read_only_tenants(client_with_db, demo_locked):
    demo = client_with_db.post("/api/v1/auth/register", json={
        "email": "visitor-demo@example.com", "password": "password123",
        "tenant_name": "Demo", "graph_tenant_id": "demo",
    })
    assert demo.status_code == 201
    assert demo.json()["read_only"] is True

    own = client_with_db.post("/api/v1/auth/register", json={
        "email": "someone@example.com", "password": "password123", "tenant_name": "Acme",
    })
    assert own.status_code == 201
    assert own.json()["read_only"] is False
