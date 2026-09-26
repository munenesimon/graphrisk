"""
Integration tests for /api/v1/auth/register and /login, backed by a real
(in-memory SQLite) database via the client_with_db fixture -- these
exercise the actual SQLAlchemy models and the real JWT create/decode
pipeline end to end, not a mocked-out shortcut.
"""
from app.auth.security import decode_access_token


def _register(client_with_db, email="owner@example.com", password="hunter22222", tenant_name="Acme Inc", graph_tenant_id=None):
    body = {"email": email, "password": password, "tenant_name": tenant_name}
    if graph_tenant_id is not None:
        body["graph_tenant_id"] = graph_tenant_id
    return client_with_db.post("/api/v1/auth/register", json=body)


class TestRegister:
    def test_register_creates_tenant_and_returns_a_working_token(self, client_with_db):
        resp = _register(client_with_db)
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["role"] == "owner"
        assert body["graph_tenant_id"] == "acme-inc"

        payload = decode_access_token(body["access_token"])
        assert payload["tenant_id"] == body["tenant_id"]
        assert payload["graph_tenant_id"] == "acme-inc"
        assert payload["role"] == "owner"

    def test_graph_tenant_id_can_be_supplied_explicitly(self, client_with_db):
        resp = _register(client_with_db, graph_tenant_id="custom-slug")
        assert resp.status_code == 201, resp.text
        assert resp.json()["graph_tenant_id"] == "custom-slug"

    def test_duplicate_email_is_rejected(self, client_with_db):
        _register(client_with_db, email="dup@example.com", tenant_name="Org A")
        resp = _register(client_with_db, email="dup@example.com", tenant_name="Org B")
        assert resp.status_code == 409

    def test_duplicate_graph_tenant_id_is_rejected(self, client_with_db):
        _register(client_with_db, email="a@example.com", tenant_name="Acme Inc")
        resp = _register(client_with_db, email="b@example.com", tenant_name="Acme Inc, LLC", graph_tenant_id="acme-inc")
        assert resp.status_code == 409

    def test_password_too_short_is_rejected_by_schema_validation(self, client_with_db):
        resp = _register(client_with_db, password="short")
        assert resp.status_code == 422


class TestLogin:
    def test_login_with_correct_credentials_succeeds(self, client_with_db):
        _register(client_with_db, email="login@example.com", password="correct-password")
        resp = client_with_db.post("/api/v1/auth/login", json={"email": "login@example.com", "password": "correct-password"})
        assert resp.status_code == 200, resp.text
        assert "access_token" in resp.json()

    def test_login_with_wrong_password_is_rejected(self, client_with_db):
        _register(client_with_db, email="login2@example.com", password="correct-password")
        resp = client_with_db.post("/api/v1/auth/login", json={"email": "login2@example.com", "password": "wrong-password"})
        assert resp.status_code == 401

    def test_login_with_unknown_email_is_rejected(self, client_with_db):
        resp = client_with_db.post("/api/v1/auth/login", json={"email": "nobody@example.com", "password": "whatever123"})
        assert resp.status_code == 401

    def test_login_error_message_does_not_reveal_whether_the_email_exists(self, client_with_db):
        """Same generic message for 'wrong password' and 'no such user' --
        an attacker enumerating emails shouldn't be able to tell them apart."""
        _register(client_with_db, email="exists@example.com", password="correct-password")
        wrong_password_resp = client_with_db.post("/api/v1/auth/login", json={"email": "exists@example.com", "password": "nope"})
        unknown_email_resp = client_with_db.post("/api/v1/auth/login", json={"email": "nobody@example.com", "password": "nope"})
        assert wrong_password_resp.json()["detail"] == unknown_email_resp.json()["detail"]


class TestTokenWorksAgainstARealProtectedRoute:
    def test_register_then_use_token_on_a_protected_route(self, client_with_db, fake_graph):
        register_resp = _register(client_with_db, email="e2e@example.com", tenant_name="E2E Tenant")
        token = register_resp.json()["access_token"]

        resp = client_with_db.get(
            "/api/v1/connectors/",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200, resp.text

    def test_protected_route_without_a_token_is_rejected(self, client_with_db):
        resp = client_with_db.get("/api/v1/connectors/")
        assert resp.status_code == 401
