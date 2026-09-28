"""
Offline tests for WazuhAdapter using the `responses` library to simulate a
self-hosted Wazuh manager, plus a regression check for the allow_private
SSRF wiring specific to this connector (see base.py's _assert_safe_url and
the "Wazuh SSRF gap" fix in the Roadmap doc).

Unlike the other four connectors, Wazuh's authenticate()/_wazuh_get() call
self._session directly instead of BaseConnector's shared _get()/_post(),
so it needs its own explicit proof that _assert_safe_url() is still being
called -- with allow_private=True, since a real customer's manager
legitimately lives on a private network -- and that loopback/link-local
targets are still rejected even so.
"""
import socket
from unittest.mock import patch

import pytest
import responses

from app.connectors.adapters.wazuh import WazuhAdapter
from app.connectors.base import UnsafeURLError
from app.connectors.models import CheckStatus

BASE_URL = "https://wazuh-manager.internal:55000"


def _mock_getaddrinfo(mapping):
    def _fake(host, *a, **kw):
        ip = mapping.get(host)
        if ip is None:
            raise socket.gaierror(f"mock: unknown host {host!r}")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]
    return _fake


def _mock_private_dns():
    # wazuh-manager.internal resolves to an ordinary private address --
    # exactly the case allow_private=True exists to permit.
    return patch("app.connectors.base.socket.getaddrinfo", side_effect=_mock_getaddrinfo({"wazuh-manager.internal": "192.168.1.50"}))


def _register_wazuh_api():
    responses.add(
        responses.POST, f"{BASE_URL}/security/user/authenticate",
        json={"data": {"token": "fake-wazuh-jwt"}},
        status=200,
    )
    # First /agents call: no status filter, used by wazuh_agent_connectivity.
    # "000" is the manager itself and must be excluded from the count.
    responses.add(
        responses.GET, f"{BASE_URL}/agents",
        json={"data": {"affected_items": [
            {"id": "000", "status": "active"},
            {"id": "001", "status": "active"},
            {"id": "002", "status": "active"},
            {"id": "003", "status": "active"},
            {"id": "004", "status": "disconnected"},
        ]}},
        status=200,
    )
    # Second /agents call: status=active, used by wazuh_sca_compliance's
    # agent sweep. `responses` serves repeated registrations for the same
    # URL in order, so this one is consumed by the second call.
    responses.add(
        responses.GET, f"{BASE_URL}/agents",
        json={"data": {"affected_items": [
            {"id": "001", "status": "active"},
            {"id": "002", "status": "active"},
            {"id": "003", "status": "active"},
        ]}},
        status=200,
    )
    responses.add(
        responses.GET, f"{BASE_URL}/sca/001",
        json={"data": {"affected_items": [{"pass": 8, "total_checks": 10}]}},
        status=200,
    )
    responses.add(
        responses.GET, f"{BASE_URL}/sca/002",
        json={"data": {"affected_items": [{"pass": 9, "total_checks": 10}]}},
        status=200,
    )
    responses.add(
        responses.GET, f"{BASE_URL}/sca/003",
        json={"data": {"affected_items": []}},  # SCA module not enabled on this agent
        status=200,
    )


@responses.activate
def test_wazuh_adapter_runs_both_checks_against_a_private_manager():
    with _mock_private_dns():
        _register_wazuh_api()

        adapter = WazuhAdapter(
            tenant_id="test-tenant",
            config={
                "api_url": BASE_URL,
                "username": "wazuh-wui",
                "password": "fake-password",
                "verify_ssl": False,  # self-signed cert, as most real Wazuh installs are
            },
        )

        results, errors = adapter.run_all_checks()

        assert errors == [], f"Expected no errors against the simulated manager, got: {errors}"
        assert len(results) == 2

        by_id = {r.check_id: r for r in results}

        connectivity = by_id["wazuh_agent_connectivity"]
        # 4 non-manager agents, 3 active, 1 disconnected -> 0.75
        assert connectivity.total_count == 4
        assert connectivity.affected_count == 1
        assert connectivity.score == 0.75
        assert connectivity.status == CheckStatus.FAIL

        sca = by_id["wazuh_sca_compliance"]
        # 17 of 20 checks passing across agents 001/002; 003 has no SCA data
        assert sca.total_count == 20
        assert sca.affected_count == 3
        assert sca.score == 0.85
        assert sca.status == CheckStatus.WARNING
        assert "2 of 3 active agents" in sca.detail


@pytest.mark.parametrize("host,ip", [
    ("localhost-manager.attacker.test", "127.0.0.1"),
    ("metadata-manager.attacker.test", "169.254.169.254"),
])
def test_wazuh_adapter_still_rejects_loopback_and_link_local_targets(host, ip):
    """Regression test for the gap found while live-verifying this connector
    for the first time: authenticate()/_wazuh_get() call self._session
    directly rather than BaseConnector's shared _get()/_post(), so they
    need their own explicit _assert_safe_url() wiring -- this proves it's
    actually there, not just present on the unused shared helpers."""
    with patch("app.connectors.base.socket.getaddrinfo", side_effect=_mock_getaddrinfo({host: ip})):
        adapter = WazuhAdapter(
            tenant_id="test-tenant",
            config={"api_url": f"https://{host}:55000", "username": "u", "password": "p"},
        )
        with pytest.raises(UnsafeURLError):
            adapter.authenticate()


if __name__ == "__main__":
    test_wazuh_adapter_runs_both_checks_against_a_private_manager()
    print("OK: test_wazuh_adapter_runs_both_checks_against_a_private_manager")
    for host, ip in [("localhost-manager.attacker.test", "127.0.0.1"), ("metadata-manager.attacker.test", "169.254.169.254")]:
        test_wazuh_adapter_still_rejects_loopback_and_link_local_targets(host, ip)
        print(f"OK: rejects {host} ({ip})")
