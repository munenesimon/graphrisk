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
import json
import socket
from unittest.mock import patch

import pytest
import responses

from app.connectors.adapters.wazuh import WazuhAdapter, MAX_VULNERABILITIES_PER_RUN
from app.connectors.base import UnsafeURLError
from app.connectors.models import CheckStatus

BASE_URL = "https://wazuh-manager.internal:55000"
INDEXER_URL = "https://wazuh-manager.internal:9200"  # same host, separate service/port -- realistic all-in-one layout


def _mock_getaddrinfo(mapping):
    def _fake(host, *a, **kw):
        ip = mapping.get(host)
        if ip is None:
            raise socket.gaierror(f"mock: unknown host {host!r}")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]
    return _fake


def _mock_private_dns():
    # wazuh-manager.internal resolves to an ordinary private address --
    # exactly the case allow_private=True exists to permit. Same host
    # backs the indexer too (a realistic all-in-one install), just a
    # different port -- one DNS mapping covers both.
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
            # "Simo" has OS info -- exercises the vendor/product mapping
            # discovered_assets feeds into CVE correlation (see
            # WazuhAdapter._agent_to_asset / _OS_PLATFORM_TO_VENDOR_PRODUCT).
            {"id": "001", "status": "active", "name": "Simo", "os": {"platform": "windows"}},
            # No "name" at all -- exercises the id-based fallback name.
            {"id": "002", "status": "active"},
            {"id": "003", "status": "active", "name": "build-agent-03", "os": {"platform": "ubuntu"}},
            {"id": "004", "status": "disconnected", "name": "old-laptop"},
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

        # One discovered_assets entry per non-manager agent, regardless of
        # status -- a disconnected agent is still a real device GraphRisk
        # should show, not something to drop from the asset inventory.
        by_name = {a["name"]: a for a in connectivity.discovered_assets}
        assert set(by_name) == {"Simo", "Wazuh Agent 002", "build-agent-03", "old-laptop"}
        assert by_name["Simo"]["vendor"] == "Microsoft"
        assert by_name["Simo"]["product"] == "Windows"
        assert by_name["Simo"]["asset_type"] == "Endpoint"
        # An OS platform this adapter doesn't have a mapping for yet (or no
        # OS info at all) leaves vendor/product unset rather than guessing.
        assert by_name["build-agent-03"]["vendor"] is None
        assert by_name["Wazuh Agent 002"]["vendor"] is None
        # No indexer_url configured on this adapter -- every asset carries
        # no vulnerabilities at all, not an empty list (see _check_agent_
        # connectivity: the key is only ever set when there's something to
        # put in it).
        assert all("vulnerabilities" not in a for a in connectivity.discovered_assets)

        sca = by_id["wazuh_sca_compliance"]
        # 17 of 20 checks passing across agents 001/002; 003 has no SCA data
        assert sca.total_count == 20
        assert sca.affected_count == 3
        assert sca.score == 0.85
        assert sca.status == CheckStatus.WARNING
        assert "2 of 3 active agents" in sca.detail


def _register_indexer_vulns(hits):
    responses.add(
        responses.POST, f"{INDEXER_URL}/wazuh-states-vulnerabilities-*/_search",
        json={"hits": {"hits": hits}},
        status=200,
    )


def _vuln_hit(agent_id, cve_id, severity="High", score=7.5, source="Open Source Vulnerabilities"):
    """One indexer hit, shaped exactly like the real document a live Wazuh
    4.14 instance returns (see the "_source" fields this adapter reads)."""
    return {"_source": {
        "agent": {"id": agent_id},
        "vulnerability": {
            "id": cve_id,
            "severity": severity,
            "score": {"base": score},
            "description": "A description of the finding.",
            "published_at": "2026-08-11T13:19:08Z",
            "scanner": {"source": source},
        },
    }}


def _wazuh_config_with_indexer(**overrides):
    config = {
        "api_url": BASE_URL,
        "username": "wazuh-wui",
        "password": "fake-password",
        "verify_ssl": False,
        "indexer_url": INDEXER_URL,
        "indexer_username": "admin",
        "indexer_password": "fake-indexer-password",
    }
    config.update(overrides)
    return config


@responses.activate
def test_wazuh_adapter_enriches_assets_with_indexer_vulnerabilities_when_configured():
    with _mock_private_dns():
        _register_wazuh_api()
        _register_indexer_vulns([
            _vuln_hit("001", "CVE-2026-72775", severity="High", score=8.8),
            _vuln_hit("002", "CVE-2026-11111", severity="Critical", score=9.8),
        ])

        adapter = WazuhAdapter(tenant_id="test-tenant", config=_wazuh_config_with_indexer())
        connectivity = adapter.run_check("wazuh_agent_connectivity")

        by_name = {a["name"]: a for a in connectivity.discovered_assets}
        assert by_name["Simo"]["vulnerabilities"] == [{
            "cve_id": "CVE-2026-72775",
            "severity": "High",
            "cvss_score": 8.8,
            "description": "A description of the finding.",
            "published_at": "2026-08-11T13:19:08Z",
            "source": "Wazuh (Open Source Vulnerabilities)",
        }]
        assert by_name["Wazuh Agent 002"]["vulnerabilities"][0]["cve_id"] == "CVE-2026-11111"
        # Agents the mocked indexer reported nothing for carry no key at all.
        assert "vulnerabilities" not in by_name["build-agent-03"]
        assert "vulnerabilities" not in by_name["old-laptop"]

        # The actual query sent to the indexer is what matters most here --
        # wrong filter fields would silently return nothing against a real
        # instance, same class of bug as the SCA control_title mismatch.
        sent_body = json.loads(responses.calls[-1].request.body)
        assert sent_body["size"] == MAX_VULNERABILITIES_PER_RUN
        assert set(sent_body["query"]["bool"]["filter"][0]["terms"]["agent.id"]) == {"001", "002", "003", "004"}
        assert set(sent_body["query"]["bool"]["filter"][1]["terms"]["vulnerability.severity"]) == {"Critical", "High"}


@responses.activate
def test_wazuh_adapter_derives_the_indexer_url_from_the_manager_host_when_indexer_url_is_omitted():
    """Most self-hosted installs run manager and indexer on the same box,
    just on different ports -- a tenant who sets indexer_username/
    indexer_password but never types indexer_url should still get real
    vulnerability data, against the derived host:9200 address (see
    WazuhAdapter._effective_indexer_url)."""
    with _mock_private_dns():
        _register_wazuh_api()
        _register_indexer_vulns([_vuln_hit("001", "CVE-2026-72775")])

        config = _wazuh_config_with_indexer()
        del config["indexer_url"]

        adapter = WazuhAdapter(tenant_id="test-tenant", config=config)
        connectivity = adapter.run_check("wazuh_agent_connectivity")

        by_name = {a["name"]: a for a in connectivity.discovered_assets}
        assert by_name["Simo"]["vulnerabilities"][0]["cve_id"] == "CVE-2026-72775"
        # BASE_URL and INDEXER_URL share a host in this fixture on purpose
        # (see INDEXER_URL's comment) -- proves the request actually went
        # to the *derived* address, not a hardcoded one, since responses
        # would 404 a mismatched URL rather than silently pass.
        assert responses.calls[-1].request.url.startswith(INDEXER_URL)


@responses.activate
def test_wazuh_adapter_survives_an_unreachable_or_misconfigured_indexer():
    """A bad indexer_password, an unreachable host, an index that doesn't
    exist yet -- none of these should take down agent connectivity, which
    has nothing to do with the indexer at all. Assets just carry no
    vulnerabilities for this run."""
    with _mock_private_dns():
        _register_wazuh_api()
        responses.add(
            responses.POST, f"{INDEXER_URL}/wazuh-states-vulnerabilities-*/_search",
            json={"error": "unauthorized"}, status=401,
        )

        adapter = WazuhAdapter(tenant_id="test-tenant", config=_wazuh_config_with_indexer())
        connectivity = adapter.run_check("wazuh_agent_connectivity")

        assert connectivity.total_count == 4  # the check itself is unaffected
        assert all("vulnerabilities" not in a for a in connectivity.discovered_assets)


@responses.activate
def test_wazuh_adapter_skips_the_indexer_entirely_when_not_configured():
    """No indexer_url at all -- the adapter shouldn't even attempt a
    request (a tenant that hasn't set this up yet shouldn't see failed
    requests in their logs for a feature they never opted into)."""
    with _mock_private_dns():
        _register_wazuh_api()
        adapter = WazuhAdapter(
            tenant_id="test-tenant",
            config={"api_url": BASE_URL, "username": "wazuh-wui", "password": "fake-password", "verify_ssl": False},
        )
        adapter.run_check("wazuh_agent_connectivity")
        assert not any("9200" in call.request.url for call in responses.calls)


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
