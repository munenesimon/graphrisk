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

from app.connectors.adapters.wazuh import WazuhAdapter, MAX_VULNERABILITIES_PER_RUN, detect_protection
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


@responses.activate
def test_sca_counts_only_applicable_checks_and_match_the_device_page():
    """Wazuh also reports checks that don't apply to a device. The run
    message must count only applicable ones (pass + fail), like Wazuh's own
    score, so it agrees with the benchmark card on the device page."""
    with _mock_private_dns():
        responses.add(
            responses.POST, f"{BASE_URL}/security/user/authenticate",
            json={"data": {"token": "fake-wazuh-jwt"}}, status=200,
        )
        responses.add(
            responses.GET, f"{BASE_URL}/agents",
            json={"data": {"affected_items": [
                {"id": "001", "status": "active", "name": "Simo", "os": {"platform": "windows"}},
            ]}},
            status=200,
        )
        responses.add(
            responses.GET, f"{BASE_URL}/sca/001",
            json={"data": {"affected_items": [
                {"policy_id": "cis_win10", "name": "CIS Windows 10", "pass": 115, "fail": 302, "total_checks": 424},
            ]}},
            status=200,
        )
        adapter = WazuhAdapter(
            tenant_id="test-tenant",
            config={"api_url": BASE_URL, "username": "u", "password": "p", "verify_ssl": False},
        )
        sca = adapter.run_check("wazuh_sca_compliance")

    assert sca.total_count == 417
    assert sca.affected_count == 302
    assert sca.score == round(115 / 417, 4)
    assert "302 of 417 applicable SCA checks failing" in sca.detail
    assert "(7 not applicable)" in sca.detail



# ── Endpoint protection detection ────────────────────────────────────────────

def test_detect_protection_reports_running_and_installed_products_separately():
    section = detect_protection(
        {"msmpeng.exe", "explorer.exe", "wazuh-agent.exe"},
        ["WinRAR 7.11", "Malwarebytes version 4.6", "Reset Tool", "Preset Manager"],
        {"passed": 6, "failed": 3, "gaps": ["Ensure 'Turn on behavior monitoring' is set to 'Enabled'"]},
    )
    assert section["status"] == "Active"
    assert section["product"] == "Microsoft Defender Antivirus, Malwarebytes"
    assert section["detected"] == [
        "Microsoft Defender Antivirus (Antivirus) — running (msmpeng.exe)",
        "Malwarebytes — installed, not seen running",
    ]
    # "Reset"/"Preset" must not read as ESET -- whole-word matching.
    assert "ESET" not in section["product"]
    assert section["policy"] == "Microsoft Defender settings: 6 of 9 CIS benchmark checks pass"
    assert section["policy_gaps"] == ["Ensure 'Turn on behavior monitoring' is set to 'Enabled'"]
    assert section["running"] is True


def test_detect_protection_distinguishes_none_found_from_unknown():
    # Processes were read and nothing protective is running.
    assert detect_protection({"explorer.exe"}, ["AVG Driver Updater"]) == {
        "status": "Not detected", "running": False, "running_products": [],
    }
    # Processes couldn't be read: an installed product is reported, but we
    # don't claim to know whether it runs -- and there's no "running" marker.
    section = detect_protection(None, ["ESET Security"])
    assert section["status"] == "Installed"
    assert "running" not in section
    # No evidence at all.
    assert detect_protection(None, None) is None


def _register_single_windows_agent(processes):
    responses.add(responses.POST, f"{BASE_URL}/security/user/authenticate",
                  json={"data": {"token": "fake-wazuh-jwt"}}, status=200)
    responses.add(responses.GET, f"{BASE_URL}/agents", json={"data": {"affected_items": [
        {"id": "001", "status": "active", "name": "Simo", "os": {"platform": "windows"}},
    ]}}, status=200)
    sc = f"{BASE_URL}/syscollector/001"
    responses.add(responses.GET, f"{sc}/processes", json={"data": {
        "affected_items": [{"name": n} for n in processes], "total_affected_items": len(processes)}})
    responses.add(responses.GET, f"{sc}/packages", json={"data": {
        "affected_items": [{"name": "Malwarebytes version 4.6"}], "total_affected_items": 1}})
    responses.add(responses.GET, f"{BASE_URL}/sca/001", json={"data": {"affected_items": [
        {"policy_id": "cis_win10_enterprise"}]}})
    responses.add(responses.GET, f"{BASE_URL}/sca/001/checks/cis_win10_enterprise", json={"data": {"affected_items": [
        {"title": "Ensure 'Turn off Microsoft Defender AntiVirus' is set to 'Disabled'", "result": "passed"},
        {"title": "Ensure 'Turn on behavior monitoring' (Microsoft Defender) is set to 'Enabled'", "result": "failed"},
        {"title": "Ensure 'Account lockout threshold' is set", "result": "failed"},
    ]}})


@responses.activate
def test_edr_check_counts_a_reporting_agent_with_antivirus_running_as_covered():
    with _mock_private_dns():
        _register_single_windows_agent(["MsMpEng.exe", "explorer.exe"])
        result = WazuhAdapter(tenant_id="t", config={
            "api_url": BASE_URL, "username": "u", "password": "p", "verify_ssl": False,
        }).run_check("wazuh_agent_connectivity")

    assert result.score == 1.0
    assert result.status == CheckStatus.PASS
    assert "antivirus/EDR running on 1 of 1 checked (Microsoft Defender Antivirus)" in result.detail
    protection = result.discovered_assets[0]["profile"]["protection"]
    assert protection["status"] == "Active"
    assert protection["policy"] == "Microsoft Defender settings: 1 of 2 CIS benchmark checks pass"
    assert protection["policy_gaps"] == ["Ensure 'Turn on behavior monitoring' (Microsoft Defender) is set to 'Enabled'"]
    # The EDR check's internal markers never reach the stored profile.
    assert "running" not in protection and "running_products" not in protection


@responses.activate
def test_edr_check_does_not_count_a_reporting_agent_without_antivirus():
    with _mock_private_dns():
        _register_single_windows_agent(["csrss.exe", "services.exe", "explorer.exe", "wazuh-agent.exe"])
        result = WazuhAdapter(tenant_id="t", config={
            "api_url": BASE_URL, "username": "u", "password": "p", "verify_ssl": False,
        }).run_check("wazuh_agent_connectivity")

    # Reporting, but nothing protective running: not covered.
    assert result.score == 0.0
    assert result.status == CheckStatus.FAIL
    assert result.affected_count == 1
    assert "antivirus/EDR running on 0 of 1 checked" in result.detail
    protection = result.discovered_assets[0]["profile"]["protection"]
    assert protection["status"] == "Installed, not seen running"
    assert protection["detected"] == ["Malwarebytes — installed, not seen running"]


# ── Vulnerability patching -> "Vulnerability & Patch Management" ─────────────

def _register_two_active_agents():
    responses.add(responses.POST, f"{BASE_URL}/security/user/authenticate",
                  json={"data": {"token": "fake-wazuh-jwt"}}, status=200)
    responses.add(responses.GET, f"{BASE_URL}/agents", json={"data": {"affected_items": [
        {"id": "000", "status": "active"},
        {"id": "001", "status": "active", "name": "Simo"},
        {"id": "002", "status": "active", "name": "build-02"},
    ]}}, status=200)


@responses.activate
def test_patching_check_scores_the_share_of_devices_without_critical_or_high_findings():
    with _mock_private_dns():
        _register_two_active_agents()
        responses.add(responses.POST, f"{INDEXER_URL}/wazuh-states-vulnerabilities-*/_search", json={
            "aggregations": {"by_agent": {"buckets": [
                {"key": "001", "by_severity": {"buckets": [{"key": "High", "doc_count": 274},
                                                           {"key": "Critical", "doc_count": 39},
                                                           {"key": "Medium", "doc_count": 208}]}},
                {"key": "002", "by_severity": {"buckets": [{"key": "Medium", "doc_count": 3}]}},
            ]}}})
        adapter = WazuhAdapter(tenant_id="t", config=_wazuh_config_with_indexer())
        assert "wazuh_vulnerability_patching" in adapter.supported_checks()
        result = adapter.run_check("wazuh_vulnerability_patching")

    # Every open finding counts, weighted by severity: 39x10 + 274x4 + 211x1.
    assert result.raw_data["progress"] == {"open_weight": 1697.0, "devices": 2}
    assert result.score == 0.0                     # no history yet: nothing resolved
    assert result.status == CheckStatus.FAIL
    assert result.affected_count == 1 and result.total_count == 2
    assert result.control_title == "Vulnerability & Patch Management"
    assert result.detail == ("39 critical, 274 high, 211 medium and 0 low findings open across "
                             "2 scanned devices; 1 with no Critical or High")


@responses.activate
def test_patching_check_refuses_to_score_without_scan_data():
    with _mock_private_dns():
        _register_two_active_agents()
        responses.add(responses.POST, f"{INDEXER_URL}/wazuh-states-vulnerabilities-*/_search",
                      json={"aggregations": {"by_agent": {"buckets": []}}})
        adapter = WazuhAdapter(tenant_id="t", config=_wazuh_config_with_indexer())
        with pytest.raises(RuntimeError, match="No vulnerability scan results"):
            adapter.run_check("wazuh_vulnerability_patching")


def test_patching_check_is_skipped_without_the_indexer():
    adapter = WazuhAdapter(tenant_id="t", config={"api_url": BASE_URL, "username": "u", "password": "p"})
    assert adapter.supported_checks() == ["wazuh_agent_connectivity", "wazuh_sca_compliance"]



@responses.activate
def test_patching_check_gives_partial_credit_for_a_light_load():
    with _mock_private_dns():
        _register_two_active_agents()
        responses.add(responses.POST, f"{INDEXER_URL}/wazuh-states-vulnerabilities-*/_search", json={
            "aggregations": {"by_agent": {"buckets": [
                {"key": "001", "by_severity": {"buckets": [{"key": "Medium", "doc_count": 4}]}},
                {"key": "002", "by_severity": {"buckets": []}},
            ]}}})
        result = WazuhAdapter(tenant_id="t", config=_wazuh_config_with_indexer()).run_check(
            "wazuh_vulnerability_patching")
    # 4 Medium against a floor of 20 per device x 2 devices.
    assert result.score == 0.9


def test_defender_is_recognised_by_its_companion_processes():
    # MsMpEng.exe is protected and can be missing from Wazuh's list; the
    # Defender platform processes that run alongside it still show up.
    section = detect_protection({"lsass.exe", "defendersessionhelper.exe", "explorer.exe"}, [],
                                platform="windows")
    assert section["status"] == "Active"
    assert section["running"] is True
    assert section["detected"] == [
        "Microsoft Defender Antivirus (Antivirus) — running (defendersessionhelper.exe)"]


def test_hidden_protected_processes_mean_unknown_not_unprotected():
    # A Windows list with none of the protected core processes can't show an
    # antivirus engine either -- so nothing found is "not confirmed", and the
    # EDR check treats it as unchecked rather than unprotected.
    section = detect_protection({"lsass.exe", "explorer.exe"}, ["AVG Driver Updater"], platform="windows")
    assert section["status"] == "Not confirmed"
    assert "running" not in section
    assert "protected processes" in section["note"]
    # With the core processes visible, the same result is a real "none running".
    full = detect_protection({"csrss.exe", "services.exe", "explorer.exe"}, [], platform="windows")
    assert full["status"] == "Not detected" and full["running"] is False
    # Linux lists aren't judged by Windows process names.
    assert detect_protection({"sshd"}, [], platform="ubuntu")["status"] == "Not detected"


@responses.activate
def test_edr_check_counts_hidden_processes_as_reporting_only():
    with _mock_private_dns():
        _register_single_windows_agent(["lsass.exe", "explorer.exe"])
        result = WazuhAdapter(tenant_id="t", config={
            "api_url": BASE_URL, "username": "u", "password": "p", "verify_ssl": False,
        }).run_check("wazuh_agent_connectivity")

    assert result.score == 1.0
    assert "couldn't confirm antivirus from the running processes" in result.detail
    protection = result.discovered_assets[0]["profile"]["protection"]
    assert protection["status"] == "Installed"
    assert protection["detected"] == ["Malwarebytes — installed (couldn't check whether it's running)"]
