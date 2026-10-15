"""
Antivirus confirmed from Wazuh's Windows services inventory when the
process list can't see protected processes (MsMpEng and the core system
processes are hidden from the agent's process scan on some machines).
"""
import responses

from app.connectors.adapters.wazuh import WazuhAdapter, detect_protection
from tests.test_wazuh_connector import (BASE_URL, INDEXER_URL, _mock_private_dns,
                                        _register_single_windows_agent, _wazuh_config_with_indexer)

HIDDEN = {"svchost.exe", "explorer.exe", "anydesk.exe"}   # no csrss/services/smss: protected ones hidden


def test_a_running_defender_service_confirms_it_when_processes_are_hidden():
    s = detect_protection(HIDDEN, None, platform="windows", services={"WinDefend": "RUNNING"})
    assert s["running"] is True and s["running_products"] == ["Microsoft Defender Antivirus"]
    assert s["status"] == "Active"
    assert s["detected"] == ["Microsoft Defender Antivirus (Antivirus) — running (Windows service WinDefend)"]
    assert "note" not in s


def test_without_the_service_hidden_processes_stay_unconfirmed():
    s = detect_protection(HIDDEN, None, platform="windows", services={})
    assert "running" not in s and s["status"] == "Not confirmed"


def test_a_stopped_service_is_reported_but_does_not_rule_out_a_hidden_engine():
    s = detect_protection(HIDDEN, None, platform="windows", services={"WinDefend": "STOPPED"})
    assert s["detected"] == ["Microsoft Defender Antivirus — installed, service not running"]
    assert "running" not in s     # other protection could still be running unseen


def test_unknown_services_are_ignored():
    assert detect_protection(None, None, platform="windows", services={"Spooler": "RUNNING"}) is None


@responses.activate
def test_edr_check_counts_defender_confirmed_by_its_service():
    with _mock_private_dns():
        _register_single_windows_agent(sorted(HIDDEN))
        responses.add(responses.POST, f"{INDEXER_URL}/wazuh-states-inventory-services-*/_search", json={
            "hits": {"hits": [{"_source": {"agent": {"id": "001"},
                                           "service": {"id": "WinDefend", "state": "RUNNING"}}}]}})
        result = WazuhAdapter(tenant_id="t", config=_wazuh_config_with_indexer()).run_check(
            "wazuh_agent_connectivity")
    assert result.score == 1.0
    assert "antivirus/EDR running on 1 of 1 checked (Microsoft Defender Antivirus)" in result.detail
    assert result.discovered_assets[0]["profile"]["protection"]["status"] == "Active"
