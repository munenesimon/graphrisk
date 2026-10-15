"""
Findings for a package version the device itself no longer reports are held
back as "fixed on the device, awaiting rescan": not ingested, not scored,
and listed on the asset page.
"""
import responses

from app.connectors.adapters.wazuh import WazuhAdapter, stale_packages
from tests.test_wazuh_connector import (BASE_URL, INDEXER_URL, _mock_private_dns,
                                        _wazuh_config_with_indexer, _vuln_hit)

OLD = ("Wireshark 4.4.5 x64", "4.4.5")
SQL = ("Microsoft SQL Server 2019 Setup (English)", "15.0.4013.40")
INSTALLED = {("Wireshark 4.6.9 x64", "4.6.9"), SQL, ("Notepad++ (64-bit x64)", "8.9.8.1")}


def test_a_version_the_device_no_longer_has_is_stale():
    assert stale_packages({OLD, SQL}, INSTALLED) == {OLD}


def test_nothing_is_stale_without_a_complete_inventory():
    assert stale_packages({OLD, SQL}, None) == set()
    assert stale_packages({OLD, SQL}, set()) == set()


def test_too_many_missing_means_the_names_do_not_match_so_none_are_held_back():
    pairs = {("A", "1"), ("B", "1"), ("C", "1"), ("D", "1")}
    assert stale_packages(pairs, {("A", "1"), ("Z", "9")}) == set()
    # With only a couple of vulnerable packages there's too little to judge,
    # so a single updated package is still held back.
    assert stale_packages({OLD}, INSTALLED) == {OLD}


def _with_pkg(hit, name, version):
    hit["_source"]["package"] = {"name": name, "version": version}
    return hit


def _register(packages, total=None):
    responses.add(responses.POST, f"{BASE_URL}/security/user/authenticate",
                  json={"data": {"token": "jwt"}}, status=200)
    responses.add(responses.GET, f"{BASE_URL}/agents", json={"data": {"affected_items": [
        {"id": "001", "status": "active", "name": "Simo", "os": {"platform": "windows"}}]}})
    responses.add(responses.GET, f"{BASE_URL}/syscollector/001/packages", json={"data": {
        "affected_items": [{"name": n, "version": v} for n, v in packages],
        "total_affected_items": total if total is not None else len(packages)}})


@responses.activate
def test_connectivity_run_holds_back_findings_for_an_updated_package():
    with _mock_private_dns():
        _register(INSTALLED)
        responses.add(responses.POST, f"{INDEXER_URL}/wazuh-states-vulnerabilities-*/_search", json={"hits": {
            "total": {"value": 2},
            "hits": [_with_pkg(_vuln_hit("001", "CVE-OLD", severity="High"), *OLD),
                     _with_pkg(_vuln_hit("001", "CVE-SQL", severity="Critical"), *SQL)]}})
        result = WazuhAdapter(tenant_id="t", config=_wazuh_config_with_indexer(
            collect_inventory=False)).run_check("wazuh_agent_connectivity")

    asset = result.discovered_assets[0]
    assert [v["cve_id"] for v in asset["vulnerabilities"]] == ["CVE-SQL"]
    names = [p["name"] for p in asset["profile"]["software"]["vulnerable_packages"]]
    assert names == [SQL[0]]


@responses.activate
def test_an_incomplete_inventory_holds_nothing_back():
    with _mock_private_dns():
        _register(INSTALLED, total=5000)
        responses.add(responses.POST, f"{INDEXER_URL}/wazuh-states-vulnerabilities-*/_search", json={"hits": {
            "total": {"value": 2},
            "hits": [_with_pkg(_vuln_hit("001", "CVE-OLD"), *OLD),
                     _with_pkg(_vuln_hit("001", "CVE-SQL"), *SQL)]}})
        result = WazuhAdapter(tenant_id="t", config=_wazuh_config_with_indexer(
            collect_inventory=False)).run_check("wazuh_agent_connectivity")
    assert {v["cve_id"] for v in result.discovered_assets[0]["vulnerabilities"]} == {"CVE-OLD", "CVE-SQL"}


@responses.activate
def test_patching_score_leaves_out_findings_awaiting_rescan():
    with _mock_private_dns():
        _register(INSTALLED)
        responses.add(responses.POST, f"{INDEXER_URL}/wazuh-states-vulnerabilities-*/_search", json={
            "aggregations": {"by_agent": {"buckets": [{
                "key": "001",
                "by_severity": {"buckets": [{"key": "Critical", "doc_count": 5},
                                            {"key": "High", "doc_count": 14}]},
                "by_package": {"buckets": [
                    {"key": OLD[0], "by_version": {"buckets": [{"key": OLD[1], "by_severity": {"buckets": [
                        {"key": "High", "doc_count": 10}]}}]}},
                    {"key": SQL[0], "by_version": {"buckets": [{"key": SQL[1], "by_severity": {"buckets": [
                        {"key": "Critical", "doc_count": 5}, {"key": "High", "doc_count": 4}]}}]}},
                ]},
            }]}}})
        result = WazuhAdapter(tenant_id="t", config=_wazuh_config_with_indexer()).run_check(
            "wazuh_vulnerability_patching")
    assert result.detail.startswith("5 critical, 4 high, 0 medium and 0 low findings open across 1 scanned device")
    assert "10 findings in 1 package the device no longer reports are awaiting rescan and not counted" in result.detail


@responses.activate
def test_asset_page_lists_what_is_awaiting_rescan():
    with _mock_private_dns():
        _register(INSTALLED)
        search = f"{INDEXER_URL}/wazuh-states-vulnerabilities-*/_search"
        responses.add(responses.POST, search, json={"aggregations": {"by_agent": {"buckets": [{
            "key": "001",
            "by_severity": {"buckets": [{"key": "High", "doc_count": 84}]},
            "by_package": {"buckets": [{"key": OLD[0], "by_version": {"buckets": [
                {"key": OLD[1], "by_severity": {"buckets": [{"key": "High", "doc_count": 84}]}}]}}]},
        }]}}})
        responses.add(responses.POST, search, json={"hits": {"total": {"value": 1}, "hits": [
            _with_pkg(_vuln_hit("001", "CVE-OLD"), *OLD)]}})
        result = WazuhAdapter(tenant_id="t", config=_wazuh_config_with_indexer(
            collect_inventory=False)).run_check("wazuh_agent_connectivity")
    profile = result.discovered_assets[0]["profile"]
    assert profile["software"]["awaiting_rescan"] == ["Wireshark 4.4.5 x64: 84 findings"]
    assert profile["vulnerabilities"]["awaiting_rescan"] == 84
    assert profile["vulnerabilities"]["counts_by_severity"] == {"High": 0}
    assert "vulnerabilities" not in result.discovered_assets[0]


def test_package_label_does_not_repeat_a_version_already_in_the_name():
    from app.connectors.profile import package_label
    assert package_label("Wireshark 4.4.5 x64", "4.4.5") == "Wireshark 4.4.5 x64"
    assert package_label("Oracle VirtualBox 7.1.6", "7.1.6") == "Oracle VirtualBox 7.1.6"
    assert package_label("n8n", "1.120.4") == "n8n 1.120.4"
    # A longer, more exact version is still shown.
    assert package_label("Microsoft ASP.NET Core 8.0.14 - Shared Framework (x86)", "8.0.14.25112") == \
        "Microsoft ASP.NET Core 8.0.14 - Shared Framework (x86) 8.0.14.25112"
    assert package_label("Tool", None) == "Tool"
