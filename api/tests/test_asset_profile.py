"""
Tests for the universal device profile (app/connectors/profile.py): the
schema normalisation every connector's data goes through, how the registry
stores it (per asset/connector/section, limited to what the connector
declares it can provide), the Wazuh mapping as the first real connector,
and the GET /assets/{id}/profile endpoint that merges it for the UI.
"""
import json
import socket
from unittest.mock import patch

import responses

from app.connectors.adapters.wazuh import WazuhAdapter
from app.connectors.base import BaseConnector
from app.connectors.models import CheckResult, CheckStatus, CheckCategory
from app.connectors.profile import (
    normalize_profile, merge_sections, mask_sensitive, LIST_CAPS, to_storage,
)
from app.connectors.registry import CheckRegistry
from app.graph import queries as app_queries


# ── Schema normalisation ─────────────────────────────────────────────────────

def test_normalize_keeps_known_fields_and_moves_unknown_ones_to_extra():
    out = normalize_profile({
        "os": {"name": "Windows 11", "version": "", "flavour": "Pro"},
        "made_up_section": {"thing": 1},
        "health": {"status": None},
    })
    assert out["os"] == {"name": "Windows 11"}           # empty value dropped
    assert out["extra"] == {"os.flavour": "Pro", "made_up_section.thing": 1}
    assert "health" not in out                            # nothing left in it


def test_normalize_caps_lists_and_trims_strings():
    ports = [{"port": p} for p in range(100)]
    out = normalize_profile({"network": {"listening_ports": ports}, "os": {"name": "x" * 1000}})
    assert len(out["network"]["listening_ports"]) == LIST_CAPS["network.listening_ports"]
    assert len(out["os"]["name"]) == 300


def test_normalize_ignores_garbage():
    assert normalize_profile(None) == {}
    assert normalize_profile({"os": "not a dict"}) == {}


# ── Merging and masking ──────────────────────────────────────────────────────

def test_merge_newest_value_per_field_wins_and_keeps_its_source():
    rows = [
        {"source": "wazuh", "section": "os", "collected_at": "2026-10-05T10:00:00",
         "data": to_storage({"name": "Windows 10", "architecture": "x86_64"})},
        {"source": "crowdstrike", "section": "os", "collected_at": "2026-10-05T12:00:00",
         "data": to_storage({"name": "Windows 11"})},
    ]
    merged = merge_sections(rows, {"wazuh": "Wazuh", "crowdstrike": "CrowdStrike Falcon"})
    os_sec = merged["os"]
    assert os_sec["fields"] == {"name": "Windows 11", "architecture": "x86_64"}
    assert os_sec["field_sources"] == {"name": "crowdstrike", "architecture": "wazuh"}
    assert [s["name"] for s in os_sec["sources"]] == ["Wazuh", "CrowdStrike Falcon"]


def test_mask_sensitive_removes_and_reports_hidden_fields():
    merged = merge_sections([
        {"source": "wazuh", "section": "network", "collected_at": "t",
         "data": to_storage({"ip_addresses": ["10.0.0.5"], "listening_ports": [{"port": 445}]})},
        {"source": "wazuh", "section": "identity", "collected_at": "t",
         "data": to_storage({"serial_number": "ABC123"})},
    ])
    hidden = mask_sensitive(merged)
    assert set(hidden) == {"network.ip_addresses", "identity.serial_number"}
    assert "ip_addresses" not in merged["network"]["fields"]
    assert merged["network"]["fields"]["listening_ports"] == [{"port": 445}]
    assert "identity" not in merged                     # nothing left to show


# ── Registry storage ─────────────────────────────────────────────────────────

class _ProfiledAdapter(BaseConnector):
    CONNECTOR_ID = "profiled"
    CONNECTOR_NAME = "Profiled Tool"
    PROFILE_SECTIONS = ("os", "health")

    def authenticate(self): pass
    def supported_checks(self): return []
    def run_check(self, check_id): raise NotImplementedError


def _registry():
    r = CheckRegistry()
    r.register(_ProfiledAdapter, [])
    return r


def _result(discovered_assets):
    return CheckResult(
        check_id="c", check_name="C", category=CheckCategory.ENDPOINT,
        source="profiled", tenant_id="tenant-1", status=CheckStatus.PASS,
        score=1.0, detail="ok", discovered_assets=discovered_assets,
    )


def _profile_writes(fake_graph):
    return [c[0][1] for c in fake_graph.write.call_args_list
            if c[0][0] == app_queries.UPSERT_ASSET_PROFILE_SECTION]


def test_registry_stores_one_snapshot_per_declared_section(fake_graph):
    fake_graph.query.return_value = [{"name": "Simo", "id": "asset-1"}]
    _registry()._ingest_assets(_result([{
        "name": "Simo",
        "profile": {
            "os": {"name": "Windows 11"},
            "health": {"status": "online"},
            "hardware": {"cpu": "i7"},          # not declared -> ignored
        },
    }]), "tenant-1")

    writes = _profile_writes(fake_graph)
    assert {w["section"] for w in writes} == {"os", "health"}
    os_write = next(w for w in writes if w["section"] == "os")
    assert os_write["asset_id"] == "asset-1"
    assert os_write["tenant_id"] == "tenant-1"
    assert os_write["source"] == "profiled"
    assert json.loads(os_write["data"]) == {"name": "Windows 11"}


def test_profile_only_entries_update_existing_assets_but_never_create_one(fake_graph):
    fake_graph.query.return_value = [{"name": "Simo", "id": "asset-1"}]
    _registry()._ingest_assets(_result([
        {"name": "Simo", "profile_only": True, "profile": {"os": {"name": "Windows 11"}}},
        {"name": "Unknown box", "profile_only": True, "profile": {"os": {"name": "Linux"}}},
    ]), "tenant-1")

    assert not any(c[0][0] == app_queries.CREATE_ASSET for c in fake_graph.write.call_args_list)
    writes = _profile_writes(fake_graph)
    assert [w["asset_id"] for w in writes] == ["asset-1"]


def test_registry_reports_profile_capabilities():
    caps = _registry().profile_capabilities
    assert caps == {"profiled": {"name": "Profiled Tool", "sections": ["os", "health"]}}


# ── Wazuh mapping ────────────────────────────────────────────────────────────

BASE_URL = "https://wazuh-manager.internal:55000"
INDEXER_URL = "https://wazuh-manager.internal:9200"


def _dns():
    def _fake(host, *a, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", 0))]
    return patch("app.connectors.base.socket.getaddrinfo", side_effect=_fake)


def _items(*items, total=None):
    return {"data": {"affected_items": list(items), "total_affected_items": total if total is not None else len(items)}}


def _register_live_like_wazuh():
    responses.add(responses.POST, f"{BASE_URL}/security/user/authenticate", json={"data": {"token": "t"}})
    responses.add(responses.GET, f"{BASE_URL}/agents", json=_items(
        {"id": "000", "status": "active"},
        {"id": "001", "status": "active", "name": "Simo", "ip": "192.168.0.53", "registerIP": "any",
         "version": "Wazuh v4.14.0", "lastKeepAlive": "2026-10-05T10:49:00+00:00",
         "dateAdd": "2026-09-20T08:00:00+00:00", "group": ["default"],
         "os": {"name": "Microsoft Windows 11 Home", "version": "10.0.26100", "platform": "windows", "arch": "x86_64"}},
    ))
    sc = f"{BASE_URL}/syscollector/001"
    responses.add(responses.GET, f"{sc}/hardware", json=_items(
        {"cpu": {"name": "Intel Core i5", "cores": 8}, "ram": {"total": 16 * 1024 * 1024, "usage": 61},
         "board_serial": "PF3XYZ"}))
    responses.add(responses.GET, f"{sc}/os", json=_items({"release": "10.0.26100", "os": {"build": "26100"}}))
    responses.add(responses.GET, f"{sc}/netiface", json=_items(
        {"name": "Wi-Fi", "mac": "aa:bb:cc:dd:ee:ff"}, {"name": "lo", "mac": "00:00:00:00:00:00"}))
    responses.add(responses.GET, f"{sc}/ports", json=_items(
        {"local": {"ip": "0.0.0.0", "port": 445}, "protocol": "tcp", "process": "System", "state": "listening"}))
    responses.add(responses.GET, f"{sc}/packages", json=_items({"name": "x"}, total=312))
    responses.add(responses.GET, f"{sc}/hotfixes", json=_items({"hotfix": "KB5044284"}, total=14))
    # Indexer: first the per-severity aggregation, then the findings search.
    responses.add(responses.POST, f"{INDEXER_URL}/wazuh-states-vulnerabilities-*/_search", json={
        "aggregations": {"by_agent": {"buckets": [{"key": "001", "by_severity": {"buckets": [
            {"key": "High", "doc_count": 2}, {"key": "Medium", "doc_count": 5}]}}]}}})
    responses.add(responses.POST, f"{INDEXER_URL}/wazuh-states-vulnerabilities-*/_search", json={
        "hits": {"hits": [
            {"_source": {"agent": {"id": "001"}, "package": {"name": "WinRAR", "version": "6.02"},
                         "vulnerability": {"id": "CVE-2023-38831", "severity": "High", "score": {"base": 7.8}}}},
            {"_source": {"agent": {"id": "001"}, "package": {"name": "WinRAR", "version": "6.02"},
                         "vulnerability": {"id": "CVE-2025-8088", "severity": "High", "score": {"base": 8.8}}}},
        ]}})


@responses.activate
def test_wazuh_maps_agent_inventory_and_findings_onto_the_profile():
    with _dns():
        _register_live_like_wazuh()
        adapter = WazuhAdapter(tenant_id="t", config={
            "api_url": BASE_URL, "username": "u", "password": "p", "verify_ssl": False,
            "indexer_url": INDEXER_URL, "indexer_username": "admin", "indexer_password": "x",
        })
        result = adapter.run_check("wazuh_agent_connectivity")

    simo = result.discovered_assets[0]
    profile = simo["profile"]
    assert profile["identity"]["hostname"] == "Simo"
    assert profile["identity"]["serial_number"] == "PF3XYZ"
    assert profile["health"] == {
        "status": "online", "last_seen": "2026-10-05T10:49:00+00:00",
        "enrolled_at": "2026-09-20T08:00:00+00:00", "agent_version": "Wazuh v4.14.0",
    }
    assert profile["os"]["name"] == "Microsoft Windows 11 Home"
    assert profile["os"]["build"] == "26100"
    assert profile["hardware"] == {"cpu": "Intel Core i5", "cpu_cores": 8,
                                   "memory_total_mb": 16384, "memory_used_percent": 61}
    assert profile["network"]["ip_addresses"] == ["192.168.0.53"]       # "any" dropped
    assert profile["network"]["mac_addresses"] == ["aa:bb:cc:dd:ee:ff"]  # loopback MAC dropped
    assert profile["network"]["listening_ports"] == [{"port": 445, "protocol": "tcp", "process": "System"}]
    assert profile["software"]["installed_count"] == 312
    assert profile["software"]["hotfixes_count"] == 14
    assert profile["software"]["vulnerable_packages"] == [{
        "name": "WinRAR", "version": "6.02", "cve_ids": ["CVE-2023-38831", "CVE-2025-8088"],
        "max_severity": "High", "cve_count": 2,
    }]
    assert profile["vulnerabilities"]["counts_by_severity"] == {"High": 2, "Medium": 5}
    assert profile["vulnerabilities"]["total"] == 7
    # Everything Wazuh reports is within what it declares it can provide.
    assert set(profile) <= set(WazuhAdapter.PROFILE_SECTIONS)
    # The findings still carry their package for the ingestion side too.
    assert simo["vulnerabilities"][0]["package"] == {"name": "WinRAR", "version": "6.02"}


@responses.activate
def test_wazuh_sca_adds_benchmarks_with_failed_checks_as_profile_only():
    with _dns():
        responses.add(responses.POST, f"{BASE_URL}/security/user/authenticate", json={"data": {"token": "t"}})
        responses.add(responses.GET, f"{BASE_URL}/agents", json=_items({"id": "001", "status": "active", "name": "Simo"}))
        responses.add(responses.GET, f"{BASE_URL}/sca/001", json=_items(
            {"policy_id": "cis_win11", "name": "CIS Microsoft Windows 11", "pass": 62, "fail": 38,
             "total_checks": 100, "score": 62, "end_scan": "2026-10-05T09:00:00+00:00"}))
        responses.add(responses.GET, f"{BASE_URL}/sca/001/checks/cis_win11", json=_items(
            {"title": "Ensure 'Account lockout threshold' is set", "remediation": "Set it to 5 or fewer."}))
        result = WazuhAdapter(tenant_id="t", config={
            "api_url": BASE_URL, "username": "u", "password": "p", "verify_ssl": False,
        }).run_check("wazuh_sca_compliance")

    entry = result.discovered_assets[0]
    assert entry["name"] == "Simo" and entry["profile_only"] is True
    bench = entry["profile"]["configuration"]["benchmarks"][0]
    assert bench["name"] == "CIS Microsoft Windows 11"
    assert bench["score"] == 62 and bench["failed"] == 38
    assert bench["failed_checks"] == [{"title": "Ensure 'Account lockout threshold' is set",
                                       "remediation": "Set it to 5 or fewer."}]


@responses.activate
def test_wazuh_stops_asking_for_inventory_when_syscollector_is_unavailable():
    with _dns():
        responses.add(responses.POST, f"{BASE_URL}/security/user/authenticate", json={"data": {"token": "t"}})
        responses.add(responses.GET, f"{BASE_URL}/agents", json=_items(
            {"id": "001", "status": "active", "name": "a"}, {"id": "002", "status": "active", "name": "b"}))
        result = WazuhAdapter(tenant_id="t", config={
            "api_url": BASE_URL, "username": "u", "password": "p", "verify_ssl": False,
        }).run_check("wazuh_agent_connectivity")

    syscollector_calls = [c for c in responses.calls if "/syscollector/" in c.request.url]
    assert all("/syscollector/001/" in c.request.url for c in syscollector_calls)
    # The basic profile (from /agents) is still there.
    assert result.discovered_assets[1]["profile"]["health"]["status"] == "online"


# ── API ──────────────────────────────────────────────────────────────────────

def _detail():
    return [{
        "asset": {"id": "asset-1", "name": "Simo", "asset_type": "Endpoint"},
        "risks": [{"id": "r1", "title": "Ransomware Infection Risk", "driver_cves": ["CVE-2023-38831"], "controls": []}],
        "vulnerabilities": [
            {"cve_id": "CVE-2024-0001", "severity": "Critical", "cvss_score": 9.8, "ransomware_use": "Unknown"},
            {"cve_id": "CVE-2023-38831", "severity": "High", "cvss_score": 7.8, "ransomware_use": "Known"},
            {"cve_id": "CVE-2025-8088", "severity": "High", "cvss_score": 8.8, "ransomware_use": "Known"},
        ],
    }]


def _profile_rows():
    return [
        {"source": "wazuh", "section": "network", "collected_at": "2026-10-05T10:50:00",
         "data": to_storage({"ip_addresses": ["192.168.0.53"], "listening_ports": [{"port": 445}]})},
        {"source": "wazuh", "section": "software", "collected_at": "2026-10-05T10:50:00",
         "data": to_storage({"vulnerable_packages": [
             {"name": "OpenSSL", "version": "3.0.1", "cve_ids": ["CVE-2024-0001"], "cve_count": 1},
             {"name": "WinRAR", "version": "6.02", "cve_ids": ["CVE-2023-38831", "CVE-2025-8088"], "cve_count": 2},
         ]})},
    ]


def _get_profile(client, fake_graph):
    fake_graph.query.side_effect = [_detail(), _profile_rows()]
    return client.get("/api/v1/assets/asset-1/profile")


def test_profile_endpoint_merges_and_orders_fix_first_by_ransomware(client, fake_graph, as_user):
    as_user(role="owner", graph_tenant_id="test")
    resp = _get_profile(client, fake_graph)
    assert resp.status_code == 200
    body = resp.json()

    assert body["asset"]["name"] == "Simo"
    assert body["profile"]["network"]["fields"]["ip_addresses"] == ["192.168.0.53"]
    assert body["profile"]["network"]["sources"][0]["name"] == "Wazuh"
    assert body["hidden_fields"] == []
    # WinRAR (ransomware-linked) outranks OpenSSL despite OpenSSL's higher CVSS.
    assert [p["name"] for p in body["fix_first"]] == ["WinRAR", "OpenSSL"]
    winrar = body["fix_first"][0]
    assert winrar["ransomware"] is True
    assert [c["cve_id"] for c in winrar["cves"]] == ["CVE-2025-8088", "CVE-2023-38831"]
    # Vulnerability list: ransomware first, then severity.
    assert [v["cve_id"] for v in body["vulnerabilities"]["items"]][0] in ("CVE-2025-8088", "CVE-2023-38831")
    assert body["vulnerabilities"]["total"] == 3
    # Capabilities say which connectors could fill each section.
    assert "Wazuh" in body["capabilities"]["hardware"]
    assert body["capabilities"]["protection"] == []


def test_profile_endpoint_hides_sensitive_fields_from_non_admins(client, fake_graph, as_user):
    as_user(role="member", graph_tenant_id="test")
    body = _get_profile(client, fake_graph).json()
    assert body["can_view_sensitive"] is False
    assert body["hidden_fields"] == ["network.ip_addresses"]
    assert "ip_addresses" not in body["profile"]["network"]["fields"]


def test_profile_endpoint_404s_for_an_unknown_asset(client, fake_graph, as_user):
    as_user()
    fake_graph.query.return_value = []
    assert client.get("/api/v1/assets/nope/profile").status_code == 404
