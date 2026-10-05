"""
Root cause in Blast Radius: blast_radius.risk_drivers lists, per (risk,
asset) link, the CVEs recorded as the reason for it -- see
_risk_drivers in app/api/v1/blast_radius.py.
"""
from app.graph import queries as app_queries

CONTROL_ROW = {
    "control_title": "Endpoint Detection & Response", "control_status": "Implemented",
    "effectiveness_score": 1.0, "exposed_risks": ["Ransomware Infection Risk"],
    "affected_assets": ["Simo"], "affected_asset_ids": [], "impacted_processes": [],
    "frameworks": [], "framework_controls": [], "mapped_framework_controls": [],
    "risk_count": 1, "asset_count": 1,
}


def _query_router(driver_rows):
    def _fake(query, params=None):
        if query == app_queries.BLAST_RADIUS_CONTROL:
            return [CONTROL_ROW]
        if query == app_queries.BLAST_RADIUS_RISK_DRIVERS:
            return driver_rows
        return []
    return _fake


def _drivers(client, fake_graph, as_user, rows):
    as_user(graph_tenant_id="acme")
    fake_graph.query.side_effect = _query_router(rows)
    resp = client.get("/api/v1/graph/blast-radius/control/ctrl-1")
    assert resp.status_code == 200, resp.text
    return resp.json()["blast_radius"]["risk_drivers"]


def test_known_ransomware_cves_come_first_then_by_cvss(client, fake_graph, as_user):
    drivers = _drivers(client, fake_graph, as_user, [{
        "risk": "Ransomware Infection Risk", "asset": "Simo",
        "cve_ids": ["CVE-A", "CVE-B", "CVE-C"],
        "cves": [
            {"cve_id": "CVE-A", "severity": "High", "cvss_score": 7.5, "ransomware_use": "Unknown"},
            {"cve_id": "CVE-B", "severity": "Critical", "cvss_score": 9.8, "ransomware_use": "Unknown"},
            {"cve_id": "CVE-C", "severity": "High", "cvss_score": 7.0, "ransomware_use": "Known"},
        ],
    }])
    assert len(drivers) == 1
    d = drivers[0]
    assert (d["risk"], d["asset"], d["total_cves"]) == ("Ransomware Infection Risk", "Simo", 3)
    assert [c["cve_id"] for c in d["cves"]] == ["CVE-C", "CVE-B", "CVE-A"]
    assert [c["known_ransomware"] for c in d["cves"]] == [True, False, False]


def test_caps_listed_cves_but_reports_the_true_total(client, fake_graph, as_user):
    ids = [f"CVE-{i}" for i in range(25)]
    drivers = _drivers(client, fake_graph, as_user, [{
        "risk": "Unpatched Vulnerability Risk", "asset": "Simo", "cve_ids": ids,
        "cves": [{"cve_id": i, "severity": "High", "cvss_score": 7.0} for i in ids],
    }])
    assert drivers[0]["total_cves"] == 25
    assert len(drivers[0]["cves"]) == 10


def test_a_link_without_recorded_cves_is_kept_with_an_empty_list(client, fake_graph, as_user):
    drivers = _drivers(client, fake_graph, as_user, [
        {"risk": "Ransomware Infection Risk", "asset": "HR Database", "cve_ids": [], "cves": []},
    ])
    assert drivers == [{"risk": "Ransomware Infection Risk", "asset": "HR Database", "total_cves": 0, "cves": []}]
