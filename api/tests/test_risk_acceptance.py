"""
Risk acceptance: an owner/admin accepts the findings in one package on one
device until a review date. While it's in date the package leaves the
device's actions straight away, and its findings leave the counts and the
score at the next connector run. See app/risk_acceptance.py.
"""
from datetime import date

import responses

from app.api.v1.frameworks import add_months
from app.connectors.adapters.wazuh import WazuhAdapter
from app.graph import queries as app_queries
from app.risk_acceptance import package_key, split_accepted
from tests.test_stale_findings import INSTALLED, SQL, _register, _with_pkg
from tests.test_wazuh_connector import INDEXER_URL, _mock_private_dns, _vuln_hit, _wazuh_config_with_indexer

VBOX = ("Oracle VirtualBox 7.1.6", "7.1.6")
ACCEPTED = {"simo": {package_key(*VBOX): {"name": VBOX[0], "version": VBOX[1], "review_by": "2027-04-22"}}}


# ── Matching ────────────────────────────────────────────────────────────────

def test_packages_match_on_letters_digits_and_version():
    assert package_key("ASP.NET Core 8.0.14 - Shared Framework", "8.0.14") == \
        package_key("ASP.NET Core 8.0.14 Shared Framework", "8.0.14")
    assert package_key("Tool", "1") != package_key("Tool", "2")


def test_split_accepted():
    keep, held = split_accepted([{"name": VBOX[0], "version": VBOX[1]}, {"name": SQL[0], "version": SQL[1]}],
                                ACCEPTED["simo"])
    assert [p["name"] for p in keep] == [SQL[0]] and [p["name"] for p in held] == [VBOX[0]]


# ── API ─────────────────────────────────────────────────────────────────────

def test_owner_accepts_a_package_until_a_review_date(client, fake_graph, as_user):
    as_user(role="owner", graph_tenant_id="acme", user_id="u-1")
    fake_graph.write.return_value = [{"package_name": VBOX[0], "package_version": VBOX[1],
                                      "review_by": "2027-04-22"}]
    resp = client.put("/api/v1/assets/a-1/risk-acceptances", json={
        "package_name": VBOX[0], "package_version": VBOX[1],
        "reason": "Hosts the Wazuh VM; upgrade after the next release", "review_months": 6})
    assert resp.status_code == 200, resp.text
    query, params = fake_graph.write.call_args[0]
    assert query == app_queries.SET_RISK_ACCEPTANCE
    assert params["review_by"] == add_months(date.today(), 6).isoformat()
    assert params["owner"] == "u-1" and params["asset_id"] == "a-1" and params["tenant_id"] == "acme"


def test_acceptances_need_a_reason_and_last_at_most_a_year(client, fake_graph, as_user):
    as_user(role="owner")
    base = {"package_name": VBOX[0], "package_version": VBOX[1], "reason": "ok reason"}
    assert client.put("/api/v1/assets/a-1/risk-acceptances", json={**base, "reason": ""}).status_code == 422
    assert client.put("/api/v1/assets/a-1/risk-acceptances", json={**base, "review_months": 13}).status_code == 422
    fake_graph.write.assert_not_called()


def test_members_cannot_accept_or_revoke(client, fake_graph, as_user):
    as_user(role="member")
    body = {"package_name": VBOX[0], "reason": "because"}
    assert client.put("/api/v1/assets/a-1/risk-acceptances", json=body).status_code == 403
    assert client.delete("/api/v1/assets/a-1/risk-acceptances",
                         params={"package_name": VBOX[0]}).status_code == 403
    fake_graph.write.assert_not_called()


def test_unknown_asset_is_a_404(client, fake_graph, as_user):
    as_user(role="admin")
    fake_graph.write.return_value = []
    resp = client.put("/api/v1/assets/nope/risk-acceptances", json={"package_name": "X", "reason": "because"})
    assert resp.status_code == 404


def test_revoke(client, fake_graph, as_user):
    as_user(role="admin")
    resp = client.delete("/api/v1/assets/a-1/risk-acceptances",
                         params={"package_name": VBOX[0], "package_version": VBOX[1]})
    assert resp.status_code == 200
    query, params = fake_graph.write.call_args[0]
    assert query == app_queries.DELETE_RISK_ACCEPTANCE
    assert (params["package_name"], params["package_version"]) == VBOX


def test_registry_hands_acceptances_in_date_to_the_adapter(fake_graph):
    from app.connectors.registry import CheckRegistry
    fake_graph.query.return_value = [{"asset_id": "a-1", "asset_name": "Simo",
                                      "package_name": VBOX[0], "package_version": VBOX[1],
                                      "review_by": "2027-04-22"}]

    class _Adapter:
        accepted_packages = {}
    adapter = _Adapter()
    CheckRegistry._attach_acceptances(adapter, "acme")
    assert package_key(*VBOX) in adapter.accepted_packages["simo"]
    assert fake_graph.query.call_args[0] == (app_queries.GET_ACTIVE_RISK_ACCEPTANCES, {"tenant_id": "acme"})


# ── Wazuh holds accepted findings back ──────────────────────────────────────

def _adapter(**cfg):
    a = WazuhAdapter(tenant_id="t", config=_wazuh_config_with_indexer(**cfg))
    a.accepted_packages = ACCEPTED
    return a


@responses.activate
def test_accepted_findings_are_not_ingested_and_are_listed_on_the_device():
    with _mock_private_dns():
        _register(INSTALLED | {VBOX})
        search = f"{INDEXER_URL}/wazuh-states-vulnerabilities-*/_search"
        responses.add(responses.POST, search, json={"aggregations": {"by_agent": {"buckets": [{
            "key": "001",
            "by_severity": {"buckets": [{"key": "High", "doc_count": 3}, {"key": "Critical", "doc_count": 1}]},
            "by_package": {"buckets": [
                {"key": VBOX[0], "by_version": {"buckets": [{"key": VBOX[1], "by_severity": {"buckets": [
                    {"key": "High", "doc_count": 1}]}}]}},
                {"key": SQL[0], "by_version": {"buckets": [{"key": SQL[1], "by_severity": {"buckets": [
                    {"key": "High", "doc_count": 2}, {"key": "Critical", "doc_count": 1}]}}]}},
            ]},
        }]}}})
        responses.add(responses.POST, search, json={"hits": {"total": {"value": 2}, "hits": [
            _with_pkg(_vuln_hit("001", "CVE-VBOX", severity="High"), *VBOX),
            _with_pkg(_vuln_hit("001", "CVE-SQL", severity="Critical"), *SQL)]}})
        result = _adapter(collect_inventory=False).run_check("wazuh_agent_connectivity")
    asset = result.discovered_assets[0]
    assert [v["cve_id"] for v in asset["vulnerabilities"]] == ["CVE-SQL"]
    profile = asset["profile"]
    assert profile["software"]["accepted_risk"] == ["Oracle VirtualBox 7.1.6: 1 finding, accepted until 22 Apr 2027"]
    assert profile["vulnerabilities"]["accepted_risk"] == 1
    assert profile["vulnerabilities"]["counts_by_severity"] == {"High": 2, "Critical": 1}


@responses.activate
def test_patching_score_leaves_out_accepted_findings():
    with _mock_private_dns():
        _register(INSTALLED | {VBOX})
        responses.add(responses.POST, f"{INDEXER_URL}/wazuh-states-vulnerabilities-*/_search", json={
            "aggregations": {"by_agent": {"buckets": [{
                "key": "001",
                "by_severity": {"buckets": [{"key": "High", "doc_count": 1}]},
                "by_package": {"buckets": [
                    {"key": VBOX[0], "by_version": {"buckets": [{"key": VBOX[1], "by_severity": {"buckets": [
                        {"key": "High", "doc_count": 1}]}}]}}]},
            }]}}})
        result = _adapter().run_check("wazuh_vulnerability_patching")
    assert result.detail.startswith("0 critical, 0 high, 0 medium and 0 low findings open across 1 scanned device")
    assert "1 finding in 1 accepted package not counted until their review date" in result.detail
    assert result.score == 1.0


@responses.activate
def test_without_acceptances_everything_counts():
    with _mock_private_dns():
        _register(INSTALLED | {VBOX})
        responses.add(responses.POST, f"{INDEXER_URL}/wazuh-states-vulnerabilities-*/_search", json={
            "aggregations": {"by_agent": {"buckets": [{
                "key": "001",
                "by_severity": {"buckets": [{"key": "High", "doc_count": 1}]},
                "by_package": {"buckets": [
                    {"key": VBOX[0], "by_version": {"buckets": [{"key": VBOX[1], "by_severity": {"buckets": [
                        {"key": "High", "doc_count": 1}]}}]}}]},
            }]}}})
        result = WazuhAdapter(tenant_id="t", config=_wazuh_config_with_indexer()).run_check(
            "wazuh_vulnerability_patching")
    assert result.detail.startswith("0 critical, 1 high")
    assert "accepted" not in result.detail


# ── Asset page ──────────────────────────────────────────────────────────────

def test_asset_page_drops_accepted_packages_from_actions_straight_away(client, fake_graph, as_user):
    as_user(role="owner")
    pkgs = [{"name": VBOX[0], "version": VBOX[1], "cve_ids": ["CVE-VBOX"], "cve_count": 1, "max_severity": "High"},
            {"name": SQL[0], "version": SQL[1], "cve_ids": ["CVE-SQL"], "cve_count": 1, "max_severity": "Critical"}]

    def _fake(query, params=None):
        if query == app_queries.GET_ASSET_DETAIL:
            return [{"asset": {"id": "a-1", "name": "Simo"}, "vulnerabilities": [], "risks": []}]
        if query == app_queries.GET_ASSET_PROFILE_SECTIONS:
            return [{"section": "software", "source": "wazuh", "data": '{"vulnerable_packages": %s}' %
                     __import__("json").dumps(pkgs), "updated_at": "2026-10-22"}]
        if query == app_queries.GET_RISK_ACCEPTANCES_FOR_ASSET:
            return [{"package_name": VBOX[0], "package_version": VBOX[1], "reason": "VM host",
                     "review_by": "2027-04-22", "active": True}]
        return []
    fake_graph.query.side_effect = _fake
    body = client.get("/api/v1/assets/a-1/profile").json()
    assert [p["name"] for p in body["fix_first"]] == [SQL[0]]
    assert body["risk_acceptances"][0]["package_name"] == VBOX[0]
    assert body["can_accept_risk"] is True
