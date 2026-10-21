"""
Sector-specific frameworks (CBK banks/PSPs, CMCA CII, PCI DSS) stay hidden
until the organisation switches them on in its regulatory profile -- see
app/sector_frameworks.py.
"""
from app.graph import queries as app_queries


def _fw(fid, name, applies, category="regulation"):
    return {"framework_id": fid, "framework": name, "version": "1", "category": category,
            "applies": applies, "total": 10, "not_applicable": 0, "met": 0, "partial": 0, "gap": 0,
            "attested": 0, "no_evidence": 10, "score_sum": 0.0}


# ── Frameworks page ─────────────────────────────────────────────────────────

def test_switched_off_sector_frameworks_are_not_shown_even_for_reference(client, fake_graph, as_user):
    as_user()
    fake_graph.query.return_value = [
        _fw("KE_DPA_2019", "KENYA_DPA", False),
        _fw("CBK_CYBER_BANKS_2017", "CBK_CYBER_BANKS", False),
        _fw("PCI_DSS_4", "PCI_DSS", False, category="standard"),
        _fw("NIST_CSF_2", "NIST_CSF", False, category="standard"),
    ]
    body = client.get("/api/v1/frameworks/adherence").json()
    assert [f["framework"] for f in body["other"]] == ["KENYA_DPA", "NIST_CSF"]
    assert body["obligations"] == []
    hidden = {h["framework"]: h for h in body["hidden_sector_frameworks"]}
    assert set(hidden) == {"CBK_CYBER_BANKS", "PCI_DSS"}
    assert hidden["CBK_CYBER_BANKS"]["sector"] == "Banking"
    assert hidden["PCI_DSS"]["applies_to"]


def test_a_switched_on_sector_framework_is_an_obligation(client, fake_graph, as_user):
    as_user()
    fake_graph.query.return_value = [_fw("CBK_CYBER_BANKS_2017", "CBK_CYBER_BANKS", True)]
    body = client.get("/api/v1/frameworks/adherence").json()
    assert [f["framework"] for f in body["obligations"]] == ["CBK_CYBER_BANKS"]
    assert body["has_profile"] is True and body["hidden_sector_frameworks"] == []


def test_only_hidden_sector_frameworks_do_not_count_as_a_profile(client, fake_graph, as_user):
    as_user()
    fake_graph.query.return_value = [_fw("CBK_CYBER_PSP_2019", "CBK_CYBER_PSP", False)]
    body = client.get("/api/v1/frameworks/adherence").json()
    assert body["has_profile"] is False and body["other"] == []


def test_framework_list_marks_the_sector_each_one_is_limited_to(client, fake_graph, as_user):
    as_user()
    fake_graph.query.return_value = [
        {"id": "CBK_CYBER_BANKS_2017", "name": "CBK_CYBER_BANKS", "version": "2017"},
        {"id": "KE_DPA_2019", "name": "KENYA_DPA", "version": "2019"},
    ]
    rows = {f["name"]: f for f in client.get("/api/v1/frameworks/").json()["frameworks"]}
    assert rows["CBK_CYBER_BANKS"]["sector"]["sector"] == "Banking"
    assert rows["KENYA_DPA"]["sector"] is None


# ── Blast radius ────────────────────────────────────────────────────────────

CONTROL_ROW = {
    "control_title": "Endpoint Detection & Response", "control_status": "Implemented",
    "effectiveness_score": 1.0, "exposed_risks": [], "affected_assets": [], "affected_asset_ids": [],
    "impacted_processes": [],
    "frameworks": [
        {"id": "NIST_CSF_2", "name": "NIST_CSF", "category": "standard", "in_profile": False},
        {"id": "PCI_DSS_4", "name": "PCI_DSS", "category": "standard", "in_profile": False},
        {"id": "KE_DPA_2019", "name": "KENYA_DPA", "category": "regulation", "in_profile": False},
        {"id": "CBK_CYBER_BANKS_2017", "name": "CBK_CYBER_BANKS", "category": "regulation", "in_profile": False},
    ],
    "framework_controls": ["DE.CM-01", "11.5.1"],
    "mapped_framework_controls": ["KENYA_DPA DPR-DETECTION", "CBK_CYBER_BANKS B-3.1c.vii"],
    "risk_count": 0, "asset_count": 0,
}


def _blast(client, fake_graph, as_user, row, scope="all"):
    as_user(graph_tenant_id="acme")

    def _fake(query, params=None):
        if query == app_queries.BLAST_RADIUS_CONTROL:
            return [row]
        if query == app_queries.BLAST_RADIUS_DIRECT_REFS:
            return [{"framework": "NIST_CSF", "reference": "DE.CM-01"},
                    {"framework": "PCI_DSS", "reference": "11.5.1"}]
        return []
    fake_graph.query.side_effect = _fake
    resp = client.get(f"/api/v1/graph/blast-radius/control/ctrl-1?scope={scope}")
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_blast_radius_leaves_out_switched_off_sector_frameworks_under_all(client, fake_graph, as_user):
    body = _blast(client, fake_graph, as_user, CONTROL_ROW, scope="all")
    br = body["blast_radius"]
    assert br["frameworks"] == {"standards": ["NIST_CSF"], "your_regulations": [],
                                "other_regulations": ["KENYA_DPA"]}
    assert br["compliance_gaps"] == ["NIST_CSF", "KENYA_DPA"]
    assert br["mapped_framework_controls"] == ["KENYA_DPA DPR-DETECTION"]
    assert br["framework_controls"] == ["DE.CM-01"]
    assert {h["framework"] for h in body["hidden_sector_frameworks"]} == {"PCI_DSS", "CBK_CYBER_BANKS"}
    assert body["summary"]["framework_count"] == 2


def test_blast_radius_shows_a_sector_framework_once_switched_on(client, fake_graph, as_user):
    row = dict(CONTROL_ROW, frameworks=[
        dict(f, in_profile=True) if f["name"] == "CBK_CYBER_BANKS" else f for f in CONTROL_ROW["frameworks"]])
    br = _blast(client, fake_graph, as_user, row, scope="applicable")["blast_radius"]
    assert br["frameworks"]["your_regulations"] == ["CBK_CYBER_BANKS"]
    assert "CBK_CYBER_BANKS B-3.1c.vii" in br["mapped_framework_controls"]


def test_nothing_hidden_skips_the_reference_lookup(client, fake_graph, as_user):
    row = dict(CONTROL_ROW, frameworks=CONTROL_ROW["frameworks"][:1], mapped_framework_controls=[])
    body = _blast(client, fake_graph, as_user, row)
    assert body["blast_radius"]["framework_controls"] == ["DE.CM-01", "11.5.1"]
    assert body["hidden_sector_frameworks"] == []
    called = [c[0][0] for c in fake_graph.query.call_args_list]
    assert app_queries.BLAST_RADIUS_DIRECT_REFS not in called


# ── Dashboard coverage ──────────────────────────────────────────────────────

def test_coverage_leaves_out_switched_off_sector_frameworks(client, fake_graph, as_user):
    as_user()

    def _fake(query, params=None):
        if query == app_queries.FRAMEWORK_COVERAGE_ALL:
            return [{"framework": "NIST_CSF"}, {"framework": "PCI_DSS"}, {"framework": "CBK_CYBER_PSP"}]
        if query == app_queries.GET_REGULATORY_PROFILE:
            return [{"qualifiers": [], "frameworks": [{"id": "PCI_DSS_4", "name": "PCI_DSS"}]}]
        return []
    fake_graph.query.side_effect = _fake
    rows = client.get("/api/v1/dashboard/framework-coverage").json()["frameworks"]
    assert [r["framework"] for r in rows] == ["NIST_CSF", "PCI_DSS"]
