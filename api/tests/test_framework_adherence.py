"""
Framework adherence: obligations vs other frameworks, "not met" vs "not
evidenced", and self-declared attestations.
"""
from app.graph import queries as app_queries


def _framework(fid, name, applies, **counts):
    row = {"framework_id": fid, "framework": name, "version": "1", "category": "regulation",
           "applies": applies, "total": 0, "not_applicable": 0, "met": 0, "partial": 0, "gap": 0,
           "attested": 0, "no_evidence": 0, "score_sum": 0.0}
    row.update(counts)
    return row


def test_frameworks_split_into_obligations_and_others(client, fake_graph, as_user):
    as_user(graph_tenant_id="acme")
    fake_graph.query.return_value = [
        _framework("KE_DPA_2019", "KENYA_DPA", True, total=27, met=1, attested=2, no_evidence=24, score_sum=3.0),
        _framework("CBK_CYBER_BANKS_2017", "CBK_CYBER_BANKS", False, total=19, met=1, no_evidence=18, score_sum=1.0),
    ]
    body = client.get("/api/v1/frameworks/adherence").json()
    assert body["has_profile"] is True
    assert [f["framework"] for f in body["obligations"]] == ["KENYA_DPA"]
    assert [f["framework"] for f in body["other"]] == ["CBK_CYBER_BANKS"]
    dpa = body["obligations"][0]
    assert dpa["evidenced"] == 3 and dpa["no_evidence"] == 24
    assert dpa["adherence_pct"] == round(3 / 27 * 100, 1)
    assert dpa["evidence_pct"] == round(3 / 27 * 100, 1)
    assert dpa["met_of_evidenced_pct"] == 100.0
    assert fake_graph.query.call_args[0][1] == {"tenant_id": "acme"}


def test_not_applicable_requirements_leave_the_totals(client, fake_graph, as_user):
    as_user()
    fake_graph.query.return_value = [
        _framework("X", "X", True, total=10, not_applicable=4, partial=2, no_evidence=4, score_sum=1.0)]
    f = client.get("/api/v1/frameworks/adherence").json()["obligations"][0]
    assert f["applicable"] == 6 and f["evidenced"] == 2
    assert f["adherence_pct"] == round(1.0 / 6 * 100, 1)
    assert f["met_of_evidenced_pct"] == 50.0


def test_nothing_evidenced_has_no_met_percentage(client, fake_graph, as_user):
    as_user()
    fake_graph.query.return_value = [_framework("X", "X", False, total=5, no_evidence=5)]
    f = client.get("/api/v1/frameworks/adherence").json()["other"][0]
    assert f["met_of_evidenced_pct"] is None and f["adherence_pct"] == 0.0


def _req(rid, status, score=0.0, controls=(), attestation=None):
    return {"framework": "KENYA_DPA", "applies": True, "id": rid, "control_reference": rid,
            "title": rid, "domain": None, "summary": None, "official_url": None,
            "requirement_type": None, "controls": list(controls), "status": status, "score": score,
            "attestation": attestation}


def test_requirements_show_their_evidence_and_status(client, fake_graph, as_user):
    as_user(role="owner")
    fake_graph.query.return_value = [
        _req("R1", "met", 1.0, [{"title": "Endpoint Detection & Response", "health": 1.0, "via": "direct"}]),
        _req("R2", "attested", 1.0, attestation={"status": "in_place", "note": "Policy v2"}),
        _req("R3", "no_evidence"),
        _req("R4", "not_applicable", attestation={"status": "not_applicable"}),
    ]
    body = client.get("/api/v1/frameworks/KE_DPA_2019/requirements").json()
    assert (body["met"], body["attested"], body["no_evidence"], body["not_applicable"]) == (1, 1, 1, 1)
    assert body["applicable"] == 3 and body["adherence_pct"] == round(2 / 3 * 100, 1)
    assert body["can_attest"] is True
    assert body["requirements"][1]["attestation"]["note"] == "Policy v2"
    assert "framework" not in body["requirements"][0]


def test_requirements_404_for_an_unknown_framework(client, fake_graph, as_user):
    as_user()
    fake_graph.query.return_value = []
    assert client.get("/api/v1/frameworks/nope/requirements").status_code == 404


def test_owner_can_record_an_attestation(client, fake_graph, as_user):
    as_user(role="owner", graph_tenant_id="acme", user_id="u-9")
    fake_graph.write.return_value = [{"status": "in_place"}]
    resp = client.put("/api/v1/frameworks/KE_DPA_2019/attestation", json={
        "requirement_id": "KE_DPA_2019:S41", "status": "in_place",
        "note": "  Data protection policy approved by the board  ",
        "evidence_url": "https://intranet.example.com/policies/dp.pdf"})
    assert resp.status_code == 200, resp.text
    query, params = fake_graph.write.call_args[0]
    assert query == app_queries.SET_ATTESTATION
    assert params == {"tenant_id": "acme", "framework_id": "KE_DPA_2019", "requirement_id": "KE_DPA_2019:S41",
                      "status": "in_place", "note": "Data protection policy approved by the board",
                      "evidence_url": "https://intranet.example.com/policies/dp.pdf", "attested_by": "u-9"}


def test_members_cannot_attest(client, fake_graph, as_user):
    as_user(role="member")
    resp = client.put("/api/v1/frameworks/X/attestation", json={"requirement_id": "R1", "status": "in_place"})
    assert resp.status_code == 403
    assert fake_graph.write.call_count == 0


def test_attestation_rejects_bad_input(client, fake_graph, as_user):
    as_user(role="owner")
    for body in ({"requirement_id": "R1", "status": "done"},
                 {"requirement_id": "R1", "status": "in_place", "evidence_url": "javascript:alert(1)"}):
        assert client.put("/api/v1/frameworks/X/attestation", json=body).status_code == 422


def test_attesting_a_requirement_outside_the_framework_404s(client, fake_graph, as_user):
    as_user(role="admin")
    fake_graph.write.return_value = []
    resp = client.put("/api/v1/frameworks/X/attestation", json={"requirement_id": "OTHER:R1", "status": "in_place"})
    assert resp.status_code == 404


def test_owner_can_remove_an_attestation(client, fake_graph, as_user):
    as_user(role="owner", graph_tenant_id="acme")
    resp = client.delete("/api/v1/frameworks/X/attestation", params={"requirement_id": "R1"})
    assert resp.status_code == 200
    assert fake_graph.write.call_args[0] == (app_queries.DELETE_ATTESTATION,
                                             {"tenant_id": "acme", "requirement_id": "R1"})


def test_requirement_references_sort_naturally():
    from app.api.v1.frameworks import requirement_sort_key
    iso = ["A.5.10", "10.1", "A.5.9", "4.1", "9.3", "A.8.1"]
    assert sorted(iso, key=requirement_sort_key) == ["4.1", "9.3", "10.1", "A.5.9", "A.5.10", "A.8.1"]
    soc2 = ["P1.1", "A1.1", "CC10.1", "PI1.1", "CC2.1", "C1.1", "CC1.1"]
    assert sorted(soc2, key=requirement_sort_key) == ["CC1.1", "CC2.1", "CC10.1", "A1.1", "C1.1", "PI1.1", "P1.1"]


def test_requirements_are_returned_in_reading_order(client, fake_graph, as_user):
    as_user(graph_tenant_id="acme")
    def req(ref):
        return {"framework": "ISO_27001", "applies": False, "id": ref, "control_reference": ref,
                "title": ref, "domain": None, "summary": None, "official_url": None,
                "requirement_type": "process", "controls": [], "status": "no_evidence",
                "score": 0.0, "attestation": None}
    fake_graph.query.return_value = [req("10.1"), req("A.5.1"), req("4.1")]
    resp = client.get("/api/v1/frameworks/ISO_27001_2022/requirements")
    assert resp.status_code == 200
    assert [r["control_reference"] for r in resp.json()["requirements"]] == ["4.1", "10.1", "A.5.1"]
