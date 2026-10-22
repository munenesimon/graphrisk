"""
Self-declared attestations have a review date: 12 months by default, at
most 36. Past it they show as "expired" and stop counting as evidence --
see _ATTESTATION_REVIEW_BY in app/graph/queries.py.
"""
from datetime import date

import pytest

from app.api.v1.frameworks import add_months


def _put(client, **body):
    return client.put("/api/v1/frameworks/X/attestation", json={"requirement_id": "R1", **body})


def test_a_chosen_review_date_is_stored(client, fake_graph, as_user):
    as_user(role="owner")
    fake_graph.write.return_value = [{"status": "in_place"}]
    when = add_months(date.today(), 6).isoformat()
    resp = _put(client, status="in_place", review_by=when)
    assert resp.status_code == 200, resp.text
    assert fake_graph.write.call_args[0][1]["review_by"] == when


@pytest.mark.parametrize("months", [0, -1, 37])
def test_review_date_must_be_in_the_future_and_within_three_years(client, fake_graph, as_user, months):
    as_user(role="owner")
    fake_graph.write.return_value = [{"status": "in_place"}]
    when = add_months(date.today(), months).isoformat()
    assert _put(client, status="in_place", review_by=when).status_code == 400
    fake_graph.write.assert_not_called()


def test_not_applicable_has_no_review_date(client, fake_graph, as_user):
    as_user(role="owner")
    fake_graph.write.return_value = [{"status": "not_applicable"}]
    resp = _put(client, status="not_applicable", review_by=add_months(date.today(), 6).isoformat())
    assert resp.status_code == 200
    assert fake_graph.write.call_args[0][1]["review_by"] is None and resp.json()["review_by"] is None


def test_expired_attestations_count_as_neither_evidence_nor_met(client, fake_graph, as_user):
    as_user()
    fake_graph.query.return_value = [{
        "framework_id": "KE_DPA_2019", "framework": "KENYA_DPA", "version": "1", "category": "regulation",
        "applies": True, "total": 10, "not_applicable": 0, "met": 1, "partial": 0, "gap": 0,
        "attested": 2, "no_evidence": 5, "expired": 2, "score_sum": 3.0}]
    f = client.get("/api/v1/frameworks/adherence").json()["obligations"][0]
    assert f["expired"] == 2
    assert f["evidenced"] == 3
    assert f["adherence_pct"] == 30.0


@pytest.mark.parametrize("start,months,expected", [
    (date(2026, 1, 31), 1, date(2026, 2, 28)),
    (date(2027, 10, 22), 12, date(2028, 10, 22)),
    (date(2028, 2, 29), 12, date(2029, 2, 28)),
    (date(2026, 11, 15), 3, date(2027, 2, 15)),
])
def test_add_months_keeps_the_day_or_uses_the_months_last(start, months, expected):
    assert add_months(start, months) == expected


def test_review_in_a_number_of_months(client, fake_graph, as_user):
    as_user(role="owner")
    fake_graph.write.return_value = [{"status": "in_place"}]
    resp = _put(client, status="in_place", review_months=24)
    assert resp.status_code == 200, resp.text
    assert resp.json()["review_by"] == add_months(date.today(), 24).isoformat()
    assert _put(client, status="in_place", review_months=48).status_code == 422
