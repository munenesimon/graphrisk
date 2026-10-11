"""
The shared connector rules (app/connectors/checks.py) and how each adapter
follows them: missing data is unknown, vulnerability load is graded and
measured as progress, only applicable items count, and busy APIs are
retried with sane waits.
"""
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from unittest.mock import MagicMock

import pytest
import requests
import responses

from app.connectors import checks
from app.connectors.adapters.crowdstrike import CrowdStrikeAdapter
from app.connectors.adapters.okta import OktaAdapter
from app.connectors.adapters.qualys import QualysAdapter
from app.connectors.models import CheckCategory, CheckResult, CheckStatus
from app.connectors.registry import CheckRegistry
from app.recommendations import recommend_for_asset


# ── Rule 1: missing data is unknown ──────────────────────────────────────────

def test_an_empty_population_has_no_score():
    assert checks.share_score(0, 0) is None
    assert checks.share_score(1, 4) == 0.75


def test_the_registry_leaves_control_health_alone_when_nothing_was_measured(monkeypatch, fake_graph):
    result = checks.no_data_result(
        check_id="x", check_name="X", category=CheckCategory.IAM, source="okta", tenant_id="t",
        control_title="Multi-Factor Authentication", reason="no users in the Okta org")
    assert result.status == CheckStatus.SKIPPED
    assert result.detail == "Nothing to measure yet: no users in the Okta org"
    progress_spy = MagicMock()
    monkeypatch.setattr(CheckRegistry, "_apply_progress", progress_spy)
    CheckRegistry()._write_to_graph(result)
    progress_spy.assert_not_called()
    assert fake_graph.write.call_count == 0


# ── Rule 2: graded vulnerability load ────────────────────────────────────────

def test_open_weight_grades_findings_by_severity():
    assert checks.open_weight({"Critical": 2, "High": 1, "Medium": 3, "Low": 4, "Unknown": 9}) == 28.0
    assert checks.open_weight({"CRITICAL": 1}) == 10.0
    assert checks.progress(28.0, 0) == {"open_weight": 28.0, "devices": 1}


def test_first_run_score_uses_the_per_device_floor():
    assert checks.first_run_score(10.0, 1) == 0.5      # baseline is the 20-point floor
    assert checks.first_run_score(100.0, 1) == 0.0     # worst seen so far
    assert checks.first_run_score(0.0, 3) == 1.0


def test_progress_baselines_are_kept_per_connector(fake_graph):
    from app.graph import queries
    fake_graph.write.side_effect = lambda q, p=None: []
    result = CheckResult(check_id="q", check_name="Q", category=CheckCategory.PATCH_MGMT, source="qualys",
                         tenant_id="t", status=CheckStatus.FAIL, score=0.0, detail="d",
                         control_title="Vulnerability & Patch Management",
                         raw_data={"progress": {"open_weight": 8.0, "devices": 1}})
    CheckRegistry()._apply_progress(result)
    calls = [c.args for c in fake_graph.write.call_args_list if c.args[0] == queries.RECORD_PROGRESS_PEAK]
    assert calls[0][1]["source"] == "qualys"


# ── Rule 4: retries with sane waits ──────────────────────────────────────────

def _response(status=200, headers=None):
    r = requests.Response()
    r.status_code = status
    r.headers.update(headers or {})
    return r


def test_backoff_reads_seconds_dates_and_epoch_resets():
    now = 1_800_000_000.0
    assert checks.backoff_seconds(_response(429, {"Retry-After": "5"}), 0, now=lambda: now) == 5.0
    when = datetime.fromtimestamp(now + 12, tz=timezone.utc)
    assert checks.backoff_seconds(_response(429, {"Retry-After": format_datetime(when, usegmt=True)}),
                                  0, now=lambda: now) == pytest.approx(12.0, abs=1)
    # Okta sends an epoch timestamp; the old adapter slept that many seconds.
    assert checks.backoff_seconds(_response(429, {"X-Rate-Limit-Reset": str(int(now + 7))}),
                                  0, now=lambda: now) == 7.0
    assert checks.backoff_seconds(_response(429, {"Retry-After": "99999"}), 0) == checks.MAX_BACKOFF_SECONDS
    assert checks.backoff_seconds(None, 2) == 4.0


def test_request_with_retry_rides_out_a_busy_server():
    session = MagicMock()
    session.request.side_effect = [_response(503), requests.Timeout("slow"), _response(200)]
    waits = []
    r = checks.request_with_retry(session, "GET", "https://example.com/x", sleep=waits.append)
    assert r.status_code == 200 and len(waits) == 2


def test_request_with_retry_gives_up_after_its_attempts():
    session = MagicMock()
    session.request.side_effect = requests.ConnectionError("down")
    with pytest.raises(requests.ConnectionError):
        checks.request_with_retry(session, "GET", "https://example.com/x", retries=2, sleep=lambda s: None)
    assert session.request.call_count == 2


# ── Qualys ───────────────────────────────────────────────────────────────────
QUALYS = "https://qualysapi.qualys.com"
EMPTY_HOSTS = ("<?xml version='1.0'?><HOST_LIST_OUTPUT><RESPONSE><HOST_LIST></HOST_LIST>"
               "</RESPONSE></HOST_LIST_OUTPUT>")


def _qualys():
    return QualysAdapter(tenant_id="t", config={"username": "u", "password": "p"})


@responses.activate
def test_qualys_with_no_hosts_reports_no_data_instead_of_a_perfect_score():
    responses.add(responses.GET, f"{QUALYS}/api/2.0/fo/asset/host/vm/detection/", body=EMPTY_HOSTS)
    responses.add(responses.GET, f"{QUALYS}/api/2.0/fo/asset/host/", body=EMPTY_HOSTS)
    for check in ("qualys_critical_vulnerabilities", "qualys_stale_scans"):
        result = _qualys().run_check(check)
        assert result.status == CheckStatus.SKIPPED
        assert "no hosts in the Qualys subscription" in result.detail


@responses.activate
def test_qualys_confirmed_findings_are_graded_and_reported_as_progress():
    responses.add(responses.GET, f"{QUALYS}/api/2.0/fo/asset/host/vm/detection/", body="""<?xml version='1.0'?>
<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST>
  <HOST><ID>1</ID><DNS>web-01</DNS><DETECTION_LIST>
    <DETECTION><SEVERITY>5</SEVERITY></DETECTION><DETECTION><SEVERITY>4</SEVERITY></DETECTION>
  </DETECTION_LIST></HOST>
  <HOST><ID>2</ID><DNS>db-01</DNS><DETECTION_LIST>
    <DETECTION><SEVERITY>4</SEVERITY></DETECTION>
  </DETECTION_LIST></HOST>
</HOST_LIST></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>""")
    result = _qualys().run_check("qualys_confirmed_high_severity")
    # 1 Critical (10) + 2 High (4 each) = 18 over 2 hosts (floor 40).
    assert result.raw_data["progress"] == {"open_weight": 18.0, "devices": 2}
    assert result.score == 0.55
    assert "(1 critical, 2 high) across 2 hosts" in result.detail


# ── CrowdStrike ──────────────────────────────────────────────────────────────
CS = "https://api.crowdstrike.com"


def _falcon(hosts=None, spotlight=None):
    responses.add(responses.POST, f"{CS}/oauth2/token", json={"access_token": "t", "expires_in": 1800}, status=201)
    if hosts is not None:
        responses.add(responses.GET, f"{CS}/devices/combined/devices/light/v1", json={"resources": hosts})
    if spotlight is not None:
        responses.add(responses.GET, f"{CS}/spotlight/combined/vulnerabilities/v1", json={"resources": spotlight})
    return CrowdStrikeAdapter(tenant_id="t", config={"client_id": "c", "client_secret": "s"})


@responses.activate
def test_crowdstrike_with_no_sensors_reports_no_data():
    adapter = _falcon(hosts=[])
    for check in ("crowdstrike_stale_sensors", "crowdstrike_rfm_hosts"):
        assert adapter.run_check(check).status == CheckStatus.SKIPPED


@responses.activate
def test_a_silent_falcon_sensor_no_longer_vouches_for_protection():
    recent = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    adapter = _falcon(hosts=[
        {"device_id": "a", "hostname": "OLD-LT", "last_seen": "2020-01-01T00:00:00Z"},
        {"device_id": "b", "hostname": "NEW-LT", "last_seen": recent},
    ])
    assets = {a["name"]: a for a in adapter.run_check("crowdstrike_stale_sensors").discovered_assets}
    assert assets["OLD-LT"]["profile"]["protection"]["status"] == "Not confirmed (sensor not reporting)"
    assert assets["NEW-LT"]["profile"]["protection"]["status"] == "Active"


def _finding(host, cve, severity):
    return {"host_info": {"hostname": host}, "cve": {"id": cve, "severity": severity}}


@responses.activate
def test_fixing_low_spotlight_findings_moves_the_score_the_right_way():
    # The old score was "critical share of all findings": fixing the Lows
    # and leaving the Critical made it WORSE. Graded load only ever falls.
    before = _falcon(spotlight=[_finding("H1", "CVE-1", "CRITICAL"), _finding("H1", "CVE-2", "LOW"),
                                _finding("H1", "CVE-3", "LOW")]).run_check("crowdstrike_critical_vulnerabilities")
    responses.reset()
    after = _falcon(spotlight=[_finding("H1", "CVE-1", "CRITICAL")]).run_check(
        "crowdstrike_critical_vulnerabilities")
    assert before.raw_data["progress"] == {"open_weight": 10.5, "devices": 1}
    assert after.raw_data["progress"] == {"open_weight": 10.0, "devices": 1}
    assert after.score > before.score


def test_reduced_functionality_mode_gets_a_recommended_action():
    profile = {"protection": {"fields": {"status": "Reduced functionality mode", "product": "CrowdStrike Falcon"},
                              "sources": [{"name": "CrowdStrike Falcon"}]}}
    actions = recommend_for_asset(profile, [], [])
    assert actions[0]["title"] == "Restore full protection in CrowdStrike Falcon"
    assert actions[0]["priority"] == "high"


# ── Okta ─────────────────────────────────────────────────────────────────────
OKTA = "https://fake-org.okta.com"


@responses.activate
def test_okta_counts_only_devices_that_report_encryption():
    responses.add(responses.GET, f"{OKTA}/api/v1/devices", json=[
        {"id": "d1", "status": "ACTIVE", "profile": {"displayName": "A", "diskEncryptionType": "FULL"}},
        {"id": "d2", "status": "ACTIVE", "profile": {"displayName": "B", "diskEncryptionType": "NONE"}},
        {"id": "d3", "status": "ACTIVE", "profile": {"displayName": "C"}},      # doesn't say
    ])
    result = OktaAdapter(tenant_id="t", config={"org_url": OKTA, "api_token": "x"}).run_check(
        "okta_device_assurance")
    assert (result.affected_count, result.total_count, result.score) == (1, 2, 0.5)
    assert "1 active device doesn't report encryption (not counted)" in result.detail
    assert len(result.discovered_assets) == 3


@responses.activate
def test_okta_with_no_users_reports_no_data_instead_of_zero():
    responses.add(responses.GET, f"{OKTA}/api/v1/users", json=[])
    result = OktaAdapter(tenant_id="t", config={"org_url": OKTA, "api_token": "x"}).run_check(
        "okta_mfa_enrollment")
    assert result.status == CheckStatus.SKIPPED
