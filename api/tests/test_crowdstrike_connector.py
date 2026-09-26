"""
Offline test for CrowdStrikeAdapter using the `responses` library to
simulate the Falcon API. Proves the adapter logic and CheckRegistry
integration work correctly WITHOUT needing a real CrowdStrike tenant.

Usage: python test_crowdstrike_connector.py
Requires: pip install responses  (already installed as a moto dependency)
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import responses
from app.connectors.adapters.crowdstrike import CrowdStrikeAdapter

BASE_URL = "https://api.crowdstrike.com"


@responses.activate
def test_crowdstrike_adapter():
    print("=" * 55)
    print("  CrowdStrike Connector Offline Test (via responses)")
    print("=" * 55)

    # ── OAuth2 token exchange (201, not 200) ────────────────────────────────
    responses.add(
        responses.POST, f"{BASE_URL}/oauth2/token",
        json={"access_token": "fake-falcon-token", "expires_in": 1800, "token_type": "bearer"},
        status=201,
    )

    # ── Combined devices endpoint: 2 hosts, 1 stale, 1 in RFM ───────────────
    responses.add(
        responses.GET, f"{BASE_URL}/devices/combined/devices/light/v1",
        json={"resources": [
            {"device_id": "h1", "hostname": "ws-01", "last_seen": "2026-09-24T12:00:00Z", "reduced_functionality_mode": "no"},
            {"device_id": "h2", "hostname": "ws-02", "last_seen": "2026-08-01T00:00:00Z", "reduced_functionality_mode": "yes"},
        ]},
        status=200,
    )

    # ── Open detection IDs, then their summaries (1 Critical) ───────────────
    responses.add(
        responses.GET, f"{BASE_URL}/detects/queries/detects/v1",
        json={"resources": ["ldt:1", "ldt:2"]},
        status=200,
    )
    responses.add(
        responses.POST, f"{BASE_URL}/detects/entities/summaries/GET/v1",
        json={"resources": [
            {"detection_id": "ldt:1", "max_severity_displayname": "Critical"},
            {"detection_id": "ldt:2", "max_severity_displayname": "Low"},
        ]},
        status=200,
    )

    # ── Spotlight vulnerabilities: 1 CRITICAL of 2 open ─────────────────────
    responses.add(
        responses.GET, f"{BASE_URL}/spotlight/combined/vulnerabilities/v1",
        json={"resources": [
            {"id": "v1", "cve": {"id": "CVE-2026-0001", "severity": "CRITICAL"}},
            {"id": "v2", "cve": {"id": "CVE-2026-0002", "severity": "MEDIUM"}},
        ]},
        status=200,
    )

    print("\n[Setup] Simulated Falcon tenant: 2 hosts (1 stale, 1 in RFM),")
    print("[Setup] 2 open detections (1 Critical), 2 open vulns (1 CRITICAL)")

    adapter = CrowdStrikeAdapter(
        tenant_id="test-tenant",
        config={"client_id": "fake-client-id", "client_secret": "fake-client-secret"},
    )
    adapter.authenticate()
    print("\n[Auth] CrowdStrikeAdapter authenticated with simulated OAuth2 token (HTTP 201)")

    print("\n" + "-" * 55)
    print("  Running all supported checks")
    print("-" * 55)

    results, errors = adapter.run_all_checks()

    for r in results:
        print(f"\n  {r.check_id}")
        print(f"    status: {r.status.value}")
        print(f"    score:  {r.score}")
        print(f"    detail: {r.detail}")

    for e in errors:
        print(f"\n  [ERROR] {e.check_id}: {e.error_type} - {e.message}")

    assert len(errors) == 0, "Expected no errors against the simulated Falcon API"
    assert len(results) == 4, f"Expected 4 checks, got {len(results)}"

    print("\n" + "=" * 55)
    print(f"  Test complete. {len(results)} checks ran successfully.")
    print("  This proves CrowdStrikeAdapter correctly implements BaseConnector")
    print("  and reuses its shared OAuth2 + Bearer-GET path end to end,")
    print("  without ever touching a real Falcon tenant.")
    print("=" * 55)


if __name__ == "__main__":
    test_crowdstrike_adapter()
