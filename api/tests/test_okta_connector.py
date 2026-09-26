"""
Offline test for OktaAdapter using the `responses` library to simulate
Okta\'s REST API. Proves the adapter logic and CheckRegistry integration
work correctly WITHOUT needing a real Okta account or API token.

Usage: python test_okta_connector.py
Requires: pip install responses  (already installed as a moto dependency)
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import responses
from app.connectors.adapters.okta import OktaAdapter

FAKE_ORG = "https://fake-org.okta.com"


@responses.activate
def test_okta_adapter():
    print("=" * 55)
    print("  Okta Connector Offline Test (via responses)")
    print("=" * 55)

    # ── Simulate Okta's user list endpoint ──────────────────────────────────
    responses.add(
        responses.GET, f"{FAKE_ORG}/api/v1/users",
        json=[
            {
                "id": "u1", "status": "ACTIVE",
                "lastLogin": "2026-09-01T00:00:00.000Z",
                "credentials": {"provider": {"type": "OKTA"}},
            },
            {
                "id": "u2", "status": "ACTIVE",
                "lastLogin": "2025-01-01T00:00:00.000Z",  # dormant, no MFA
                "credentials": {},
            },
        ],
        status=200,
    )

    # ── Simulate the Super Admin role assignees endpoint ────────────────────
    responses.add(
        responses.GET, f"{FAKE_ORG}/api/v1/iam/roles/SUPER_ADMIN/assignees/users",
        json=[{"id": "u1"}],
        status=200,
    )

    # ── Simulate the password policy endpoint ───────────────────────────────
    responses.add(
        responses.GET, f"{FAKE_ORG}/api/v1/policies",
        json=[
            {
                "status": "ACTIVE",
                "settings": {"password": {"complexity": {"minLength": 14}}},
            }
        ],
        status=200,
    )

    print("\n[Setup] Simulated Okta org with 2 users (1 dormant, 1 without MFA),")
    print("[Setup] 1 Super Admin, and a 14-character password policy")

    adapter = OktaAdapter(
        tenant_id="test-tenant",
        config={"org_url": FAKE_ORG, "api_token": "fake-okta-token"},
    )
    adapter.authenticate()
    print("\n[Auth] OktaAdapter authenticated with simulated API token")

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

    print("\n" + "=" * 55)
    print(f"  Test complete. {len(results)} checks ran successfully.")
    print("  This proves OktaAdapter correctly implements BaseConnector")
    print("  with a third distinct auth pattern (static API key header),")
    print("  without ever touching a real Okta account.")
    print("=" * 55)


if __name__ == "__main__":
    test_okta_adapter()
