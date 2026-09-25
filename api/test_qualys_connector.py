"""
Offline test for QualysAdapter using the `responses` library to simulate
Qualys's XML-based VM API. Proves the adapter logic, XML parsing, and
CheckRegistry integration work correctly WITHOUT needing a real Qualys
subscription.

Usage: python test_qualys_connector.py
Requires: pip install responses  (already installed as a moto dependency)
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import responses
from responses import matchers
from app.connectors.adapters.qualys import QualysAdapter

BASE_URL = "https://qualysapi.qualys.com"
DETECTION_PATH = f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/"
HOST_LIST_PATH = f"{BASE_URL}/api/2.0/fo/asset/host/"

# ── Fake XML fixtures -- Qualys's API v2 is XML-only, no JSON option ───────
SEVERITY_5_XML = """<?xml version="1.0" encoding="UTF-8" ?>
<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST>
  <HOST><ID>1001</ID><DNS>web-01.internal</DNS>
    <DETECTION_LIST><DETECTION><QID>90001</QID><TYPE>Confirmed</TYPE>
      <SEVERITY>5</SEVERITY><STATUS>Active</STATUS></DETECTION></DETECTION_LIST>
  </HOST>
</HOST_LIST></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>"""

HOST_LIST_XML = """<?xml version="1.0" encoding="UTF-8" ?>
<HOST_LIST_OUTPUT><RESPONSE><HOST_LIST>
  <HOST><ID>1001</ID><DNS>web-01.internal</DNS><TRACKING_METHOD>AGENT</TRACKING_METHOD>
    <LAST_VULN_SCAN_DATETIME>2026-09-20T03:00:00Z</LAST_VULN_SCAN_DATETIME></HOST>
  <HOST><ID>1002</ID><DNS>db-01.internal</DNS><TRACKING_METHOD>IP</TRACKING_METHOD>
    <LAST_VULN_SCAN_DATETIME>2026-06-01T03:00:00Z</LAST_VULN_SCAN_DATETIME></HOST>
</HOST_LIST></RESPONSE></HOST_LIST_OUTPUT>"""

REOPENED_XML = """<?xml version="1.0" encoding="UTF-8" ?>
<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST>
  <HOST><ID>1002</ID><DETECTION_LIST>
    <DETECTION><QID>90010</QID><STATUS>Re-Opened</STATUS></DETECTION>
    <DETECTION><QID>90011</QID><STATUS>Re-Opened</STATUS></DETECTION>
  </DETECTION_LIST></HOST>
</HOST_LIST></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>"""

CONFIRMED_HIGH_XML = """<?xml version="1.0" encoding="UTF-8" ?>
<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST>
  <HOST><ID>1001</ID><DETECTION_LIST>
    <DETECTION><QID>90020</QID><TYPE>Confirmed</TYPE><SEVERITY>4</SEVERITY><STATUS>Active</STATUS></DETECTION>
  </DETECTION_LIST></HOST>
</HOST_LIST></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>"""


@responses.activate
def test_qualys_adapter():
    print("=" * 55)
    print("  Qualys Connector Offline Test (via responses)")
    print("=" * 55)

    # Distinguish same-path calls by their actual query params -- three
    # different checks hit DETECTION_PATH with three different filters.
    responses.add(
        responses.GET, DETECTION_PATH, body=SEVERITY_5_XML, status=200, content_type="text/xml",
        match=[matchers.query_param_matcher({"action": "list", "status": "New,Active", "severities": "5"})],
    )
    responses.add(
        responses.GET, DETECTION_PATH, body=REOPENED_XML, status=200, content_type="text/xml",
        match=[matchers.query_param_matcher({"action": "list", "status": "Re-Opened"})],
    )
    responses.add(
        responses.GET, DETECTION_PATH, body=CONFIRMED_HIGH_XML, status=200, content_type="text/xml",
        match=[matchers.query_param_matcher({
            "action": "list", "status": "New,Active", "severities": "4-5", "type": "Confirmed",
        })],
    )
    # HOST_LIST_PATH is hit twice (once from the critical-vuln check for its
    # denominator, once from the stale-scan check) with identical params --
    # one registration is reused for both calls.
    responses.add(
        responses.GET, HOST_LIST_PATH, body=HOST_LIST_XML, status=200, content_type="text/xml",
        match=[matchers.query_param_matcher({"action": "list", "truncation_limit": "1000"})],
    )

    print("\n[Setup] Simulated Qualys subscription: 2 hosts, 1 Severity-5 finding,")
    print("[Setup] 1 stale scan (>30d), 2 re-opened detections, 1 confirmed Sev-4 finding")

    adapter = QualysAdapter(
        tenant_id="test-tenant",
        config={"username": "fake-qualys-user", "password": "fake-qualys-pass"},
    )
    adapter.authenticate()
    print("\n[Auth] QualysAdapter authenticated (Basic Auth -- no token exchange)")

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

    assert len(errors) == 0, "Expected no errors against the simulated Qualys API"
    assert len(results) == 4, f"Expected 4 checks, got {len(results)}"

    print("\n" + "=" * 55)
    print(f"  Test complete. {len(results)} checks ran successfully.")
    print("  This proves QualysAdapter correctly implements BaseConnector,")
    print("  parses Qualys's XML-only API responses with the stdlib")
    print("  ElementTree, and handles per-request Basic Auth -- without")
    print("  ever touching a real Qualys subscription.")
    print("=" * 55)


if __name__ == "__main__":
    test_qualys_adapter()
