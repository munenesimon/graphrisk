"""
Layer 2: Qualys VM adapter.

Qualys's VM (Vulnerability Management) API v2 authenticates with plain
HTTP Basic Auth sent on every request -- there's no token exchange, same
as OktaAdapter's static-key pattern, so authenticate() just calls
_set_token() once with a long expiry purely to satisfy BaseConnector's
freshness check. Every request also has to carry an X-Requested-With
header (Qualys's documented CSRF mitigation for API v2 -- requests
missing it are rejected) and Basic credentials, neither of which
BaseConnector._get() sends, so -- like Okta and Wazuh before it -- this
adapter makes its own HTTP calls rather than reusing the shared helper.

Unlike every other adapter here, Qualys's API v2 endpoints are XML-only:
the Host List Detection API's documented output_format values are XML,
CSV, CSV_NO_METADATA and CSV_MS_EXCEL -- there is no JSON option, unlike
most modern REST APIs. Rather than adding a new dependency for this one
adapter, responses are parsed with Python's built-in xml.etree.ElementTree.

Qualys customers are provisioned onto one of several regional "Platform"
API gateways (Platform 1: qualysapi.qualys.com, Platform 2: qg2, Platform
3: qg3, and so on) -- config["base_url"] lets a tenant point at their own
platform instead of hardcoding Platform 1 as the default.

Structurally complete against the documented Host List and Host List
Detection APIs (the VM module's core asset/vulnerability surface) -- not
yet run against a live Qualys subscription. Same status as WazuhAdapter
and CrowdStrikeAdapter: correct against the published API shape, pending
real-credential validation. Deliberately does not touch the Policy
Compliance (PC) module or scan-authentication status -- both would need
API surface this adapter hasn't verified field-by-field against Qualys's
docs, and guessing at an XML shape that would silently return nothing (or
parse incorrectly) against a real subscription is worse than leaving it
out, the same call WazuhAdapter's docstring makes about the vulnerability
indexer.

control_title values are a best guess at what this tenant's Control nodes
are actually titled -- see WazuhAdapter's docstring for why a mismatch
fails silently at the graph-write step. Override via
config["control_titles"] = {"qualys_critical_vulnerabilities": "...", ...}
if your graph uses different names.
"""
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

from ..base import BaseConnector
from ..models import CheckResult, CheckStatus, CheckCategory

SUPPORTED_CHECKS = [
    "qualys_critical_vulnerabilities",
    "qualys_stale_scans",
    "qualys_reopened_vulnerabilities",
    "qualys_confirmed_high_severity",
]

DEFAULT_CONTROL_TITLES = {
    "qualys_critical_vulnerabilities": "Vulnerability & Patch Management",
    "qualys_stale_scans":              "Vulnerability Scanning Coverage",
    "qualys_reopened_vulnerabilities": "Vulnerability & Patch Management",
    "qualys_confirmed_high_severity":  "Vulnerability & Patch Management",
}

DEFAULT_BASE_URL = "https://qualysapi.qualys.com"

# Host List Detection defaults to 1,000 records/page; a subscription with
# a larger fleet would need this adapter to follow the response's
# WARNING/URL "next page" pointer -- left as a known scaling limit rather
# than guessed at, same spirit as Wazuh's MAX_AGENTS_PER_SCA_SWEEP cap.
TRUNCATION_LIMIT = 1000


class QualysAdapter(BaseConnector):
    CONNECTOR_ID   = "qualys"
    CONNECTOR_NAME = "Qualys VM"
    REQUIRED_CONFIG_KEYS = ["username", "password"]

    def authenticate(self) -> None:
        # No token to fetch -- Basic Auth is re-sent on every request in
        # _qualys_get(). This only marks the adapter "ready."
        self._set_token("qualys-basic-auth", expires_in=86400 * 365)

    def _qualys_get(self, path: str, params: dict) -> ET.Element:
        self._ensure_token()
        base_url = self.config.get("base_url", DEFAULT_BASE_URL).rstrip("/")
        headers = {"X-Requested-With": "GraphRisk Connector"}
        auth = (self.config["username"], self.config["password"])
        r = self._session.get(f"{base_url}{path}", headers=headers, auth=auth, params=params, timeout=60)
        r.raise_for_status()
        return ET.fromstring(r.content)

    def _control_title(self, check_id: str) -> str:
        return self.config.get("control_titles", {}).get(check_id, DEFAULT_CONTROL_TITLES[check_id])

    def supported_checks(self) -> list[str]:
        return SUPPORTED_CHECKS

    def run_check(self, check_id: str) -> CheckResult:
        self._ensure_token()
        dispatch = {
            "qualys_critical_vulnerabilities": self._check_critical_vulnerabilities,
            "qualys_stale_scans":              self._check_stale_scans,
            "qualys_reopened_vulnerabilities": self._check_reopened_vulnerabilities,
            "qualys_confirmed_high_severity":  self._check_confirmed_high_severity,
        }
        if check_id not in dispatch:
            raise ValueError(f"Unknown check for QualysAdapter: {check_id}")
        return dispatch[check_id]()

    # ── Individual checks ────────────────────────────────────────────────────
    def _check_critical_vulnerabilities(self) -> CheckResult:
        """
        What fraction of hosts have at least one active or newly-found
        Severity 5 (Qualys's top of its 1-5 scale) detection -- the
        broadest "is anything on fire" signal, regardless of whether
        Qualys has independently confirmed exploitability.
        """
        root = self._qualys_get(
            "/api/2.0/fo/asset/host/vm/detection/",
            params={"action": "list", "status": "New,Active", "severities": "5"},
        )
        hosts = root.findall(".//HOST")
        affected = len(hosts)
        total_root = self._qualys_get(
            "/api/2.0/fo/asset/host/", params={"action": "list", "truncation_limit": TRUNCATION_LIMIT}
        )
        total = len(total_root.findall(".//HOST"))
        score = round(1.0 - (affected / total), 4) if total > 0 else 1.0

        return CheckResult(
            check_id="qualys_critical_vulnerabilities",
            check_name="Qualys Critical (Severity 5) Vulnerability Exposure",
            category=CheckCategory.PATCH_MGMT,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=(
                CheckStatus.PASS if affected == 0 else
                CheckStatus.WARNING if affected <= 5 else
                CheckStatus.FAIL
            ),
            score=score,
            affected_count=affected,
            total_count=total,
            detail=f"{affected} of {total} hosts have an active Severity 5 vulnerability",
            control_title=self._control_title("qualys_critical_vulnerabilities"),
        )

    def _check_stale_scans(self, threshold_days: int = 30) -> CheckResult:
        """
        A host that hasn't been vulnerability-scanned recently is a
        blind spot -- its last known posture could be stale by weeks or
        months, or it may never have been scanned at all.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=threshold_days)
        root = self._qualys_get(
            "/api/2.0/fo/asset/host/", params={"action": "list", "truncation_limit": TRUNCATION_LIMIT}
        )
        hosts = root.findall(".//HOST")
        total = len(hosts)
        stale = 0
        for h in hosts:
            scanned_el = h.find("LAST_VULN_SCAN_DATETIME")
            scanned = scanned_el.text if scanned_el is not None else None
            if not scanned:
                stale += 1
                continue
            try:
                scanned_at = datetime.strptime(scanned, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            except ValueError:
                stale += 1
                continue
            if scanned_at < cutoff:
                stale += 1
        score = round(1.0 - (stale / total), 4) if total > 0 else 1.0

        return CheckResult(
            check_id="qualys_stale_scans",
            check_name="Qualys Scan Freshness",
            category=CheckCategory.PATCH_MGMT,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=(
                CheckStatus.PASS if score >= 0.90 else
                CheckStatus.WARNING if score >= 0.70 else
                CheckStatus.FAIL
            ),
            score=score,
            affected_count=stale,
            total_count=total,
            detail=f"{stale} of {total} hosts have not been vulnerability-scanned in the last {threshold_days} days",
            control_title=self._control_title("qualys_stale_scans"),
        )

    def _check_reopened_vulnerabilities(self) -> CheckResult:
        """
        A detection Qualys marks Re-Opened was previously Fixed and has
        since come back -- a regression signal (a patch that didn't
        stick, a rebuilt host from a stale image, a config drift), not
        just an ordinary new finding.
        """
        root = self._qualys_get(
            "/api/2.0/fo/asset/host/vm/detection/",
            params={"action": "list", "status": "Re-Opened"},
        )
        reopened = len(root.findall(".//DETECTION"))

        return CheckResult(
            check_id="qualys_reopened_vulnerabilities",
            check_name="Qualys Re-Opened Vulnerability Audit",
            category=CheckCategory.PATCH_MGMT,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=CheckStatus.PASS if reopened == 0 else CheckStatus.WARNING if reopened <= 5 else CheckStatus.FAIL,
            score=1.0 if reopened == 0 else 0.6 if reopened <= 5 else 0.2,
            affected_count=reopened,
            total_count=reopened,
            detail=f"{reopened} previously-fixed detections have regressed back to Re-Opened status",
            control_title=self._control_title("qualys_reopened_vulnerabilities"),
        )

    def _check_confirmed_high_severity(self) -> CheckResult:
        """
        Narrower and higher-confidence than the Severity 5 check above:
        only detections Qualys has independently Confirmed (not merely
        Potential) at Severity 4 or 5 -- verified exposure that warrants
        action, not a finding still awaiting confirmation.
        """
        root = self._qualys_get(
            "/api/2.0/fo/asset/host/vm/detection/",
            params={"action": "list", "status": "New,Active", "severities": "4-5", "type": "Confirmed"},
        )
        confirmed = len(root.findall(".//DETECTION"))

        return CheckResult(
            check_id="qualys_confirmed_high_severity",
            check_name="Qualys Confirmed High-Severity Detections",
            category=CheckCategory.PATCH_MGMT,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=CheckStatus.PASS if confirmed == 0 else CheckStatus.WARNING if confirmed <= 5 else CheckStatus.FAIL,
            score=1.0 if confirmed == 0 else 0.6 if confirmed <= 5 else 0.2,
            affected_count=confirmed,
            total_count=confirmed,
            detail=f"{confirmed} vulnerabilities are Confirmed (not just Potential) at Severity 4-5",
            control_title=self._control_title("qualys_confirmed_high_severity"),
        )
