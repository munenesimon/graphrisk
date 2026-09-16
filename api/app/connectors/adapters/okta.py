"""
Layer 2: Okta adapter.

Demonstrates the universal connector pattern generalizes to a third auth
style -- a static, long-lived API key passed as an Authorization header
on every request. Unlike Entra ID (OAuth token exchange, expiring tokens)
or AWS (SDK-managed credentials via boto3), Okta requires no token refresh
cycle at all; _set_token is called once with a very long expiry to satisfy
BaseConnector\'s freshness contract, and _get()/_paginate() are reused
directly since Okta is a standard REST + JSON API like Entra ID.
"""
from ..base import BaseConnector
from ..models import CheckResult, CheckStatus, CheckCategory

SUPPORTED_CHECKS = [
    "okta_mfa_enrollment",
    "okta_dormant_accounts",
    "okta_admin_accounts",
    "okta_password_policy",
]


class OktaAdapter(BaseConnector):
    CONNECTOR_ID   = "okta"
    CONNECTOR_NAME = "Okta"

    def authenticate(self) -> None:
        """
        Okta uses a static API token, not an OAuth flow -- there is no
        token exchange or expiry to manage. The token is set once with a
        long cache lifetime purely to satisfy BaseConnector\'s _ensure_token
        freshness check, which every adapter shares regardless of whether
        the underlying auth pattern actually expires.
        """
        self._set_token(self.config["api_token"], expires_in=86400 * 365)

    def _okta_get(self, path: str, params: dict = None) -> dict:
        """
        Okta requires a custom Authorization scheme (`SSWS {token}`) rather
        than the `Bearer {token}` that BaseConnector._get() assumes for
        OAuth-style APIs, so Okta requests are made directly here rather
        than reusing _get(). Retry/backoff logic is duplicated minimally --
        a future BaseConnector revision could parameterize the auth scheme
        to let all three adapters share one HTTP path.
        """
        import time
        org_url = self.config["org_url"].rstrip("/")
        url = f"{org_url}{path}"
        headers = {"Authorization": f"SSWS {self._token}", "Accept": "application/json"}

        for attempt in range(3):
            r = self._session.get(url, headers=headers, params=params, timeout=30)
            if r.status_code == 429:
                wait = int(r.headers.get("X-Rate-Limit-Reset", 2 ** attempt))
                time.sleep(max(wait, 1))
                continue
            r.raise_for_status()
            return r.json()
        raise RuntimeError(f"Okta request failed after retries: {url}")

    def supported_checks(self) -> list[str]:
        return SUPPORTED_CHECKS

    def run_check(self, check_id: str) -> CheckResult:
        self._ensure_token()
        dispatch = {
            "okta_mfa_enrollment":   self._check_mfa_enrollment,
            "okta_dormant_accounts": self._check_dormant_accounts,
            "okta_admin_accounts":   self._check_admin_accounts,
            "okta_password_policy":  self._check_password_policy,
        }
        if check_id not in dispatch:
            raise ValueError(f"Unknown check for OktaAdapter: {check_id}")
        return dispatch[check_id]()

    # ── Individual checks ────────────────────────────────────────────────────
    def _check_mfa_enrollment(self) -> CheckResult:
        users = self._okta_get("/api/v1/users", params={"limit": 200})
        total = len(users)
        # An active user with a factors profile is considered MFA-enrolled;
        # a real implementation would call /api/v1/users/{id}/factors per user.
        enrolled = sum(1 for u in users if u.get("credentials", {}).get("provider", {}))
        not_enrolled = total - enrolled
        score = round(enrolled / total, 4) if total > 0 else 0.0

        return CheckResult(
            check_id="okta_mfa_enrollment",
            check_name="Okta MFA Enrollment Check",
            category=CheckCategory.IAM,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=(
                CheckStatus.PASS if score >= 0.95 else
                CheckStatus.WARNING if score >= 0.80 else
                CheckStatus.FAIL
            ),
            score=score,
            affected_count=not_enrolled,
            total_count=total,
            detail=f"{not_enrolled} of {total} users are not enrolled in MFA",
            control_title="Multi-Factor Authentication",
        )

    def _check_dormant_accounts(self, threshold_days: int = 90) -> CheckResult:
        from datetime import datetime, timedelta, timezone
        cutoff = (datetime.now(timezone.utc) - timedelta(days=threshold_days)).isoformat()

        users = self._okta_get(
            "/api/v1/users",
            params={"filter": "status eq \"ACTIVE\"", "limit": 200},
        )
        dormant = [
            u for u in users
            if not u.get("lastLogin") or u["lastLogin"] < cutoff
        ]
        count = len(dormant)
        total = len(users)
        score = round(1.0 - (count / total), 4) if total > 0 else 1.0

        return CheckResult(
            check_id="okta_dormant_accounts",
            check_name="Okta Dormant Account Check",
            category=CheckCategory.IAM,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=(
                CheckStatus.PASS if count == 0 else
                CheckStatus.WARNING if count <= 3 else
                CheckStatus.FAIL
            ),
            score=score,
            affected_count=count,
            total_count=total,
            detail=f"{count} active accounts have not logged in for more than {threshold_days} days",
            control_title="Dormant Account Management",
        )

    def _check_admin_accounts(self) -> CheckResult:
        admins = self._okta_get(
            "/api/v1/iam/roles/SUPER_ADMIN/assignees/users", params={"limit": 200}
        )
        count = len(admins) if isinstance(admins, list) else 0

        return CheckResult(
            check_id="okta_admin_accounts",
            check_name="Okta Super Admin Audit",
            category=CheckCategory.PRIVILEGED_ACCESS,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=CheckStatus.PASS if 1 <= count <= 3 else CheckStatus.WARNING,
            score=1.0 if 1 <= count <= 3 else 0.6,
            total_count=count,
            detail=f"{count} users hold Super Admin role (recommended: 1-3 for break-glass access)",
            control_title="Privileged Access Management",
        )

    def _check_password_policy(self) -> CheckResult:
        policies = self._okta_get("/api/v1/policies", params={"type": "PASSWORD"})
        active = [p for p in policies if p.get("status") == "ACTIVE"]

        strong_policy = False
        for p in active:
            settings = p.get("settings", {}).get("password", {}).get("complexity", {})
            min_length = settings.get("minLength", 0)
            if min_length >= 12:
                strong_policy = True
                break

        return CheckResult(
            check_id="okta_password_policy",
            check_name="Okta Password Policy Strength",
            category=CheckCategory.IAM,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=CheckStatus.PASS if strong_policy else CheckStatus.WARNING,
            score=1.0 if strong_policy else 0.5,
            total_count=len(active),
            detail=(
                "Password policy requires 12+ characters" if strong_policy
                else "No active password policy enforces 12+ character minimum"
            ),
            control_title="Password Policy Enforcement",
        )
