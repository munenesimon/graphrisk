"""
Layer 2 reference implementation: Microsoft Entra ID adapter.

This is deliberately thin — authentication, HTTP, retries, and pagination
are all inherited from BaseConnector. This file contains only what is
unique to the Microsoft Graph API: endpoints, field names, and check logic.
"""
from ..base import BaseConnector
from ..models import CheckResult, CheckStatus, CheckCategory

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

SUPPORTED_CHECKS = [
    "mfa_enabled",
    "dormant_accounts",
    "privileged_mfa",
    "conditional_access",
    "guest_account_audit",
    "entra_device_compliance",
]

# Entra's trustType values, in plain words.
_TRUST_TYPES = {"AzureAd": "Entra joined", "ServerAd": "Hybrid joined", "Workplace": "Registered (personal)"}


class EntraIDAdapter(BaseConnector):
    CONNECTOR_ID   = "entra_id"
    CONNECTOR_NAME = "Microsoft Entra ID"
    REQUIRED_CONFIG_KEYS = ["azure_tenant_id", "client_id", "client_secret"]
    # Device profile (see connectors/profile.py), from Entra's device
    # directory: join type, OS, last sign-in, managed/compliant state.
    # Needs the Device.Read.All application permission.
    PROFILE_SECTIONS = ("identity", "health", "os", "ownership")

    def authenticate(self) -> None:
        """OAuth 2.0 client credentials via the Microsoft identity platform."""
        self._oauth_client_credentials(
            token_url=(
                f"https://login.microsoftonline.com/"
                f"{self.config['azure_tenant_id']}/oauth2/v2.0/token"
            ),
            client_id=self.config["client_id"],
            client_secret=self.config["client_secret"],
            scope="https://graph.microsoft.com/.default",
        )

    def supported_checks(self) -> list[str]:
        return SUPPORTED_CHECKS

    def run_check(self, check_id: str) -> CheckResult:
        dispatch = {
            "mfa_enabled":         self._check_mfa_enabled,
            "dormant_accounts":    self._check_dormant_accounts,
            "privileged_mfa":      self._check_privileged_mfa,
            "conditional_access":  self._check_conditional_access,
            "guest_account_audit": self._check_guest_accounts,
            "entra_device_compliance": self._check_device_compliance,
        }
        if check_id not in dispatch:
            raise ValueError(f"Unknown check for EntraIDAdapter: {check_id}")
        return dispatch[check_id]()

    # ── Individual checks ────────────────────────────────────────────────────
    def _check_mfa_enabled(self) -> CheckResult:
        users = list(self._paginate(
            f"{GRAPH_BASE}/reports/authenticationMethods/userRegistrationDetails"
        ))
        total    = len(users)
        mfa_ok   = sum(1 for u in users if u.get("isMfaRegistered", False))
        mfa_fail = total - mfa_ok
        score    = round(mfa_ok / total, 4) if total > 0 else 0.0

        return CheckResult(
            check_id="mfa_enabled",
            check_name="MFA Enabled Check",
            category=CheckCategory.IAM,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=(
                CheckStatus.PASS if score >= 0.95 else
                CheckStatus.WARNING if score >= 0.80 else
                CheckStatus.FAIL
            ),
            score=score,
            affected_count=mfa_fail,
            total_count=total,
            detail=f"{mfa_fail} of {total} users have MFA disabled ({round((1-score)*100)}%)",
            raw_data={"mfa_ok": mfa_ok, "mfa_fail": mfa_fail},
            control_title="Multi-Factor Authentication",
        )

    def _check_dormant_accounts(self, threshold_days: int = 90) -> CheckResult:
        from datetime import datetime, timedelta, timezone
        cutoff = (datetime.now(timezone.utc) - timedelta(days=threshold_days)).isoformat()

        users = list(self._paginate(
            f"{GRAPH_BASE}/users",
            params={
                "$select": "id,displayName,signInActivity,accountEnabled",
                "$filter": "accountEnabled eq true",
            },
        ))
        dormant = [
            u for u in users
            if not u.get("signInActivity")
            or u["signInActivity"].get("lastSignInDateTime", "") < cutoff
        ]
        count = len(dormant)
        score = round(1.0 - (count / len(users)), 4) if users else 1.0

        return CheckResult(
            check_id="dormant_accounts",
            check_name="Dormant Account Check",
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
            total_count=len(users),
            detail=f"{count} accounts inactive for more than {threshold_days} days",
            control_title="Dormant Account Management",
        )

    def _check_privileged_mfa(self) -> CheckResult:
        privileged_roles = [
            "Global Administrator", "Privileged Role Administrator",
            "Security Administrator", "Exchange Administrator",
        ]
        mfa_data = list(self._paginate(
            f"{GRAPH_BASE}/reports/authenticationMethods/userRegistrationDetails"
        ))
        mfa_map = {u["id"]: u.get("isMfaRegistered", False) for u in mfa_data}

        roles = self._get(f"{GRAPH_BASE}/directoryRoles")
        privs_without_mfa = []
        for role in roles.get("value", []):
            if role["displayName"] in privileged_roles:
                members = self._get(f"{GRAPH_BASE}/directoryRoles/{role['id']}/members")
                for m in members.get("value", []):
                    if not mfa_map.get(m["id"], False):
                        privs_without_mfa.append({
                            "user": m.get("displayName", ""),
                            "role": role["displayName"],
                        })

        count = len(privs_without_mfa)
        return CheckResult(
            check_id="privileged_mfa",
            check_name="Privileged Accounts MFA Check",
            category=CheckCategory.PRIVILEGED_ACCESS,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=CheckStatus.PASS if count == 0 else CheckStatus.FAIL,
            score=0.0 if count > 0 else 1.0,
            affected_count=count,
            total_count=len(mfa_map),
            detail=f"{count} privileged accounts without MFA — immediate action required",
            raw_data={"accounts": privs_without_mfa},
            control_title="Multi-Factor Authentication",
        )

    def _check_conditional_access(self) -> CheckResult:
        policies = self._get(f"{GRAPH_BASE}/identity/conditionalAccess/policies")
        active = [p for p in policies.get("value", []) if p.get("state") == "enabled"]
        has_risk_policy = any("signInRiskLevels" in str(p) for p in active)

        return CheckResult(
            check_id="conditional_access",
            check_name="Conditional Access Policy Check",
            category=CheckCategory.IAM,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=CheckStatus.PASS if has_risk_policy else CheckStatus.WARNING,
            score=1.0 if has_risk_policy else 0.5,
            total_count=len(active),
            detail=(
                f"{len(active)} active Conditional Access policies. "
                f"Risk-based policy present: {'Yes' if has_risk_policy else 'No'}"
            ),
            control_title="Conditional Access Enforcement",
        )

    def _check_guest_accounts(self) -> CheckResult:
        guests = list(self._paginate(
            f"{GRAPH_BASE}/users",
            params={
                "$filter": "userType eq 'Guest'",
                "$select": "id,displayName,userPrincipalName",
            },
        ))
        count = len(guests)
        return CheckResult(
            check_id="guest_account_audit",
            check_name="Guest Account Audit",
            category=CheckCategory.IAM,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=CheckStatus.PASS if count == 0 else CheckStatus.WARNING,
            score=1.0 if count == 0 else 0.7,
            affected_count=count,
            total_count=count,
            detail=f"{count} guest accounts found — review for excessive permissions",
            control_title="Guest and External Account Management",
        )

    def _check_device_compliance(self) -> CheckResult:
        """
        Of the enabled devices in the directory, how many are marked
        compliant (by Intune or another MDM) -- a non-compliant or unmanaged
        device signing in is a gap Conditional Access alone may not close.
        Also discovers every device as an asset with its profile.
        """
        devices = list(self._paginate(
            f"{GRAPH_BASE}/devices",
            params={"$select": "id,deviceId,displayName,operatingSystem,operatingSystemVersion,"
                               "isCompliant,isManaged,approximateLastSignInDateTime,"
                               "registrationDateTime,trustType,manufacturer,model,accountEnabled"},
        ))
        enabled = [d for d in devices if d.get("accountEnabled", True)]
        non_compliant = sum(1 for d in enabled if not d.get("isCompliant"))
        total = len(enabled)
        score = round(1.0 - non_compliant / total, 4) if total else 1.0

        discovered = []
        for d in devices:
            os_name = d.get("operatingSystem") or ""
            windows = os_name.lower().startswith("windows")
            discovered.append({
                "name": d.get("displayName") or f"Entra device {d.get('deviceId') or d.get('id')}",
                "asset_type": "Endpoint",
                "vendor": "Microsoft" if windows else None,
                "product": "Windows" if windows else None,
                "profile": {
                    "identity": {
                        "hostname": d.get("displayName"),
                        "device_type": _TRUST_TYPES.get(d.get("trustType"), d.get("trustType")),
                        "manufacturer": d.get("manufacturer"),
                        "model": d.get("model"),
                        "agent_id": d.get("deviceId"),
                    },
                    "health": {
                        "status": "enabled" if d.get("accountEnabled", True) else "disabled",
                        "last_seen": d.get("approximateLastSignInDateTime"),
                        "enrolled_at": d.get("registrationDateTime"),
                    },
                    "os": {"name": os_name or None, "version": d.get("operatingSystemVersion")},
                    "ownership": {"managed": d.get("isManaged"), "compliant": d.get("isCompliant")},
                },
            })

        return CheckResult(
            discovered_assets=discovered,
            check_id="entra_device_compliance",
            check_name="Entra ID Device Compliance",
            category=CheckCategory.ENDPOINT,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=(
                CheckStatus.PASS if score >= 0.95 else
                CheckStatus.WARNING if score >= 0.80 else
                CheckStatus.FAIL
            ),
            score=score,
            affected_count=non_compliant,
            total_count=total,
            detail=f"{non_compliant} of {total} enabled devices are not marked compliant",
            control_title=self.config.get("control_titles", {}).get(
                "entra_device_compliance", "Secure Configuration Baseline"),
        )
