"""
Layer 2: Wazuh adapter.

Wazuh is a self-hosted SIEM/XDR manager, not a fixed-domain SaaS API --
config["api_url"] points at the customer's own manager (default port
55000), not a vendor-owned host. Auth is HTTP Basic against
POST /security/user/authenticate, which returns a JWT that -- unlike
Okta's static, effectively-permanent token -- genuinely expires (Wazuh's
default is 900s), so this adapter actually exercises BaseConnector's
_ensure_token() refresh path rather than working around it the way
OktaAdapter does.

Scope note: Wazuh's classic vulnerability-detector API
(GET /vulnerability/{agent_id}) was removed starting with Wazuh 4.8 --
that data now lives in the Wazuh indexer, a separate OpenSearch-based
service with a different host/port and response shape, not the manager
REST API this adapter talks to. Deliberately left out of this first
version rather than guessing at an indexer query that would silently
return nothing against a real instance. The two checks below -- agent
connectivity and SCA compliance -- are both on the classic manager API
and have been stable across Wazuh versions for years.

control_title values are a best guess at what this tenant's Control
nodes are actually titled -- see WRITE_CHECK_RESULT in graphrisk_core:
the write silently matches zero rows (no error, no exception) if no
Control node has that exact title, so a result can "succeed" here and
still never show up in the graph. Override via
config["control_titles"] = {"wazuh_agent_connectivity": "...", ...}
if your graph uses different names.
"""
from ..base import BaseConnector
from ..models import CheckResult, CheckStatus, CheckCategory

SUPPORTED_CHECKS = [
    "wazuh_agent_connectivity",
    "wazuh_sca_compliance",
]

DEFAULT_CONTROL_TITLES = {
    "wazuh_agent_connectivity": "Endpoint Detection & Response",
    "wazuh_sca_compliance":     "Secure Configuration Baseline",
}

# SCA compliance pulls one request per active agent; cap how many we walk
# per run so a large fleet doesn't turn one check into hundreds of
# sequential requests against the manager.
MAX_AGENTS_PER_SCA_SWEEP = 50


class WazuhAdapter(BaseConnector):
    CONNECTOR_ID   = "wazuh"
    CONNECTOR_NAME = "Wazuh"
    REQUIRED_CONFIG_KEYS = ["api_url", "username", "password"]

    def authenticate(self) -> None:
        base_url = self.config["api_url"].rstrip("/")
        # Self-hosted managers commonly run a self-signed cert (default
        # in most Wazuh installs); verify_ssl defaults to True and has to
        # be explicitly opted out per-tenant, never hardcoded off.
        verify = self.config.get("verify_ssl", True)
        r = self._session.post(
            f"{base_url}/security/user/authenticate",
            auth=(self.config["username"], self.config["password"]),
            verify=verify,
            timeout=30,
        )
        r.raise_for_status()
        token = r.json()["data"]["token"]
        self._set_token(token, expires_in=900)

    def _wazuh_get(self, path: str, params: dict = None) -> dict:
        """
        Standard Bearer-JWT GET, mirroring BaseConnector._get() -- but
        verify_ssl has to be threaded through per-request here since a
        self-hosted manager's cert trust isn't something the shared base
        class can assume one way or the other.
        """
        self._ensure_token()
        base_url = self.config["api_url"].rstrip("/")
        verify = self.config.get("verify_ssl", True)
        headers = {"Authorization": f"Bearer {self._token}"}
        r = self._session.get(f"{base_url}{path}", headers=headers, params=params, verify=verify, timeout=30)
        if r.status_code == 401:
            self.authenticate()
            headers = {"Authorization": f"Bearer {self._token}"}
            r = self._session.get(f"{base_url}{path}", headers=headers, params=params, verify=verify, timeout=30)
        r.raise_for_status()
        return r.json()

    def _control_title(self, check_id: str) -> str:
        return self.config.get("control_titles", {}).get(check_id, DEFAULT_CONTROL_TITLES[check_id])

    def supported_checks(self) -> list[str]:
        return SUPPORTED_CHECKS

    def run_check(self, check_id: str) -> CheckResult:
        self._ensure_token()
        dispatch = {
            "wazuh_agent_connectivity": self._check_agent_connectivity,
            "wazuh_sca_compliance":     self._check_sca_compliance,
        }
        if check_id not in dispatch:
            raise ValueError(f"Unknown check for WazuhAdapter: {check_id}")
        return dispatch[check_id]()

    # ── Individual checks ────────────────────────────────────────────────────
    def _check_agent_connectivity(self) -> CheckResult:
        """
        What fraction of registered agents are actively reporting in,
        rather than disconnected or never having connected -- a
        disconnected agent is a monitoring coverage gap, not just an
        offline host.
        """
        data = self._wazuh_get("/agents", params={"limit": 500})
        agents = data.get("data", {}).get("affected_items", [])
        # Agent id "000" is the manager itself, not an endpoint -- exclude
        # it from the coverage count.
        agents = [a for a in agents if a.get("id") != "000"]
        total = len(agents)
        active = sum(1 for a in agents if a.get("status") == "active")
        disconnected = total - active
        score = round(active / total, 4) if total > 0 else 0.0

        return CheckResult(
            check_id="wazuh_agent_connectivity",
            check_name="Wazuh Agent Connectivity",
            category=CheckCategory.ENDPOINT,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=(
                CheckStatus.PASS if score >= 0.95 else
                CheckStatus.WARNING if score >= 0.80 else
                CheckStatus.FAIL
            ),
            score=score,
            affected_count=disconnected,
            total_count=total,
            detail=f"{disconnected} of {total} registered agents are disconnected or never connected",
            control_title=self._control_title("wazuh_agent_connectivity"),
        )

    def _check_sca_compliance(self) -> CheckResult:
        """
        Aggregate Security Configuration Assessment (CIS-benchmark-style)
        pass rate across every active agent's evaluated policies.
        """
        agents_data = self._wazuh_get("/agents", params={"limit": 500, "status": "active"})
        agents = agents_data.get("data", {}).get("affected_items", [])
        agents = [a for a in agents if a.get("id") != "000"][:MAX_AGENTS_PER_SCA_SWEEP]

        total_pass = 0
        total_checks = 0
        agents_with_data = 0
        for agent in agents:
            sca = self._wazuh_get(f"/sca/{agent['id']}")
            policies = sca.get("data", {}).get("affected_items", [])
            if policies:
                agents_with_data += 1
            for policy in policies:
                total_pass   += policy.get("pass", 0)
                total_checks += policy.get("total_checks", 0)

        score = round(total_pass / total_checks, 4) if total_checks > 0 else 0.0
        failed = total_checks - total_pass

        return CheckResult(
            check_id="wazuh_sca_compliance",
            check_name="Wazuh Security Configuration Assessment",
            category=CheckCategory.ENDPOINT,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=(
                CheckStatus.PASS if score >= 0.90 else
                CheckStatus.WARNING if score >= 0.70 else
                CheckStatus.FAIL
            ),
            score=score,
            affected_count=failed,
            total_count=total_checks,
            detail=(
                f"{failed} of {total_checks} SCA checks failing across "
                f"{agents_with_data} of {len(agents)} active agents with SCA data"
                if total_checks > 0 else
                f"No SCA policy data returned for {len(agents)} active agents "
                "-- confirm the SCA module is enabled on these agents"
            ),
            control_title=self._control_title("wazuh_sca_compliance"),
        )
