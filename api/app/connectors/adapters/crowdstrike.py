"""
Layer 2: CrowdStrike Falcon adapter.

CrowdStrike Falcon is a cloud-delivered EDR/XDR platform. Auth is standard
OAuth 2.0 client credentials against POST /oauth2/token -- BaseConnector's
shared _oauth_client_credentials() helper already sends that as a
form-encoded body (requests' `data=` argument, not `json=`), which is
exactly what CrowdStrike expects, so this adapter reuses it directly
rather than writing a bespoke auth method the way OktaAdapter and
WazuhAdapter had to. The extra "scope" field the helper always includes
is a no-op for CrowdStrike (it isn't part of the client-credentials grant
this API expects and is simply ignored), so passing scope="" is safe.
A successful token exchange returns HTTP 201, not 200; BaseConnector's
`_oauth_client_credentials` only calls `raise_for_status()`, which treats
any 2xx as success, so 201 doesn't need special-casing.

Falcon's API is region-specific -- US-1 (api.crowdstrike.com), US-2, EU-1,
and US-GOV-1 each have a distinct host tied to which cloud a customer's
CID was provisioned in. config["base_url"] lets a tenant point at their
own region instead of hardcoding US-1 as the default.

Once authenticated, every subsequent call is a standard `Authorization:
Bearer <token>` GET, so -- unlike Okta's custom `SSWS` scheme or Wazuh's
need to thread verify_ssl through every request -- this adapter can reuse
BaseConnector._get() unmodified for all four checks.

Structurally complete against CrowdStrike's documented Falcon API surface
(OAuth2, the Hosts "combined" endpoint, Detects, Spotlight Vulnerabilities)
-- not yet run against a live Falcon tenant. Same status as WazuhAdapter:
correct against the published API shape, pending real-credential
validation (see README's connector validation table).

control_title values are a best guess at what this tenant's Control nodes
are actually titled -- see WazuhAdapter's docstring for why a mismatch
fails silently at the graph-write step. Override via
config["control_titles"] = {"crowdstrike_stale_sensors": "...", ...} if
your graph uses different names.
"""
from datetime import datetime, timedelta, timezone

from ..base import BaseConnector
from ..models import CheckResult, CheckStatus, CheckCategory
from ..profile import group_vulnerable_packages, severity_label

SUPPORTED_CHECKS = [
    "crowdstrike_stale_sensors",
    "crowdstrike_rfm_hosts",
    "crowdstrike_high_severity_detections",
    "crowdstrike_critical_vulnerabilities",
]

DEFAULT_CONTROL_TITLES = {
    "crowdstrike_stale_sensors":              "Endpoint Detection & Response",
    "crowdstrike_rfm_hosts":                  "Endpoint Detection & Response",
    "crowdstrike_high_severity_detections":   "Security Incident Response",
    "crowdstrike_critical_vulnerabilities":   "Vulnerability & Patch Management",
}

DEFAULT_BASE_URL = "https://api.crowdstrike.com"

# How many hosts/detections/vulnerabilities to pull per check. CrowdStrike's
# combined endpoints cap at 500 per request; a real fleet larger than that
# would need this adapter to paginate via the endpoint's offset/after
# cursor -- left as a known scaling limit rather than guessed at, same
# spirit as Wazuh's MAX_AGENTS_PER_SCA_SWEEP cap.
PAGE_LIMIT = 500

# A host that checked in within this long is shown as "online" on the asset
# page -- Falcon's host record has a last_seen timestamp, not a live status.
ONLINE_WITHIN = timedelta(hours=24)

# Findings at these severities become Vulnerability nodes / risks, same
# cutoff as Wazuh's default; every severity still counts toward the
# device profile's totals.
INGESTED_SEVERITIES = {"Critical", "High"}


class CrowdStrikeAdapter(BaseConnector):
    CONNECTOR_ID   = "crowdstrike"
    CONNECTOR_NAME = "CrowdStrike Falcon"
    REQUIRED_CONFIG_KEYS = ["client_id", "client_secret"]
    # Device profile (see connectors/profile.py): host details from the
    # devices endpoint, open detections per host, Spotlight findings per host.
    PROFILE_SECTIONS = ("identity", "health", "os", "network", "protection",
                        "ownership", "cloud", "software", "vulnerabilities", "activity")

    def authenticate(self) -> None:
        base_url = self.config.get("base_url", DEFAULT_BASE_URL).rstrip("/")
        self._oauth_client_credentials(
            token_url=f"{base_url}/oauth2/token",
            client_id=self.config["client_id"],
            client_secret=self.config["client_secret"],
            scope="",
        )

    def _control_title(self, check_id: str) -> str:
        return self.config.get("control_titles", {}).get(check_id, DEFAULT_CONTROL_TITLES[check_id])

    def supported_checks(self) -> list[str]:
        return SUPPORTED_CHECKS

    def run_check(self, check_id: str) -> CheckResult:
        self._ensure_token()
        dispatch = {
            "crowdstrike_stale_sensors":            self._check_stale_sensors,
            "crowdstrike_rfm_hosts":                 self._check_rfm_hosts,
            "crowdstrike_high_severity_detections":  self._check_high_severity_detections,
            "crowdstrike_critical_vulnerabilities":  self._check_critical_vulnerabilities,
        }
        if check_id not in dispatch:
            raise ValueError(f"Unknown check for CrowdStrikeAdapter: {check_id}")
        return dispatch[check_id]()

    # ── Shared host fetch ────────────────────────────────────────────────────
    def _fetch_hosts(self) -> list[dict]:
        """
        Falcon's combined devices endpoint returns full host objects
        (last_seen, hostname, reduced_functionality_mode, ...) in one
        call, avoiding the query-ids-then-fetch-details round trip most
        of the rest of the Falcon API requires.
        """
        base_url = self.config.get("base_url", DEFAULT_BASE_URL).rstrip("/")
        data = self._get(f"{base_url}/devices/combined/devices/light/v1", params={"limit": PAGE_LIMIT})
        return data.get("resources", [])

    # ── Device profile ───────────────────────────────────────────────────────
    @staticmethod
    def _host_name(h: dict) -> str:
        return h.get("hostname") or f"Falcon host {h.get('device_id')}"

    @staticmethod
    def _parse_time(value):
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None

    def _host_to_asset(self, h: dict) -> dict:
        """One Falcon host, as a discovered asset with its device profile."""
        seen_at = self._parse_time(h.get("last_seen"))
        online = seen_at is not None and datetime.now(timezone.utc) - seen_at <= ONLINE_WITHIN
        platform = h.get("platform_name") or ""
        policies = h.get("device_policies") or {}
        prevention = policies.get("prevention") or {}
        if h.get("reduced_functionality_mode") == "yes":
            protection_status = "Reduced functionality mode"
        elif h.get("status") == "contained":
            protection_status = "Contained (network isolated)"
        else:
            protection_status = "Active"
        mac = (h.get("mac_address") or "").replace("-", ":").lower() or None
        return {
            "name": self._host_name(h),
            "asset_type": "Server" if h.get("product_type_desc") == "Server" else "Endpoint",
            "criticality": "Medium",
            "environment": "Production",
            "vendor": "Microsoft" if platform.lower() == "windows" else None,
            "product": "Windows" if platform.lower() == "windows" else None,
            "profile": {
                "identity": {
                    "hostname": h.get("hostname"),
                    "device_type": h.get("product_type_desc"),
                    "manufacturer": h.get("system_manufacturer"),
                    "model": h.get("system_product_name"),
                    "serial_number": h.get("serial_number"),
                    "agent_id": h.get("device_id"),
                    "cloud_instance_id": h.get("instance_id"),
                    "groups": h.get("tags"),
                },
                "health": {
                    "status": "online" if online else "offline",
                    "last_seen": h.get("last_seen"),
                    "enrolled_at": h.get("first_seen"),
                    "agent_version": h.get("agent_version"),
                },
                "os": {
                    "name": h.get("os_product_name") or platform or None,
                    "version": h.get("os_version"),
                    "platform": platform or None,
                    "kernel": h.get("kernel_version"),
                    "build": h.get("os_build"),
                },
                "network": {
                    "ip_addresses": [h["local_ip"]] if h.get("local_ip") else None,
                    "public_ip": h.get("external_ip"),
                    "mac_addresses": [mac] if mac else None,
                },
                "protection": {
                    "status": protection_status,
                    "product": "CrowdStrike Falcon",
                    "policy": (
                        None if "applied" not in prevention else
                        ("Prevention policy applied" if prevention.get("applied") else "Prevention policy not applied")
                    ),
                },
                "ownership": {"assigned_user": h.get("last_login_user")},
                "cloud": {
                    "provider": h.get("service_provider"),
                    "account": h.get("service_provider_account_id"),
                    "region": h.get("zone_group"),
                },
            },
        }

    # ── Individual checks ────────────────────────────────────────────────────
    def _check_stale_sensors(self, threshold_days: int = 7) -> CheckResult:
        """
        A sensor that hasn't checked in recently is either an offline
        endpoint or a monitoring coverage gap -- either way it isn't
        contributing to EDR visibility right now.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=threshold_days)
        hosts = self._fetch_hosts()
        total = len(hosts)
        stale = 0
        for h in hosts:
            last_seen = h.get("last_seen")
            if not last_seen:
                stale += 1
                continue
            try:
                seen_at = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
            except ValueError:
                stale += 1
                continue
            if seen_at < cutoff:
                stale += 1
        score = round(1.0 - (stale / total), 4) if total > 0 else 1.0

        return CheckResult(
            # Every Falcon-managed host becomes an asset, with its profile.
            discovered_assets=[self._host_to_asset(h) for h in hosts],
            check_id="crowdstrike_stale_sensors",
            check_name="CrowdStrike Sensor Connectivity",
            category=CheckCategory.ENDPOINT,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=(
                CheckStatus.PASS if score >= 0.95 else
                CheckStatus.WARNING if score >= 0.80 else
                CheckStatus.FAIL
            ),
            score=score,
            affected_count=stale,
            total_count=total,
            detail=f"{stale} of {total} sensors have not checked in within {threshold_days} days",
            control_title=self._control_title("crowdstrike_stale_sensors"),
        )

    def _check_rfm_hosts(self) -> CheckResult:
        """
        A sensor in Reduced Functionality Mode is installed but running
        with prevention/detection capability disabled -- typically a
        licensing, kernel-compatibility, or update-pending issue. It
        looks "connected" but isn't actually protecting the host.
        """
        hosts = self._fetch_hosts()
        total = len(hosts)
        rfm = sum(1 for h in hosts if h.get("reduced_functionality_mode") == "yes")
        score = round(1.0 - (rfm / total), 4) if total > 0 else 1.0

        return CheckResult(
            check_id="crowdstrike_rfm_hosts",
            check_name="CrowdStrike Reduced Functionality Mode Audit",
            category=CheckCategory.ENDPOINT,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=CheckStatus.PASS if rfm == 0 else CheckStatus.WARNING if rfm <= 3 else CheckStatus.FAIL,
            score=score,
            affected_count=rfm,
            total_count=total,
            detail=f"{rfm} of {total} hosts have a sensor running in Reduced Functionality Mode",
            control_title=self._control_title("crowdstrike_rfm_hosts"),
        )

    def _check_high_severity_detections(self) -> CheckResult:
        """
        Open (unresolved) detections at High or Critical severity --
        active alerts still needing triage, not historical noise.
        """
        base_url = self.config.get("base_url", DEFAULT_BASE_URL).rstrip("/")
        ids_data = self._get(
            f"{base_url}/detects/queries/detects/v1",
            params={"filter": "status:'new'", "limit": PAGE_LIMIT},
        )
        ids = ids_data.get("resources", [])
        total = len(ids)
        high_severity = 0
        per_host: dict[str, dict] = {}
        if ids:
            summaries = self._post(
                f"{base_url}/detects/entities/summaries/GET/v1", json_body={"ids": ids}
            )
            for d in summaries.get("resources", []):
                severity = d.get("max_severity_displayname")
                if severity in ("High", "Critical"):
                    high_severity += 1
                # Open detections per host, for that device's Activity section.
                device = d.get("device") or {}
                host = device.get("hostname") or (f"Falcon host {device['device_id']}" if device.get("device_id") else None)
                if not host:
                    continue
                entry = per_host.setdefault(host, {"levels": {}, "recent": []})
                label = severity or "Unknown"
                entry["levels"][label] = entry["levels"].get(label, 0) + 1
                behaviors = d.get("behaviors") or []
                what = (behaviors[0].get("display_name") or behaviors[0].get("scenario")) if behaviors else None
                entry["recent"].append(f"{label}: {what or d.get('detection_id', 'detection')}")
        activity = [
            {"name": host, "profile_only": True, "profile": {"activity": {
                "alerts_by_level": e["levels"], "recent_alerts": e["recent"], "window": "Open detections",
            }}}
            for host, e in per_host.items()
        ]
        score = round(1.0 - (high_severity / total), 4) if total > 0 else 1.0

        return CheckResult(
            discovered_assets=activity,
            check_id="crowdstrike_high_severity_detections",
            check_name="CrowdStrike High-Severity Open Detections",
            category=CheckCategory.ENDPOINT,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=(
                CheckStatus.PASS if high_severity == 0 else
                CheckStatus.WARNING if high_severity <= 3 else
                CheckStatus.FAIL
            ),
            score=score,
            affected_count=high_severity,
            total_count=total,
            detail=f"{high_severity} of {total} open detections are High or Critical severity",
            control_title=self._control_title("crowdstrike_high_severity_detections"),
        )

    def _check_critical_vulnerabilities(self) -> CheckResult:
        """
        Open, CVE-backed findings from Falcon Spotlight at Critical
        severity -- exploitable exposure Falcon itself has already
        matched to installed software on managed hosts.
        """
        base_url = self.config.get("base_url", DEFAULT_BASE_URL).rstrip("/")
        data = self._get(
            f"{base_url}/spotlight/combined/vulnerabilities/v1",
            # host_info: which device each finding is on, for the asset page.
            params={"filter": "status:'open'", "limit": PAGE_LIMIT, "facet": ["cve", "host_info"]},
        )
        vulns = data.get("resources", [])
        total = len(vulns)
        critical = sum(1 for v in vulns if (v.get("cve") or {}).get("severity") == "CRITICAL")
        discovered_assets = self._spotlight_assets(vulns)
        score = round(1.0 - (critical / total), 4) if total > 0 else 1.0

        return CheckResult(
            discovered_assets=discovered_assets,
            check_id="crowdstrike_critical_vulnerabilities",
            check_name="CrowdStrike Spotlight Critical Vulnerabilities",
            category=CheckCategory.PATCH_MGMT,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=(
                CheckStatus.PASS if critical == 0 else
                CheckStatus.WARNING if critical <= 5 else
                CheckStatus.FAIL
            ),
            score=score,
            affected_count=critical,
            total_count=total,
            detail=f"{critical} of {total} open Spotlight findings are CRITICAL severity",
            control_title=self._control_title("crowdstrike_critical_vulnerabilities"),
        )

    def _spotlight_assets(self, vulns: list[dict]) -> list[dict]:
        """
        Spotlight findings grouped per host: Critical/High ones as real
        per-device vulnerabilities (same dict shape Wazuh uses, so they get
        Vulnerability nodes, risks and root cause the same way), and every
        severity counted for the device profile, with the affected app as
        the package to patch.
        """
        by_host: dict[str, dict] = {}
        for v in vulns:
            host = (v.get("host_info") or {}).get("hostname")
            cve = v.get("cve") or {}
            if not host or not cve.get("id"):
                continue
            severity = severity_label(cve.get("severity"))
            apps = v.get("apps") or []
            app = apps[0].get("product_name_version") if apps else None
            entry = by_host.setdefault(host, {"findings": [], "counts": {}})
            label = severity or "Unknown"
            entry["counts"][label] = entry["counts"].get(label, 0) + 1
            finding = {
                "cve_id": cve["id"],
                "severity": severity or "Unknown",
                "cvss_score": cve.get("base_score", 0.0),
                "description": (cve.get("description") or "")[:600],
                "published_at": cve.get("published_date", ""),
                "source": "CrowdStrike Spotlight",
            }
            if app:
                finding["package"] = {"name": app, "version": None}
            entry["findings"].append(finding)
        out = []
        for host, e in by_host.items():
            asset = {
                "name": host,
                "asset_type": "Endpoint",
                "profile": {
                    "vulnerabilities": {
                        "counts_by_severity": e["counts"],
                        "total": sum(e["counts"].values()),
                        "scanner": "CrowdStrike Spotlight",
                    },
                    "software": {"vulnerable_packages": group_vulnerable_packages(e["findings"])},
                },
            }
            ingested = [f for f in e["findings"] if f["severity"] in INGESTED_SEVERITIES]
            if ingested:
                asset["vulnerabilities"] = ingested
            out.append(asset)
        return out
