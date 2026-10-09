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
service (default port 9200) with its own Basic-auth credentials, a
different host/port and response shape than the manager REST API the
rest of this adapter talks to. The two checks below -- agent
connectivity and SCA compliance -- are both on the classic manager API
and have been stable across Wazuh versions for years.

Indexer-backed vulnerability detection is opt-in on top of that: set
config["indexer_username"] / config["indexer_password"] (a second set of
credentials -- the indexer is a genuinely separate service from the
manager, with its own auth even though it's commonly the same host) and
the agent connectivity check additionally queries
`wazuh-states-vulnerabilities-*` and attaches real per-device CVE findings
to each discovered_assets entry (see CheckResult.discovered_assets and
CheckRegistry._ingest_assets). config["indexer_url"] is optional on top of
those two -- most self-hosted installs run the indexer on the same box as
the manager, just on its own port (9200), so it's only needed when the
indexer really is on a different host (see _effective_indexer_url below).
Leave both indexer_username and indexer_password unset and this adapter
behaves exactly as before -- agents still become Assets, they just carry
no vulnerabilities.
Wazuh's own vulnerability detection draws heavily on OSV/GitHub Security
Advisories for OS-package and language-ecosystem (npm, pip, ...) findings
that plain NVD/CISA KEV ingestion (data-ingestion/) never covers, which is
exactly why CheckRegistry can create a Vulnerability node from a finding's
own detail rather than only linking to what's already cataloged.

Only Critical/High severity findings are ingested by default (see
MIN_VULNERABILITY_SEVERITY below) -- a single real endpoint can easily
report hundreds of low-severity findings in third-party packages, and
flooding the graph with all of them would bury the ones that actually
matter for risk cascading. Override via config["vulnerability_severities"]
if you want a different cutoff (e.g. {"Critical"} only, or add "Medium").

control_title values are a best guess at what this tenant's Control
nodes are actually titled -- see WRITE_CHECK_RESULT in graphrisk_core:
the write silently matches zero rows (no error, no exception) if no
Control node has that exact title, so a result can "succeed" here and
still never show up in the graph. Override via
config["control_titles"] = {"wazuh_agent_connectivity": "...", ...}
if your graph uses different names.
"""
import logging
import re
from urllib.parse import urlsplit, urlunsplit

from ..base import BaseConnector, _assert_safe_url
from ..models import CheckResult, CheckStatus, CheckCategory
from ..profile import group_vulnerable_packages

logger = logging.getLogger(__name__)

SUPPORTED_CHECKS = [
    "wazuh_agent_connectivity",
    "wazuh_sca_compliance",
    # Only runs when the indexer is configured -- see supported_checks().
    "wazuh_vulnerability_patching",
]

DEFAULT_CONTROL_TITLES = {
    "wazuh_agent_connectivity": "Endpoint Detection & Response",
    "wazuh_sca_compliance":     "Secure Configuration Baseline",
    "wazuh_vulnerability_patching": "Vulnerability & Patch Management",
}

# SCA compliance pulls one request per active agent; cap how many we walk
# per run so a large fleet doesn't turn one check into hundreds of
# sequential requests against the manager.
MAX_AGENTS_PER_SCA_SWEEP = 50

# Vulnerability findings ingested from the indexer, by default -- see the
# module docstring's "Indexer-backed vulnerability detection" section.
DEFAULT_MIN_VULNERABILITY_SEVERITIES = {"Critical", "High"}

# A hard ceiling on how many indexer hits one run processes, independent of
# the severity filter above -- belt-and-suspenders against a single sweep
# turning into an enormous Neo4j write burst on a fleet with a LOT of
# findings.
MAX_VULNERABILITIES_PER_RUN = 500

# Device inventory (Wazuh's syscollector: hardware, OS detail, network
# interfaces, listening ports, package/hotfix counts) costs a handful of
# requests per agent, so it's capped like the SCA sweep. Turn it off per
# tenant with config["collect_inventory"] = False.
MAX_AGENTS_PER_INVENTORY = 50
# Failed SCA checks fetched per policy for the device profile -- the top of
# the list, not the whole benchmark (the Wazuh dashboard has the rest).
MAX_FAILED_CHECKS_PER_POLICY = 10

# ── Endpoint protection detection ────────────────────────────────────────
# Wazuh itself isn't an antivirus, so "the agent is reporting" says nothing
# about whether a device is protected. These tables let the device profile
# (and the EDR check) say what protection is actually present, from data
# syscollector already collects:
#
#   * a running process -- the strongest evidence: the engine is running
#     right now (it does NOT prove signatures are current or how well it
#     would stop an attack);
#   * an installed package -- the product is on the device, but may not be
#     running;
#   * Microsoft Defender's CIS policy checks (Windows) -- whether real-time
#     protection etc. is enforced by policy.
#
# process name (lowercase) -> (product, kind)
PROTECTION_PROCESSES: dict[str, tuple[str, str]] = {
    # Windows
    "msmpeng.exe":          ("Microsoft Defender Antivirus", "Antivirus"),
    # Defender companions. MsMpEng itself is a protected process, which
    # Wazuh's inventory can't open on some machines, so it may be missing
    # from the list while these (which only run alongside it) are present.
    "mpdefendercoreservice.exe": ("Microsoft Defender Antivirus", "Antivirus"),
    "nissrv.exe":           ("Microsoft Defender Antivirus", "Antivirus"),
    "defendersessionhelper.exe": ("Microsoft Defender Antivirus", "Antivirus"),
    "mssense.exe":          ("Microsoft Defender for Endpoint", "EDR"),
    "csfalconservice.exe":  ("CrowdStrike Falcon", "EDR"),
    "sentinelagent.exe":    ("SentinelOne", "EDR"),
    "cylancesvc.exe":       ("Cylance", "EDR"),
    "repmgr.exe":           ("VMware Carbon Black", "EDR"),
    "xagt.exe":             ("Trellix Endpoint Security (HX)", "EDR"),
    "ekrn.exe":             ("ESET", "Antivirus"),
    "avp.exe":              ("Kaspersky", "Antivirus"),
    "vsserv.exe":           ("Bitdefender", "Antivirus"),
    "bdservicehost.exe":    ("Bitdefender", "Antivirus"),
    "savservice.exe":       ("Sophos", "Antivirus"),
    "sophoshealth.exe":     ("Sophos", "Antivirus"),
    "ccsvchst.exe":         ("Symantec / Norton", "Antivirus"),
    "mcshield.exe":         ("McAfee / Trellix", "Antivirus"),
    "mfemms.exe":           ("McAfee / Trellix", "Antivirus"),
    "avastsvc.exe":         ("Avast", "Antivirus"),
    "avgsvc.exe":           ("AVG", "Antivirus"),
    "mbamservice.exe":      ("Malwarebytes", "Antivirus"),
    "ntrtscan.exe":         ("Trend Micro", "Antivirus"),
    "wrsa.exe":             ("Webroot", "Antivirus"),
    # Linux / macOS
    "falcon-sensor":        ("CrowdStrike Falcon", "EDR"),
    "falcond":              ("CrowdStrike Falcon", "EDR"),
    "wdavdaemon":           ("Microsoft Defender for Endpoint", "EDR"),
    "s1-agent":             ("SentinelOne", "EDR"),
    "sentineld":            ("SentinelOne", "EDR"),
    "esets_daemon":         ("ESET", "Antivirus"),
    "clamd":                ("ClamAV", "Antivirus"),
}

# Core Windows processes that are always running and, like antivirus
# engines, protected. When none of them is in a Windows device's process
# list, the inventory can't see protected processes at all -- so "no
# antivirus process seen" proves nothing and must not count as "not running".
WINDOWS_PROTECTED_CORE = frozenset({"csrss.exe", "services.exe", "smss.exe"})

# Installed-package names that mean a protection product is on the device.
# Whole-word patterns, so e.g. "ESET" doesn't match "reset".
PROTECTION_PACKAGES: tuple[tuple[str, str], ...] = (
    (r"\bcrowdstrike\b", "CrowdStrike Falcon"),
    (r"\bsentinel ?one\b|\bsentinel agent\b", "SentinelOne"),
    (r"\bcylance", "Cylance"),
    (r"\bcarbon black\b", "VMware Carbon Black"),
    (r"\beset\b", "ESET"),
    (r"\bkaspersky\b", "Kaspersky"),
    (r"\bbitdefender\b", "Bitdefender"),
    (r"\bsophos\b", "Sophos"),
    (r"\bnorton\b|\bsymantec endpoint\b", "Symantec / Norton"),
    (r"\bmcafee\b|\btrellix\b", "McAfee / Trellix"),
    (r"\bavast\b", "Avast"),
    (r"\bavg (antivirus|internet security)\b", "AVG"),
    (r"\bmalwarebytes\b", "Malwarebytes"),
    (r"\btrend micro\b", "Trend Micro"),
    (r"\bwebroot\b", "Webroot"),
    (r"\bclamav\b", "ClamAV"),
    (r"\bmicrosoft defender for endpoint\b|\bmdatp\b", "Microsoft Defender for Endpoint"),
)

# Vulnerability patching: how much one open finding of each severity counts
# toward the patch-management load (Critical ≈ 10 Mediums), and the smallest
# baseline per device so a handful of findings isn't scored as 0%.
PATCH_SEVERITY_WEIGHTS = {"Critical": 10.0, "High": 4.0, "Medium": 1.0, "Low": 0.25}
PATCH_FLOOR_PER_DEVICE = 20.0

# Processes / packages fetched per agent for the check above. Generous --
# a busy Windows laptop runs a few hundred processes.
MAX_PROCESSES_PER_AGENT = 1000
MAX_PACKAGES_PER_AGENT = 2000
MAX_DEFENDER_POLICY_GAPS = 5

# Markers detect_protection adds for the EDR check; never stored.
_INTERNAL_PROFILE_KEYS = frozenset({"running", "running_products"})

_AGENT_STATUS_LABELS = {
    "active": "online",
    "disconnected": "offline",
    "never_connected": "never connected",
    "pending": "pending",
}


class WazuhAdapter(BaseConnector):
    CONNECTOR_ID   = "wazuh"
    CONNECTOR_NAME = "Wazuh"
    REQUIRED_CONFIG_KEYS = ["api_url", "username", "password"]
    # What this connector can tell GraphRisk about each device (see
    # connectors/profile.py). Hardware/network/software need syscollector;
    # vulnerabilities need the indexer credentials.
    PROFILE_SECTIONS = ("identity", "health", "os", "hardware", "network",
                        "software", "vulnerabilities", "configuration", "protection")

    def authenticate(self) -> None:
        base_url = self.config["api_url"].rstrip("/")
        auth_url = f"{base_url}/security/user/authenticate"
        # Self-hosted by design: a real customer's manager legitimately
        # lives on a private network, so private ranges are allowed here --
        # but loopback/link-local/metadata/reserved/CGNAT are still always
        # rejected by _assert_safe_url regardless of allow_private.
        _assert_safe_url(auth_url, allow_private=True)
        # Self-hosted managers commonly run a self-signed cert (default
        # in most Wazuh installs); verify_ssl defaults to True and has to
        # be explicitly opted out per-tenant, never hardcoded off.
        verify = self.config.get("verify_ssl", True)
        r = self._session.post(
            auth_url,
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
        full_url = f"{base_url}{path}"
        # Same allow_private reasoning as authenticate() above.
        _assert_safe_url(full_url, allow_private=True)
        verify = self.config.get("verify_ssl", True)
        headers = {"Authorization": f"Bearer {self._token}"}
        r = self._session.get(full_url, headers=headers, params=params, verify=verify, timeout=30)
        if r.status_code == 401:
            self.authenticate()
            headers = {"Authorization": f"Bearer {self._token}"}
            r = self._session.get(full_url, headers=headers, params=params, verify=verify, timeout=30)
        r.raise_for_status()
        return r.json()

    def _effective_indexer_url(self) -> str | None:
        """
        Returns None when vulnerability detection isn't configured at all
        (no indexer_username/indexer_password set) -- the caller uses this
        as the feature's on/off switch, not just a URL lookup.

        When it *is* configured, config["indexer_url"] is optional: most
        self-hosted installs run manager, indexer, and dashboard on one
        box, just on different ports, so the common case is deriving the
        indexer's address from the manager's own api_url (same scheme and
        host, port 9200 -- the indexer's default) rather than making a
        tenant type out a second URL that's usually identical apart from
        the port. An explicit indexer_url always wins, for the real
        multi-node deployments where that assumption doesn't hold.
        """
        if not (self.config.get("indexer_username") and self.config.get("indexer_password")):
            return None
        explicit = self.config.get("indexer_url")
        if explicit:
            return explicit.rstrip("/")
        manager = urlsplit(self.config["api_url"])
        return urlunsplit((manager.scheme, f"{manager.hostname}:9200", "", "", ""))

    def _indexer_search(self, index_pattern: str, body: dict) -> dict:
        """
        A single OpenSearch _search call against the Wazuh indexer -- a
        genuinely separate service from the manager (default port 9200,
        its own Basic-auth credentials), not something BaseConnector's
        Bearer-JWT helpers apply to. See the module docstring's
        "Indexer-backed vulnerability detection" section.
        """
        base_url = self._effective_indexer_url()
        full_url = f"{base_url}/{index_pattern}/_search"
        # Same allow_private reasoning as authenticate()/_wazuh_get() above
        # -- a real customer's indexer legitimately lives on a private
        # network too.
        _assert_safe_url(full_url, allow_private=True)
        verify = self.config.get("verify_ssl", True)
        r = self._session.post(
            full_url,
            json=body,
            auth=(self.config["indexer_username"], self.config["indexer_password"]),
            verify=verify,
            timeout=30,
        )
        r.raise_for_status()
        return r.json()

    def _min_vulnerability_severities(self) -> set[str]:
        return set(self.config.get("vulnerability_severities", DEFAULT_MIN_VULNERABILITY_SEVERITIES))

    def _fetch_vulnerabilities(self, agent_ids: list[str]) -> dict[str, list[dict]]:
        """
        Real per-device CVE findings from wazuh-states-vulnerabilities-*,
        grouped by agent id, filtered to this tenant's configured minimum
        severity (Critical/High by default) and capped at
        MAX_VULNERABILITIES_PER_RUN hits total. Each finding comes back in
        the dict shape CheckRegistry._ingest_assets uses to create a real
        Vulnerability node when one doesn't already exist -- see that
        method's docstring and MERGE_VULNERABILITY_FROM_FINDING.

        Returns {} (not an exception) for anything short of a malformed
        config -- an indexer that's down, unreachable, or has no matching
        index yet shouldn't break the agent connectivity check itself, only
        mean this run's assets carry no vulnerabilities. The caller decides
        how much to log; this only fetches and shapes the data.
        """
        if not agent_ids:
            return {}
        severities = self._min_vulnerability_severities()
        resp = self._indexer_search("wazuh-states-vulnerabilities-*", {
            "size": MAX_VULNERABILITIES_PER_RUN,
            "_source": [
                "agent.id", "vulnerability.id", "vulnerability.severity",
                "vulnerability.score.base", "vulnerability.description",
                "vulnerability.published_at", "vulnerability.scanner.source",
                "package.name", "package.version",
            ],
            "query": {
                "bool": {
                    "filter": [
                        {"terms": {"agent.id": agent_ids}},
                        {"terms": {"vulnerability.severity": sorted(severities)}},
                    ]
                }
            },
        })

        by_agent: dict[str, list[dict]] = {}
        for hit in resp.get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            agent_id = (src.get("agent") or {}).get("id")
            vuln = src.get("vulnerability") or {}
            cve_id = vuln.get("id")
            if not agent_id or not cve_id:
                continue
            scanner_source = (vuln.get("scanner") or {}).get("source", "")
            entry = {
                "cve_id": cve_id,
                "severity": vuln.get("severity", "Unknown"),
                "cvss_score": (vuln.get("score") or {}).get("base", 0.0),
                # Matches data-ingestion/ingest/07_nvd_cve.py's own [:600]
                # truncation of NVD descriptions -- same reasoning applies
                # here (some of these, e.g. GHSA writeups, run very long).
                "description": (vuln.get("description") or "")[:600],
                "published_at": vuln.get("published_at", ""),
                "source": f"Wazuh ({scanner_source})" if scanner_source else "Wazuh",
            }
            # Which installed software the finding is in -- what the asset
            # page groups CVEs by ("update WinRAR" rather than two CVE ids).
            package = src.get("package") or {}
            if package.get("name"):
                entry["package"] = {"name": package.get("name"), "version": package.get("version")}
            by_agent.setdefault(agent_id, []).append(entry)
        return by_agent

    def _fetch_severity_counts(self, agent_ids: list[str]) -> dict[str, dict[str, int]]:
        """
        Findings per agent per severity, across *all* severities -- the
        ingested list above is filtered to Critical/High, but the device
        profile should show the real totals. One aggregation request, no
        documents returned. {} on anything unexpected.
        """
        if not agent_ids:
            return {}
        resp = self._indexer_search("wazuh-states-vulnerabilities-*", {
            "size": 0,
            "query": {"terms": {"agent.id": agent_ids}},
            "aggs": {"by_agent": {
                "terms": {"field": "agent.id", "size": len(agent_ids)},
                "aggs": {"by_severity": {"terms": {"field": "vulnerability.severity", "size": 10}}},
            }},
        })
        out: dict[str, dict[str, int]] = {}
        buckets = (((resp.get("aggregations") or {}).get("by_agent") or {}).get("buckets")) or []
        for b in buckets:
            sev = {s.get("key"): s.get("doc_count", 0)
                   for s in ((b.get("by_severity") or {}).get("buckets") or []) if s.get("key")}
            if b.get("key"):
                out[str(b["key"])] = sev
        return out

    def _fetch_inventory(self, agent_id: str, platform: str | None = None) -> dict | None:
        """
        Device detail from Wazuh's syscollector inventory, as partial
        profile sections. Each request is independent -- one failing (an
        older manager, the module disabled on that agent) only drops that
        part. Returns None when *every* request failed, which the caller
        treats as "syscollector isn't available on this manager".
        """
        succeeded = 0

        def get(path: str, params: dict | None = None) -> dict | None:
            nonlocal succeeded
            try:
                data = self._wazuh_get(f"/syscollector/{agent_id}/{path}", params=params).get("data") or {}
                succeeded += 1
                return data
            except Exception as e:
                logger.debug(f"Wazuh syscollector {path} for agent {agent_id} unavailable: {e}")
                return None

        def first(data: dict | None) -> dict:
            items = (data or {}).get("affected_items") or []
            return items[0] if items else {}

        prof: dict[str, dict] = {}
        hw = first(get("hardware"))
        if hw:
            cpu = hw.get("cpu") or {}
            ram = hw.get("ram") or {}
            prof["hardware"] = {
                "cpu": cpu.get("name"),
                "cpu_cores": cpu.get("cores"),
                "memory_total_mb": round(ram["total"] / 1024) if isinstance(ram.get("total"), (int, float)) else None,
                "memory_used_percent": ram.get("usage"),
            }
            serial = str(hw.get("board_serial") or "").strip()
            if serial and serial.lower() not in ("none", "not specified", "default string", "to be filled by o.e.m."):
                prof["identity"] = {"serial_number": serial}

        os_item = first(get("os"))
        if os_item:
            os_info = os_item.get("os") or {}
            prof["os"] = {"kernel": os_item.get("release"), "build": os_info.get("build")}

        ifaces = (get("netiface", {"limit": 20}) or {}).get("affected_items") or []
        macs = sorted({i.get("mac") for i in ifaces
                       if i.get("mac") and i.get("mac") not in ("00:00:00:00:00:00",)})
        ports_data = get("ports", {"limit": 25, "q": "state=listening"}) or {}
        ports = []
        for p in ports_data.get("affected_items") or []:
            local = p.get("local") or {}
            if local.get("port") is not None:
                ports.append({"port": local.get("port"), "protocol": p.get("protocol"),
                              "process": p.get("process")})
        if macs or ports:
            prof["network"] = {"mac_addresses": macs, "listening_ports": ports}

        # Names too (not just the count): installed security products show
        # up here even when they aren't running.
        packages = get("packages", {"limit": MAX_PACKAGES_PER_AGENT, "select": "name"})
        if packages is None:
            # Older managers may reject "select" -- still get the count.
            packages = get("packages", {"limit": 1})
        hotfixes = get("hotfixes", {"limit": 10})
        software = {}
        if packages is not None:
            software["installed_count"] = packages.get("total_affected_items")
        if hotfixes is not None:
            software["hotfixes_count"] = hotfixes.get("total_affected_items")
            software["recent_hotfixes"] = [h.get("hotfix") for h in hotfixes.get("affected_items") or [] if h.get("hotfix")]
        if software:
            prof["software"] = software

        processes = get("processes", {"limit": MAX_PROCESSES_PER_AGENT, "select": "name"})
        process_names = None if processes is None else {
            str(p.get("name")).strip().lower()
            for p in processes.get("affected_items") or [] if p.get("name")
        }
        package_names = None if packages is None else [
            str(p.get("name")) for p in packages.get("affected_items") or [] if p.get("name")
        ]
        defender = self._defender_policy(agent_id) if (platform or "").lower() == "windows" else None
        protection = detect_protection(process_names, package_names, defender, platform=platform)
        if protection:
            prof["protection"] = protection

        return prof if succeeded else None

    def _defender_policy(self, agent_id: str) -> dict | None:
        """Microsoft Defender settings from the agent's CIS benchmark: how
        many Defender-related checks pass (real-time protection, behaviour
        monitoring, ...), and the titles of a few that fail. None when SCA
        has nothing on Defender for this agent, or isn't available."""
        try:
            policies = (self._wazuh_get(f"/sca/{agent_id}").get("data") or {}).get("affected_items") or []
        except Exception as e:
            logger.debug(f"Wazuh SCA policies for agent {agent_id} unavailable: {e}")
            return None
        passed, failed, gaps = 0, 0, []
        for policy in policies:
            policy_id = policy.get("policy_id")
            if not policy_id:
                continue
            try:
                data = self._wazuh_get(f"/sca/{agent_id}/checks/{policy_id}",
                                       params={"search": "Defender", "limit": 200})
            except Exception as e:
                logger.debug(f"Wazuh Defender checks for agent {agent_id}/{policy_id} unavailable: {e}")
                continue
            for c in (data.get("data") or {}).get("affected_items") or []:
                title = str(c.get("title") or "")
                if "defender" not in title.lower():
                    continue
                result = str(c.get("result") or "").lower()
                if result == "passed":
                    passed += 1
                elif result == "failed":
                    failed += 1
                    gaps.append(title)
        if passed + failed == 0:
            return None
        return {"passed": passed, "failed": failed, "gaps": gaps[:MAX_DEFENDER_POLICY_GAPS]}

    def _agent_profile(self, agent: dict, vulns: list[dict], severity_counts: dict | None,
                       inventory: dict | None) -> dict:
        """One agent, mapped onto the universal device profile."""
        os_info = agent.get("os") or {}
        last_seen = agent.get("lastKeepAlive")
        if last_seen and str(last_seen).startswith("9999"):
            last_seen = None  # Wazuh's placeholder for "never connected"
        ips = []
        for ip in (agent.get("ip"), agent.get("registerIP")):
            if ip and ip.lower() != "any" and ip not in ips:
                ips.append(ip)
        groups = agent.get("group")
        profile: dict[str, dict] = {
            "identity": {
                "hostname": agent.get("name"),
                "device_type": "Endpoint",
                "agent_id": agent.get("id"),
                "groups": groups if isinstance(groups, list) else ([groups] if groups else None),
            },
            "health": {
                "status": _AGENT_STATUS_LABELS.get(agent.get("status"), agent.get("status")),
                "last_seen": last_seen,
                "enrolled_at": agent.get("dateAdd"),
                "agent_version": agent.get("version"),
            },
            "os": {
                "name": os_info.get("name"),
                "version": os_info.get("version"),
                "platform": os_info.get("platform"),
                "architecture": os_info.get("arch"),
            },
            "network": {"ip_addresses": ips},
        }
        for section, fields in (inventory or {}).items():
            profile.setdefault(section, {}).update({
                k: v for k, v in fields.items()
                if v is not None and k not in _INTERNAL_PROFILE_KEYS
            })
        packages = group_vulnerable_packages(vulns)
        if packages:
            profile.setdefault("software", {})["vulnerable_packages"] = packages
        if severity_counts:
            profile["vulnerabilities"] = {
                "counts_by_severity": severity_counts,
                "total": sum(severity_counts.values()),
                "scanner": "Wazuh vulnerability detection",
            }
        return profile

    def _failed_sca_checks(self, agent_id: str, policy_id: str | None) -> list[dict]:
        """The first few failed checks of one SCA policy, with Wazuh's own
        remediation text. [] if the policy id is missing or the request fails
        -- the benchmark score is still useful without them."""
        if not policy_id:
            return []
        try:
            data = self._wazuh_get(
                f"/sca/{agent_id}/checks/{policy_id}",
                params={"result": "failed", "limit": MAX_FAILED_CHECKS_PER_POLICY},
            )
        except Exception as e:
            logger.debug(f"Wazuh failed SCA checks for agent {agent_id}/{policy_id} unavailable: {e}")
            return []
        return [
            {"title": c.get("title"), "remediation": c.get("remediation")}
            for c in (data.get("data") or {}).get("affected_items") or []
            if c.get("title")
        ]

    def _control_title(self, check_id: str) -> str:
        return self.config.get("control_titles", {}).get(check_id, DEFAULT_CONTROL_TITLES[check_id])

    def supported_checks(self) -> list[str]:
        # The patching check needs the indexer's vulnerability data; without
        # it there's nothing to measure, and running it would write a
        # misleading 0% to the patch-management control.
        if self._effective_indexer_url():
            return list(SUPPORTED_CHECKS)
        return [c for c in SUPPORTED_CHECKS if c != "wazuh_vulnerability_patching"]

    def run_check(self, check_id: str) -> CheckResult:
        self._ensure_token()
        dispatch = {
            "wazuh_agent_connectivity": self._check_agent_connectivity,
            "wazuh_sca_compliance":     self._check_sca_compliance,
            "wazuh_vulnerability_patching": self._check_vulnerability_patching,
        }
        if check_id not in dispatch:
            raise ValueError(f"Unknown check for WazuhAdapter: {check_id}")
        return dispatch[check_id]()

    # ── Individual checks ────────────────────────────────────────────────────
    # Wazuh's own default OS platform strings, mapped to the vendor/product
    # pairs CORRELATE_NEW_ASSET_AGAINST_ALL_VULNERABILITIES actually matches
    # against real CVE data (see api/v1/assets.py's AssetCreate comment) --
    # left unset for anything unrecognised rather than guessing.
    _OS_PLATFORM_TO_VENDOR_PRODUCT = {
        "windows": ("Microsoft", "Windows"),
    }

    def _agent_to_asset(self, agent: dict) -> dict:
        """One discovered_assets entry per Wazuh-monitored endpoint."""
        os_info = agent.get("os") or {}
        vendor, product = self._OS_PLATFORM_TO_VENDOR_PRODUCT.get(
            (os_info.get("platform") or "").lower(), (None, None)
        )
        return {
            "name": agent.get("name") or f"Wazuh Agent {agent.get('id')}",
            "asset_type": "Endpoint",
            "criticality": "Medium",
            "environment": "Production",
            "vendor": vendor,
            "product": product,
        }

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

        inventory: dict[str, dict] = {}
        if self.config.get("collect_inventory", True):
            for a in agents[:MAX_AGENTS_PER_INVENTORY]:
                inv = self._fetch_inventory(a.get("id"), (a.get("os") or {}).get("platform"))
                if inv is None and not inventory:
                    # Nothing at all came back for the first agent -- the
                    # manager doesn't expose syscollector; don't repeat
                    # the same failing requests for every other agent.
                    logger.info("Wazuh syscollector unavailable -- skipping device inventory this run")
                    break
                if inv:
                    inventory[a.get("id")] = inv

        vulns_by_agent: dict[str, list[dict]] = {}
        severity_counts: dict[str, dict[str, int]] = {}
        if self._effective_indexer_url():
            try:
                severity_counts = self._fetch_severity_counts([a.get("id") for a in agents])
            except Exception as e:
                logger.warning(f"Wazuh indexer severity counts unavailable, continuing without them: {e}")
            try:
                vulns_by_agent = self._fetch_vulnerabilities([a.get("id") for a in agents])
            except Exception as e:
                # Deliberately broad -- bad indexer creds, unreachable host,
                # a manager that isn't on 4.8+, a missing index... all of
                # these should degrade to "no vulnerability data this run,"
                # never break agent connectivity itself.
                logger.warning(f"Wazuh indexer vulnerability fetch failed, continuing without it: {e}")

        # Score: a device counts as covered when its agent is reporting AND
        # an antivirus/EDR process is running on it. Where the running
        # processes couldn't be read (syscollector off or unavailable) the
        # device falls back to "reporting" only -- the detail line says how
        # many that applies to, so the number is never quietly overstated.
        covered = 0
        protected, unprotected, unchecked = 0, 0, 0
        products: set[str] = set()
        for a in agents:
            if a.get("status") != "active":
                continue
            prot = (inventory.get(a.get("id")) or {}).get("protection") or {}
            verified = prot.get("running")
            if verified is True:
                protected += 1
                covered += 1
                products.update(prot.get("running_products") or [])
            elif verified is False:
                unprotected += 1
            else:
                unchecked += 1
                covered += 1
        score = round(covered / total, 4) if total > 0 else 0.0

        detail = f"{active} of {total} registered agents reporting"
        if protected or unprotected:
            detail += (f"; antivirus/EDR running on {protected} of {protected + unprotected} checked"
                       + (f" ({', '.join(sorted(products))})" if products else ""))
        if unchecked and (protected or unprotected):
            detail += f"; {unchecked} couldn't be checked for antivirus (counted as reporting only)"
        elif unchecked:
            detail += " (couldn't confirm antivirus from the running processes, so it wasn't checked)"

        discovered_assets = []
        for a in agents:
            asset = self._agent_to_asset(a)
            agent_vulns = vulns_by_agent.get(a.get("id"))
            if agent_vulns:
                asset["vulnerabilities"] = agent_vulns
            asset["profile"] = self._agent_profile(
                a, agent_vulns or [], severity_counts.get(a.get("id")), inventory.get(a.get("id")))
            discovered_assets.append(asset)

        return CheckResult(
            discovered_assets=discovered_assets,
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
            affected_count=total - covered,
            total_count=total,
            detail=detail,
            control_title=self._control_title("wazuh_agent_connectivity"),
        )

    def _check_vulnerability_patching(self) -> CheckResult:
        """
        Patch management, measured: the share of scanned devices with no
        open Critical or High vulnerability findings, from the indexer's
        per-device severity counts. Feeds "Vulnerability & Patch
        Management", so patching (and re-scanning) visibly lowers every risk
        that control mitigates. Raises rather than scoring 0 when there's no
        scan data at all, so a missing scan never reads as "unpatched".
        """
        if not self._effective_indexer_url():
            raise RuntimeError("Vulnerability patching needs the Wazuh indexer configured")
        data = self._wazuh_get("/agents", params={"limit": 500, "status": "active"})
        agents = [a for a in data.get("data", {}).get("affected_items", []) if a.get("id") != "000"]
        counts = self._fetch_severity_counts([a.get("id") for a in agents]) if agents else {}
        scanned = [a for a in agents if a.get("id") in counts]
        if not scanned:
            raise RuntimeError("No vulnerability scan results in the indexer for any active agent yet")

        def serious(agent_id: str) -> int:
            sev = counts.get(agent_id) or {}
            return int(sev.get("Critical", 0)) + int(sev.get("High", 0))

        def total_of(severity: str) -> int:
            return sum(int((counts.get(a.get("id")) or {}).get(severity, 0)) for a in scanned)

        clean = sum(1 for a in scanned if serious(a.get("id")) == 0)
        total = len(scanned)
        by_sev = {s: total_of(s) for s in ("Critical", "High", "Medium", "Low")}
        # Every open finding counts, weighted by severity, so each one fixed
        # moves the score -- CheckRegistry turns this into progress against
        # the worst load seen (see _apply_progress). Until then, a
        # no-history estimate.
        open_weight = sum(PATCH_SEVERITY_WEIGHTS[s] * n for s, n in by_sev.items())
        baseline = max(open_weight, PATCH_FLOOR_PER_DEVICE * total)
        score = round(1.0 - open_weight / baseline, 4) if baseline else 1.0
        return CheckResult(
            check_id="wazuh_vulnerability_patching",
            check_name="Wazuh Vulnerability Patching",
            category=CheckCategory.ENDPOINT,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=(
                CheckStatus.PASS if score >= 0.95 else
                CheckStatus.WARNING if score >= 0.80 else
                CheckStatus.FAIL
            ),
            score=score,
            affected_count=total - clean,
            total_count=total,
            detail=(f"{by_sev['Critical']} critical, {by_sev['High']} high, {by_sev['Medium']} medium and "
                    f"{by_sev['Low']} low findings open across {total} scanned device{'s' if total != 1 else ''}; "
                    f"{clean} with no Critical or High"),
            control_title=self._control_title("wazuh_vulnerability_patching"),
            raw_data={"progress": {"open_weight": open_weight, "devices": total}},
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
        total_fail = 0
        total_not_applicable = 0
        agents_with_data = 0
        profiles = []
        for agent in agents:
            sca = self._wazuh_get(f"/sca/{agent['id']}")
            policies = sca.get("data", {}).get("affected_items", [])
            if policies:
                agents_with_data += 1
            benchmarks = []
            for policy in policies:
                passed = policy.get("pass") or 0
                total = policy.get("total_checks") or 0
                failed_n = policy.get("fail")
                if failed_n is None:
                    failed_n = max(total - passed, 0)
                # Wazuh also reports checks that don't apply to the device.
                # Like Wazuh's own score, count only applicable checks, so the
                # run message and the device page show the same numbers.
                total_pass += passed
                total_fail += failed_n
                total_not_applicable += max(total - passed - failed_n, 0)
                benchmarks.append({
                    "name": policy.get("name") or policy.get("policy_id"),
                    "score": policy.get("score"),
                    "passed": policy.get("pass"),
                    "failed": policy.get("fail"),
                    "total": policy.get("total_checks"),
                    "scanned_at": policy.get("end_scan"),
                    "failed_checks": self._failed_sca_checks(agent["id"], policy.get("policy_id")),
                })
            if benchmarks:
                # Detail for the device page only -- this check doesn't
                # discover devices, so it never creates an asset.
                profiles.append({
                    "name": self._agent_to_asset(agent)["name"],
                    "profile_only": True,
                    "profile": {"configuration": {"benchmarks": benchmarks}},
                })

        total_checks = total_pass + total_fail
        score = round(total_pass / total_checks, 4) if total_checks > 0 else 0.0
        failed = total_fail

        return CheckResult(
            discovered_assets=profiles,
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
                f"{failed} of {total_checks} applicable SCA checks failing across "
                f"{agents_with_data} of {len(agents)} active agents with SCA data"
                + (f" ({total_not_applicable} not applicable)" if total_not_applicable else "")
                if total_checks > 0 else
                f"No SCA policy data returned for {len(agents)} active agents "
                "-- confirm the SCA module is enabled on these agents"
            ),
            control_title=self._control_title("wazuh_sca_compliance"),
        )


def detect_protection(process_names: set[str] | None, package_names: list[str] | None,
                      defender_policy: dict | None = None, platform: str | None = None) -> dict | None:
    """
    What endpoint protection is present on one device, as the profile's
    "protection" section. Pure function over data syscollector already
    returns, so it's easy to test and reason about.

    ``running`` / ``running_products`` are internal markers for the EDR
    check (True: a protection process is running; False: processes were
    read and none is; absent: processes unknown, or -- on Windows -- the
    list visibly lacks protected processes, so an antivirus engine could be
    running unseen). _agent_profile leaves
    them out of the stored profile -- they're never shown on the page.

    Returns None when there's no evidence either way (nothing could be read).
    """
    if process_names is None and package_names is None and defender_policy is None:
        return None

    running: dict[str, tuple[str, str]] = {}
    for proc in sorted(process_names or ()):
        hit = PROTECTION_PROCESSES.get(proc)
        if hit and hit[0] not in running:
            running[hit[0]] = (hit[1], proc)

    # Can the process list rule an antivirus out? Not if it's unknown, and
    # not on a Windows device whose list is missing every protected core
    # process -- the engine would be hidden the same way.
    hidden = (process_names is not None and (platform or "").lower() == "windows"
              and not (process_names & WINDOWS_PROTECTED_CORE))
    can_rule_out = process_names is not None and not hidden

    installed: list[str] = []
    for pkg in package_names or ():
        for pattern, product in PROTECTION_PACKAGES:
            if re.search(pattern, pkg, re.IGNORECASE):
                if product not in running and product not in installed:
                    installed.append(product)
                break

    detected = [f"{product} ({kind}) — running ({proc})" for product, (kind, proc) in running.items()]
    detected += [
        f"{product} — installed, not seen running" if can_rule_out
        else f"{product} — installed (couldn't check whether it's running)"
        for product in installed
    ]

    if running:
        status = "Active"
    elif installed:
        status = "Installed, not seen running" if can_rule_out else "Installed"
    elif can_rule_out:
        status = "Not detected"
    elif hidden:
        status = "Not confirmed"
    else:
        status = None

    section: dict = {}
    if status:
        section["status"] = status
    if running or installed:
        section["product"] = ", ".join(list(running) + installed)
    if detected:
        section["detected"] = detected
    if defender_policy:
        checked = defender_policy["passed"] + defender_policy["failed"]
        section["policy"] = (f"Microsoft Defender settings: {defender_policy['passed']} of {checked} "
                             "CIS benchmark checks pass")
        if defender_policy.get("gaps"):
            section["policy_gaps"] = list(defender_policy["gaps"])
    if hidden and not running:
        section["note"] = ("Wazuh can't see Windows protected processes on this device, so a "
                           "running antivirus may not show up here.")
    if running or can_rule_out:
        section["running"] = bool(running)
        section["running_products"] = list(running)
    return section or None
