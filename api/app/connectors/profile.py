"""
The universal device profile -- the vendor-neutral shape every connector
maps its own device data onto, so the asset page (and anything else that
reads device detail) never needs vendor-specific logic.

How it fits together:

- Each adapter declares which sections it can fill in
  ``BaseConnector.PROFILE_SECTIONS`` (its *capability*), and attaches a
  ``"profile"`` dict -- ``{section: {field: value}}`` -- to each
  discovered_assets entry it reports (see CheckResult.discovered_assets).
- CheckRegistry runs every profile through :func:`normalize_profile`
  (known sections/fields only, lists capped, strings trimmed) and stores
  one snapshot per (asset, connector, section), so a later run of the same
  connector replaces its own data without touching another connector's.
- The assets API merges those snapshots per section with
  :func:`merge_sections` (newest value per field wins, each field keeps
  its source) and hides :data:`SENSITIVE_FIELDS` from anyone who isn't an
  owner/admin.

Adding a connector means mapping its data onto these sections -- nothing in
storage, the API or the UI changes. Fields an adapter reports that aren't in
the schema are kept under ``extra`` (shown as plain key/value pairs) rather
than dropped, so vendor-specific detail is never silently lost.
"""
from __future__ import annotations

import json
from typing import Any

# section -> the fields it may contain. Every field is optional.
SECTIONS: dict[str, tuple[str, ...]] = {
    "identity": ("hostname", "device_type", "manufacturer", "model", "serial_number",
                 "agent_id", "cloud_instance_id", "groups"),
    "health": ("status", "last_seen", "enrolled_at", "agent_version"),
    "os": ("name", "version", "platform", "architecture", "kernel", "build"),
    "hardware": ("cpu", "cpu_cores", "memory_total_mb", "memory_used_percent"),
    "network": ("ip_addresses", "mac_addresses", "public_ip", "listening_ports"),
    "software": ("installed_count", "vulnerable_packages", "hotfixes_count", "recent_hotfixes"),
    "vulnerabilities": ("counts_by_severity", "total", "scanner", "last_scanned"),
    "configuration": ("benchmarks",),
    "protection": ("status", "product", "detected", "note", "policy", "policy_gaps",
                   "last_detection", "detections_count"),
    "ownership": ("assigned_user", "owner_email", "department", "managed", "compliant"),
    "cloud": ("provider", "region", "account", "instance_type", "security_groups",
              "public_exposure", "tags"),
    "activity": ("alerts_by_level", "recent_alerts", "window"),
}

# Shown only to owners/admins (and never in a read-only/shared tenant).
SENSITIVE_FIELDS: frozenset[str] = frozenset({
    "network.ip_addresses", "network.mac_addresses", "network.public_ip",
    "identity.serial_number", "ownership.assigned_user", "ownership.owner_email",
})

# Per-field list caps; anything not listed gets DEFAULT_LIST_CAP. Keeps one
# chatty connector (hundreds of packages, ports, tags...) from bloating the
# graph -- the profile is a summary, the source tool is the full record.
LIST_CAPS: dict[str, int] = {
    "software.vulnerable_packages": 25,
    "network.listening_ports": 25,
    "configuration.benchmarks": 5,
    "software.recent_hotfixes": 10,
    "activity.recent_alerts": 10,
}
DEFAULT_LIST_CAP = 20
NESTED_LIST_CAP = 10          # e.g. failed_checks inside one benchmark
MAX_STRING = 300
MAX_DEPTH = 4


def _clean(value: Any, list_cap: int = DEFAULT_LIST_CAP, depth: int = 0) -> Any:
    """Recursively trim a value to something small and JSON-safe; returns
    None for anything empty so callers can drop it."""
    if value is None:
        return None
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        v = value.strip()
        return v[:MAX_STRING] if v else None
    if depth >= MAX_DEPTH:
        return None
    if isinstance(value, dict):
        out = {}
        for k, v in list(value.items())[:40]:
            c = _clean(v, NESTED_LIST_CAP, depth + 1)
            if c is not None:
                out[str(k)[:60]] = c
        return out or None
    if isinstance(value, (list, tuple, set)):
        out = [c for c in (_clean(v, NESTED_LIST_CAP, depth + 1) for v in list(value)[:list_cap]) if c is not None]
        return out or None
    return str(value)[:MAX_STRING]


def normalize_profile(raw: dict | None) -> dict[str, dict]:
    """Map an adapter's profile onto the schema: known sections and fields
    are cleaned and kept; anything else is collected under "extra" as
    "section.field" keys. Empty sections are dropped."""
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict] = {}
    extra: dict[str, Any] = {}
    for section, fields in raw.items():
        if not isinstance(fields, dict):
            continue
        allowed = SECTIONS.get(section)
        for field, value in fields.items():
            key = f"{section}.{field}"
            cleaned = _clean(value, LIST_CAPS.get(key, DEFAULT_LIST_CAP))
            if cleaned is None:
                continue
            if allowed is not None and field in allowed:
                out.setdefault(section, {})[field] = cleaned
            else:
                extra[key[:80]] = cleaned
    if extra:
        out["extra"] = dict(list(extra.items())[:30])
    return out


def to_storage(fields: dict) -> str:
    """Neo4j properties can't hold nested maps, so a section is stored as
    one JSON string."""
    return json.dumps(fields, separators=(",", ":"), default=str)


def from_storage(data: str | None) -> dict:
    try:
        v = json.loads(data or "{}")
        return v if isinstance(v, dict) else {}
    except (TypeError, ValueError):
        return {}


def merge_sections(rows: list[dict], source_names: dict[str, str] | None = None) -> dict[str, dict]:
    """
    Merge stored snapshots ({source, section, data, collected_at}) into one
    profile. Per section, sources are applied oldest -> newest, so the most
    recent value of each field wins; every section records which sources
    contributed and which source each field came from.

    Returns {section: {"fields": {...}, "field_sources": {field: source},
    "sources": [{"source", "name", "collected_at"}]}}.
    """
    names = source_names or {}
    by_section: dict[str, list[dict]] = {}
    for r in rows:
        by_section.setdefault(r.get("section") or "extra", []).append(r)

    merged: dict[str, dict] = {}
    for section, items in by_section.items():
        items.sort(key=lambda r: r.get("collected_at") or "")
        fields: dict[str, Any] = {}
        field_sources: dict[str, str] = {}
        sources = []
        for r in items:
            data = r["data"] if isinstance(r.get("data"), dict) else from_storage(r.get("data"))
            for k, v in data.items():
                fields[k] = v
                field_sources[k] = r.get("source")
            sources.append({
                "source": r.get("source"),
                "name": names.get(r.get("source"), r.get("source")),
                "collected_at": r.get("collected_at"),
            })
        if fields:
            merged[section] = {"fields": fields, "field_sources": field_sources, "sources": sources}
    return merged


def mask_sensitive(merged: dict[str, dict]) -> list[str]:
    """Remove SENSITIVE_FIELDS from a merged profile in place; returns the
    "section.field" names that were hidden so the UI can say so."""
    hidden = []
    for key in sorted(SENSITIVE_FIELDS):
        section, field = key.split(".", 1)
        sec = merged.get(section)
        if sec and field in sec["fields"]:
            del sec["fields"][field]
            sec["field_sources"].pop(field, None)
            hidden.append(key)
            if not sec["fields"]:
                del merged[section]
    return hidden


_SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


def severity_label(value) -> str | None:
    """Normalise a vendor's severity ("CRITICAL", "high", ...) to the
    profile's Critical/High/Medium/Low; None if it isn't one of those."""
    v = str(value or "").strip().capitalize()
    return v if v in _SEVERITY_RANK else None


def group_vulnerable_packages(findings: list[dict]) -> list[dict]:
    """
    Group per-device findings by the software they're in -- the shape of
    software.vulnerable_packages. Each finding is a dict with "cve_id",
    optional "severity" and optional "package": {"name", "version"};
    findings without a package name are skipped. Shared by every adapter
    so "what do I patch" looks the same whichever scanner found it.
    """
    groups: dict[tuple, dict] = {}
    for f in findings:
        pkg = f.get("package") or {}
        if not pkg.get("name") or not f.get("cve_id"):
            continue
        g = groups.setdefault((pkg["name"], pkg.get("version")), {
            "name": pkg["name"], "version": pkg.get("version"),
            "cve_ids": [], "max_severity": None,
        })
        if f["cve_id"] not in g["cve_ids"]:
            g["cve_ids"].append(f["cve_id"])
        if _SEVERITY_RANK.get(f.get("severity"), 0) > _SEVERITY_RANK.get(g["max_severity"], 0):
            g["max_severity"] = f.get("severity")
    out = list(groups.values())
    for g in out:
        g["cve_count"] = len(g["cve_ids"])
    out.sort(key=lambda g: (-_SEVERITY_RANK.get(g["max_severity"], 0), -g["cve_count"]))
    return out


# ── Matching one device across connectors (see CheckRegistry._ingest_assets) ──
# Strong identifiers: if two connectors report the same one, it's the same
# physical/virtual machine, so their records are merged into one asset.
# A hostname alone is NOT strong -- two different machines can share one
# ("ubuntu", "DESKTOP-1", a reused name) -- so a hostname-only match is only
# flagged as "possibly the same device" for a person to judge.
STRONG_KEYS = ("serial", "mac", "instance")

_JUNK_SERIALS = {
    "", "0", "none", "null", "n/a", "na", "unknown", "default string", "not specified",
    "to be filled by o.e.m.", "system serial number", "chassis serial number",
    "123456789", "0123456789", "serial", "invalid",
}
# Virtual/VPN adapter vendors whose MACs are shared across many machines
# (or re-generated freely) and so can't identify one device.
_VIRTUAL_MAC_PREFIXES = (
    "00:05:9a",  # Cisco AnyConnect virtual adapter
    "00:50:56", "00:0c:29", "00:1c:14",  # VMware
    "00:15:5d",  # Hyper-V
    "08:00:27", "0a:00:27",  # VirtualBox
    "00:ff:",    # TAP-Windows / OpenVPN
)
_GENERIC_HOSTNAMES = {"localhost", "ubuntu", "debian", "kali", "raspberrypi", "desktop", "laptop", "pc", "host"}


def _norm_mac(value) -> str | None:
    v = str(value or "").strip().lower().replace("-", ":")
    parts = v.split(":")
    if len(parts) != 6 or not all(len(p) == 2 for p in parts):
        return None
    try:
        first = int(parts[0], 16)
    except ValueError:
        return None
    if v in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return None
    if first & 0b10:            # locally administered (randomised, virtual)
        return None
    if v.startswith(_VIRTUAL_MAC_PREFIXES):
        return None
    return v


def hostname_key(value) -> str | None:
    """Short, case-insensitive hostname ("SIMO.corp.local" -> "simo"), or
    None for empty/generic names that say nothing about identity."""
    v = str(value or "").strip().lower().split(".")[0]
    return v if v and v not in _GENERIC_HOSTNAMES else None


def device_keys(raw_profile: dict | None) -> dict[str, list[str]]:
    """The identifiers in a profile that can tie it to one device:
    {"serial": [...], "mac": [...], "instance": [...], "hostname": [...]}."""
    p = raw_profile if isinstance(raw_profile, dict) else {}
    identity = p.get("identity") if isinstance(p.get("identity"), dict) else {}
    network = p.get("network") if isinstance(p.get("network"), dict) else {}
    keys: dict[str, list[str]] = {}
    serial = str(identity.get("serial_number") or "").strip()
    if serial.lower() not in _JUNK_SERIALS and len(serial) >= 4:
        keys["serial"] = [serial.upper()]
    macs = network.get("mac_addresses") or []
    macs = [m for m in (_norm_mac(x) for x in (macs if isinstance(macs, list) else [macs])) if m]
    if macs:
        keys["mac"] = sorted(set(macs))
    instance = str(identity.get("cloud_instance_id") or "").strip()
    if instance:
        keys["instance"] = [instance]
    host = hostname_key(identity.get("hostname"))
    if host:
        keys["hostname"] = [host]
    return keys
