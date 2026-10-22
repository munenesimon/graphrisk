"""
Risk acceptance: a recorded decision to live with the findings in one
package on one device until a review date (e.g. a hypervisor that can't be
upgraded yet), with a reason and an owner.

While an acceptance is within its review date, connectors leave that
package's findings out of the device's counts, its recommended actions and
the score, and the device page lists them as accepted. Once the date passes
they count again until someone reviews the decision and saves it again.

Packages are matched the way the asset page merges duplicates (see
_package_key in app/api/v1/assets.py): same letters and digits in the name,
same version. So "ASP.NET Core 8.0.14 - Shared Framework" and "ASP.NET Core
8.0.14 Shared Framework" are one package.
"""
import logging

logger = logging.getLogger(__name__)

# An acceptance is a temporary decision: review it at least once a year.
DEFAULT_ACCEPTANCE_MONTHS = 6
MAX_ACCEPTANCE_MONTHS = 12


def package_key(name, version) -> tuple[str, str]:
    """(letters and digits of the name, lower-cased; version)."""
    letters = "".join(ch for ch in str(name or "").lower() if ch.isalnum())
    return letters, str(version or "").strip()


def load_active(tenant_id: str) -> dict[str, dict[tuple[str, str], dict]]:
    """Acceptances within their review date, by lower-cased device name:
    {device: {package_key: {"package": "Name 1.2", "review_by": "2027-04-22"}}}.
    Empty on any error -- then nothing is held back and every finding counts."""
    from app.graph.connection import run_query
    from app.graph import queries
    try:
        rows = run_query(queries.GET_ACTIVE_RISK_ACCEPTANCES, {"tenant_id": tenant_id}) or []
    except Exception as e:
        logger.warning(f"Couldn't load risk acceptances, counting every finding: {e}")
        return {}
    out: dict[str, dict[tuple[str, str], dict]] = {}
    for r in rows:
        device = str(r.get("asset_name") or "").strip().lower()
        if not device or not r.get("package_name"):
            continue
        out.setdefault(device, {})[package_key(r["package_name"], r.get("package_version"))] = {
            "name": r["package_name"], "version": r.get("package_version") or "",
            "review_by": r.get("review_by"),
        }
    return out


def split_accepted(packages: list, accepted: dict[tuple[str, str], dict] | None) -> tuple[list, list]:
    """(packages still counted, packages accepted) for a list of
    vulnerable-package dicts with "name" and "version"."""
    if not accepted:
        return list(packages or []), []
    keep, held = [], []
    for pkg in packages or []:
        if isinstance(pkg, dict) and package_key(pkg.get("name"), pkg.get("version")) in accepted:
            held.append(pkg)
        else:
            keep.append(pkg)
    return keep, held
