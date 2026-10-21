"""
Sector-specific frameworks: ones that only bind a certain kind of
organisation (a licensed bank, a payment service provider, a designated
critical-infrastructure operator, anyone handling payment card data).

GraphRisk treats every organisation as outside these sectors until it says
otherwise. A sector-specific framework is shown or counted only once its id
is in the organisation's regulatory profile (the same SUBJECT_TO list that
already drives notification clocks). Until then it is left out of blast
radius, the crosswalk, framework adherence and coverage, rather than shown
"for reference" next to frameworks that do apply.

Keyed by Framework.name, the slug every result carries (ids differ, e.g.
CBK_CYBER_BANKS_2017). The UI reads `sector` from GET /frameworks/ to build
its switches, so this is the one place to add a framework to the list.
"""
from app.graph.connection import run_query
from app.graph import queries

SECTOR_FRAMEWORKS: dict[str, dict] = {
    "CBK_CYBER_BANKS": {
        "sector": "Banking",
        "applies_to": "We are a bank licensed by the Central Bank of Kenya",
    },
    "CBK_CYBER_PSP": {
        "sector": "Payment services",
        "applies_to": "We are a payment service provider licensed by the Central Bank of Kenya",
    },
    "KENYA_CMCA_CII": {
        "sector": "Critical infrastructure",
        "applies_to": "We have been designated a Critical Information Infrastructure operator",
    },
    "PCI_DSS": {
        "sector": "Card payments",
        "applies_to": "We store, process or transmit payment card data",
    },
}


def sector_info(name: str | None) -> dict | None:
    """The sector a framework is limited to, or None if it applies to anyone."""
    return SECTOR_FRAMEWORKS.get(name or "")


def is_hidden(name: str | None, switched_on: bool) -> bool:
    """A sector-specific framework stays hidden until the organisation switches it on."""
    return (name or "") in SECTOR_FRAMEWORKS and not switched_on


def profile_framework_names(tenant_id: str) -> set[str]:
    """Names of the frameworks in the organisation's regulatory profile.
    Empty on any error, which keeps sector-specific frameworks hidden."""
    try:
        rows = run_query(queries.GET_REGULATORY_PROFILE, {"tenant_id": tenant_id}) or []
    except Exception:
        return set()
    row = rows[0] if rows else {}
    return {f.get("name") for f in (row.get("frameworks") or []) if isinstance(f, dict) and f.get("name")}


def hidden_summary(names) -> list[dict]:
    """[{framework, sector, applies_to}] for the hidden ones, so a screen can
    say what was left out and how to switch it on."""
    return [{"framework": n, **SECTOR_FRAMEWORKS[n]} for n in sorted(set(names)) if n in SECTOR_FRAMEWORKS]
