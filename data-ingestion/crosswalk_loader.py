"""
Shared loader for hand-curated regulatory frameworks that sit on GraphRisk's
NIST crosswalk (Kenya DPA, CBK cybersecurity guidance, CMCA CII regulations).

Each framework is written as:
  (:Framework)<-[:PART_OF]-(:FrameworkControl)-[:MAPS_TO]->(NIST 800-53 / CSF control)

MAPS_TO lets controls a tenant already has count toward these obligations
(see the coverage and blast-radius queries in graphrisk_core). The mappings
are GraphRisk's own interpretation, never an official crosswalk; every edge
is tagged source="GraphRisk curated".

Requirements that carry a notification duty (e.g. "report to CBK within 24
hours") also get notification_* properties. Those drive the regulatory
clocks the API returns alongside blast-radius and vulnerability-impact
results.

Everything is MERGE-based, and properties are always SET (to null when
absent), so re-running a loader updates the graph in place and clears
anything removed from the curated data.
"""

REQUIREMENT_TYPES = {"technical", "process", "legal"}
NOTIFICATION_TRIGGERS = {
    # Only fires for assets flagged holds_personal_data
    "personal_data_breach",
    # Fires for any affected asset; the condition text says what makes it reportable
    "significant_incident",
    "cybersecurity_incident",
}
# Organisation qualifiers a notification duty can be limited to. A duty with
# no applies_to applies to every organisation subject to the framework.
QUALIFIERS = {"data_processor", "sips_swips"}

MERGE_FRAMEWORK = """
    MERGE (f:Framework {id: $id})
    SET f.name = $name, f.version = $version, f.owner = $owner,
        f.url = $url, f.license_note = $license_note
"""

MERGE_CONTROLS = """
    MATCH (f:Framework {id: $fwid})
    UNWIND $batch AS row
    MERGE (fc:FrameworkControl {id: row.id})
    SET fc.control_reference           = row.ref,
        fc.title                       = row.title,
        fc.domain                      = row.domain,
        fc.requirement_type            = row.requirement_type,
        fc.graphrisk_summary           = row.summary,
        fc.legal_source                = row.legal_source,
        fc.needs_verification          = row.needs_verification,
        fc.official_url                = row.url,
        fc.notification_deadline_hours = row.deadline_hours,
        fc.notify_party                = row.notify_party,
        fc.notification_trigger        = row.trigger,
        fc.notification_condition      = row.condition,
        fc.applies_to                  = row.applies_to
    MERGE (fc)-[:PART_OF]->(f)
"""

MERGE_MAPPINGS = """
    UNWIND $batch AS row
    MATCH (src:FrameworkControl {id: row.src})
    MATCH (dst:FrameworkControl {id: row.dst})
    MERGE (src)-[m:MAPS_TO]->(dst)
    SET m.source = "GraphRisk curated", m.confidence = row.confidence
"""

# Removes crosswalk edges that are no longer in the curated list, so a
# re-run after deleting a mapping doesn't leave the old edge behind.
PRUNE_MAPPINGS = """
    MATCH (src:FrameworkControl)-[:PART_OF]->(:Framework {id: $fwid})
    MATCH (src)-[m:MAPS_TO]->(dst:FrameworkControl)
    WHERE NOT (src.id + "|" + dst.id) IN $keep
    DELETE m
    RETURN count(m) AS pruned
"""

FIND_MISSING_TARGETS = """
    UNWIND $ids AS id
    OPTIONAL MATCH (fc:FrameworkControl {id: id})
    WITH id, fc WHERE fc IS NULL
    RETURN collect(id) AS missing
"""

COUNT = """
    MATCH (fc:FrameworkControl)-[:PART_OF]->(:Framework {id: $fwid})
    OPTIONAL MATCH (fc)-[m:MAPS_TO]->()
    RETURN count(DISTINCT fc) AS requirements, count(m) AS mappings,
           count(DISTINCT CASE WHEN fc.notification_deadline_hours IS NOT NULL THEN fc END) AS clocks
"""


def validate(framework, requirements, mappings):
    """Returns a list of problems; empty means the curated data is consistent."""
    problems = []
    refs = [r["ref"] for r in requirements]
    dupes = sorted({r for r in refs if refs.count(r) > 1})
    if dupes:
        problems.append(f"duplicate requirement refs: {dupes}")
    by_ref = {r["ref"]: r for r in requirements}
    for r in requirements:
        if r["requirement_type"] not in REQUIREMENT_TYPES:
            problems.append(f"{r['ref']}: unknown requirement_type {r['requirement_type']!r}")
        n = r.get("notification")
        if n:
            if n.get("trigger") not in NOTIFICATION_TRIGGERS:
                problems.append(f"{r['ref']}: unknown notification trigger {n.get('trigger')!r}")
            if not isinstance(n.get("deadline_hours"), (int, float)) or n["deadline_hours"] <= 0:
                problems.append(f"{r['ref']}: deadline_hours must be a positive number")
            for key in ("notify_party", "condition"):
                if not n.get(key):
                    problems.append(f"{r['ref']}: notification needs {key}")
            bad_q = sorted(set(n.get("applies_to", [])) - QUALIFIERS)
            if bad_q:
                problems.append(f"{r['ref']}: unknown applies_to qualifiers {bad_q}")
    unknown = sorted({m[0] for m in mappings} - set(by_ref))
    if unknown:
        problems.append(f"mappings reference unknown refs: {unknown}")
    legal = sorted({m[0] for m in mappings if m[0] in by_ref and by_ref[m[0]]["requirement_type"] == "legal"})
    if legal:
        problems.append(f"'legal' requirements must not be mapped (attestation only): {legal}")
    pairs = [(m[0], m[1]) for m in mappings]
    dup_pairs = sorted({p for p in pairs if pairs.count(p) > 1})
    if dup_pairs:
        problems.append(f"duplicate mappings: {dup_pairs}")
    bad_conf = sorted({m[2] for m in mappings} - {"high", "medium", "low"})
    if bad_conf:
        problems.append(f"unknown confidence values: {bad_conf}")
    return problems


def build_rows(framework, requirements):
    rows = []
    for r in requirements:
        n = r.get("notification") or {}
        rows.append({
            "id": f"{framework['id']}_{r['ref']}",
            "ref": r["ref"],
            "title": r["title"],
            "domain": r["domain"],
            "requirement_type": r["requirement_type"],
            "summary": r["summary"],
            "legal_source": r["legal_source"],
            "needs_verification": bool(r.get("needs_verification", False)),
            "url": r.get("url") or framework["url"],
            "deadline_hours": n.get("deadline_hours"),
            "notify_party": n.get("notify_party"),
            "trigger": n.get("trigger"),
            "condition": n.get("condition"),
            "applies_to": n.get("applies_to", []) if n else None,
        })
    return rows


def load(db, framework, requirements, mappings):
    """Validate, then write one framework. Returns True on success."""
    fwid = framework["id"]
    print("\n" + "=" * 55)
    print(f"  {framework['label']}  ({fwid})")
    print("=" * 55)

    problems = validate(framework, requirements, mappings)
    if problems:
        print("  ERROR: curated data is inconsistent -- nothing written:")
        for p in problems:
            print(f"    - {p}")
        return False

    targets = sorted({m[1] for m in mappings})
    missing = (db.run(FIND_MISSING_TARGETS, {"ids": targets})[0]["missing"] or []) if targets else []
    if missing:
        print(f"  WARNING: {len(missing)} mapping target(s) not in this graph -- those edges are skipped:")
        for m in missing:
            print(f"    - {m}")
    else:
        print(f"  All {len(targets)} NIST mapping targets present")

    db.run(MERGE_FRAMEWORK, {k: framework[k] for k in ("id", "name", "version", "owner", "url", "license_note")})
    with db.driver.session() as s:
        s.run(MERGE_CONTROLS, {"batch": build_rows(framework, requirements), "fwid": fwid})

    edges = [{"src": f"{fwid}_{k}", "dst": t, "confidence": c} for k, t, c in mappings]
    db.run_batch(MERGE_MAPPINGS, edges, batch_size=200)
    keep = [f"{e['src']}|{e['dst']}" for e in edges]
    pruned = db.run(PRUNE_MAPPINGS, {"fwid": fwid, "keep": keep})[0]["pruned"]

    got = db.run(COUNT, {"fwid": fwid})[0]
    expected_edges = len([m for m in mappings if m[1] not in missing])
    expected_clocks = len([r for r in requirements if r.get("notification")])
    ok = (got["requirements"] == len(requirements) and got["mappings"] == expected_edges
          and got["clocks"] == expected_clocks)
    print(f"  Requirements  : {got['requirements']} (expected {len(requirements)})")
    print(f"  MAPS_TO edges : {got['mappings']} (expected {expected_edges})" + (f", {pruned} stale edge(s) removed" if pruned else ""))
    print(f"  Notification clocks: {got['clocks']} (expected {expected_clocks})")
    attest = [r["ref"] for r in requirements if r["requirement_type"] == "legal"]
    if attest:
        print(f"  Attestation-only: {', '.join(attest)}")
    print("  OK" if ok else "  MISMATCH -- check the counts above")
    return ok
