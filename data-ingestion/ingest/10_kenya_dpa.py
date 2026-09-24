"""
DS-10: Kenya Data Protection Act 2019 (+ Data Protection (General)
Regulations 2021) -- requirements and NIST crosswalk.

Hand-curated, like DS-01 (CSF) and DS-05 (ATT&CK mappings): there's no
machine-readable feed for Kenyan statute. Requirement wording is taken
from the Act itself (Kenya Law, Act No. 24 of 2019); GraphRisk summaries
are plain-English paraphrases, not legal text.

Two kinds of data are written:

1. FrameworkControl nodes for each Kenya DPA requirement, PART_OF a new
   Framework node KE_DPA_2019.

2. MAPS_TO edges from each Kenya requirement to the NIST SP 800-53 Rev5
   and NIST CSF 2.0 controls it corresponds to. This is what lets
   existing tenant controls count toward Kenya DPA automatically: a
   Control that SATISFIES NIST IA-2 also covers any Kenya requirement
   that MAPS_TO IA-2, with no extra per-tenant linking. The coverage and
   blast-radius queries in graphrisk_core follow these edges.

   These mappings are GraphRisk's own interpretation -- no official
   Kenya DPA <-> NIST crosswalk exists that we're aware of. Every edge is
   tagged source="GraphRisk curated". Coverage through a mapping means
   "technical controls are in place that map to this requirement", never
   "compliant". This is not legal advice.

requirement_type:
   technical  -- demonstrable through security controls/telemetry
   process    -- a documented process; mappable to NIST process controls
   legal      -- needs legal/manual attestation; deliberately NOT mapped,
                 so it can never show as covered via the crosswalk

Rows with needs_verification=True come from the Data Protection (General)
Regulations 2021, Part V (regs 27-36), sourced from secondary legal
summaries. Confirm the exact regulation number against the primary text
before citing them externally.

Usage (from the data-ingestion folder, .env pointing at the target graph):
    python ingest/10_kenya_dpa.py
Safe to re-run: everything is MERGE-based.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from neo4j_utils import Neo4jClient

FRAMEWORK_ID = "KE_DPA_2019"
ACT_URL = "https://new.kenyalaw.org/akn/ke/act/2019/24/eng@2022-12-31"
REGS_URL = "https://new.kenyalaw.org/akn/ke/act/ln/2021/263/eng@2022-12-31"

# (ref, domain, requirement_type, title, graphrisk_summary, legal source,
#  notification_deadline_hours or None, needs_verification)
REQUIREMENTS = [
    ("DPA-25", "Principles", "process",
     "Principles of data protection",
     "Personal data must be processed lawfully, fairly and transparently; "
     "collected for explicit purposes; minimal; accurate; kept no longer than "
     "necessary; and not transferred out of Kenya without adequate safeguards or consent.",
     "Data Protection Act 2019, s.25", None, False),

    ("DPA-31", "Impact assessment", "process",
     "Data protection impact assessment",
     "Before high-risk processing, run a DPIA covering the processing, its necessity, "
     "risks to data subjects and the safeguards used. Consult the Data Commissioner if "
     "risk stays high; the Act requires the report 60 days before processing starts.",
     "Data Protection Act 2019, s.31", None, False),

    ("DPA-41.1", "Protection by design", "process",
     "Data protection by design",
     "Build technical and organisational measures into processing systems from the "
     "point the means of processing are decided, not after.",
     "Data Protection Act 2019, s.41(1)-(2)", None, False),

    ("DPA-41.3", "Protection by design", "technical",
     "Data protection by default (minimisation)",
     "By default only the personal data needed for each purpose is processed -- "
     "limiting how much is collected, how far it is processed, how long it is stored "
     "and who can access it.",
     "Data Protection Act 2019, s.41(3)", None, False),

    ("DPA-41.4a", "Protection by design", "process",
     "Identify foreseeable internal and external risks",
     "Identify reasonably foreseeable internal and external risks to personal data.",
     "Data Protection Act 2019, s.41(4)(a)", None, False),

    ("DPA-41.4b", "Protection by design", "process",
     "Establish safeguards against identified risks",
     "Put appropriate safeguards in place against the risks identified.",
     "Data Protection Act 2019, s.41(4)(b)", None, False),

    ("DPA-41.4c", "Protection by design", "technical",
     "Pseudonymisation and encryption of personal data",
     "Pseudonymise and encrypt personal data. Encryption also matters under s.43(6): "
     "breach communication to data subjects is not required where affected data was "
     "protected by appropriate safeguards such as encryption.",
     "Data Protection Act 2019, s.41(4)(c)", None, False),

    ("DPA-41.4d", "Protection by design", "technical",
     "Restore availability and access after an incident",
     "Be able to restore availability of and access to personal data in a timely "
     "manner after a physical or technical incident.",
     "Data Protection Act 2019, s.41(4)(d)", None, False),

    ("DPA-41.4e", "Protection by design", "technical",
     "Verify safeguards are effectively implemented",
     "Verify on an ongoing basis that the safeguards are actually working.",
     "Data Protection Act 2019, s.41(4)(e)", None, False),

    ("DPA-41.4f", "Protection by design", "technical",
     "Continually update safeguards for new risks or deficiencies",
     "Keep safeguards updated in response to new risks or discovered deficiencies.",
     "Data Protection Act 2019, s.41(4)(f)", None, False),

    ("DPA-42.2", "Processors", "process",
     "Processor guarantees and written contract",
     "Use only processors that give sufficient guarantees on security measures, "
     "under a written contract requiring them to act only on the controller's instructions.",
     "Data Protection Act 2019, s.42(2)", None, False),

    ("DPA-42.4", "Processors", "process",
     "Personnel comply with security measures",
     "Take reasonable steps to ensure everyone acting under the controller's or "
     "processor's authority complies with the security measures.",
     "Data Protection Act 2019, s.42(4)", None, False),

    ("DPA-43.1", "Breach notification", "process",
     "Notify the Data Commissioner within 72 hours",
     "Where a breach carries a real risk of harm, notify the Data Commissioner without "
     "delay and within 72 hours of becoming aware of it, and inform affected data "
     "subjects in writing within a reasonably practical period. Late notices must "
     "give reasons for the delay.",
     "Data Protection Act 2019, s.43(1)-(2)", 72, False),

    ("DPA-43.3", "Breach notification", "process",
     "Processor notifies controller within 48 hours",
     "A processor that becomes aware of a breach must notify the controller without "
     "delay and, where reasonably practicable, within 48 hours.",
     "Data Protection Act 2019, s.43(3)", 48, False),

    ("DPA-43.8", "Breach notification", "process",
     "Record breach facts, effects and remedial action",
     "Keep a record of every breach: the facts, its effects and the remedial action taken.",
     "Data Protection Act 2019, s.43(8)", None, False),

    ("DPA-48", "Cross-border transfer", "legal",
     "Conditions for transfer out of Kenya",
     "Transfers of personal data out of Kenya require proof of appropriate safeguards "
     "(ss.48-49). Needs legal attestation -- not mapped to technical controls.",
     "Data Protection Act 2019, ss.48-49", None, False),

    ("DPA-50", "Cross-border transfer", "legal",
     "Processing through a data server or data centre in Kenya",
     "The Cabinet Secretary may require certain processing to happen only through a "
     "server or data centre located in Kenya. Needs legal attestation -- not mapped.",
     "Data Protection Act 2019, s.50", None, False),

    # ── Data Protection (General) Regulations 2021 -- see needs_verification note ──
    ("DPR-ACCESS", "Security measures", "technical",
     "Access restricted to authorised personnel",
     "Restrict access to personal data to personnel who need it.",
     "Data Protection (General) Regulations 2021, Part V", None, True),

    ("DPR-LOGGING", "Security measures", "technical",
     "Backups, audit logs and event monitoring",
     "Maintain backups and audit logs, with audit trails and event monitoring.",
     "Data Protection (General) Regulations 2021, Part V", None, True),

    ("DPR-VULN", "Security measures", "technical",
     "Regular vulnerability testing",
     "Test software for vulnerabilities on a regular basis.",
     "Data Protection (General) Regulations 2021, Part V", None, True),

    ("DPR-TRANSFER", "Security measures", "technical",
     "Secure data transfers",
     "Protect personal data in transfer against unauthorised access and alteration.",
     "Data Protection (General) Regulations 2021, Part V", None, True),

    ("DPR-SEGREGATION", "Security measures", "technical",
     "Separate storage of sensitive personal data",
     "Keep sensitive personal data separate from other data where feasible.",
     "Data Protection (General) Regulations 2021, Part V", None, True),

    ("DPR-DETECTION", "Security measures", "technical",
     "Breach detection and handling routines",
     "Have routines in place to detect and handle data breaches.",
     "Data Protection (General) Regulations 2021, Part V", None, True),
]

# (kenya ref, target FrameworkControl id, confidence)
# Targets are matched by FrameworkControl.id, not control_reference, so they
# can't collide with CIS/PCI references.
N = "NIST_800_53_R5_"
C = "NIST_CSF_2_"
MAPPINGS = [
    ("DPA-25",       N + "PT-2",     "medium"),
    ("DPA-25",       N + "PT-3",     "medium"),
    ("DPA-25",       C + "GV.OC-03", "medium"),

    ("DPA-31",       N + "RA-8",     "high"),
    ("DPA-31",       N + "RA-3",     "medium"),

    ("DPA-41.1",     N + "SA-8",     "high"),
    ("DPA-41.1",     N + "PL-8",     "medium"),

    ("DPA-41.3",     N + "SI-12",    "medium"),
    ("DPA-41.3",     N + "AC-6",     "medium"),

    ("DPA-41.4a",    N + "RA-3",     "high"),
    ("DPA-41.4a",    C + "ID.RA-03", "high"),

    ("DPA-41.4b",    N + "RA-7",     "high"),

    ("DPA-41.4c",    N + "SC-28",    "high"),
    ("DPA-41.4c",    N + "SC-13",    "high"),
    ("DPA-41.4c",    N + "SI-19",    "medium"),
    ("DPA-41.4c",    C + "PR.DS-01", "high"),
    ("DPA-41.4c",    C + "PR.DS-02", "high"),

    ("DPA-41.4d",    N + "CP-9",     "high"),
    ("DPA-41.4d",    N + "CP-10",    "high"),
    ("DPA-41.4d",    C + "PR.DS-11", "high"),
    ("DPA-41.4d",    C + "RC.RP-01", "medium"),

    ("DPA-41.4e",    N + "CA-2",     "high"),
    ("DPA-41.4e",    N + "CA-7",     "high"),
    ("DPA-41.4e",    N + "CA-8",     "medium"),

    ("DPA-41.4f",    N + "CA-5",     "medium"),
    ("DPA-41.4f",    N + "SI-2",     "high"),
    ("DPA-41.4f",    N + "RA-5",     "medium"),

    ("DPA-42.2",     N + "SA-9",     "high"),
    ("DPA-42.2",     N + "SR-6",     "medium"),
    ("DPA-42.2",     N + "SA-4",     "medium"),

    ("DPA-42.4",     N + "AT-2",     "high"),
    ("DPA-42.4",     N + "PS-6",     "medium"),
    ("DPA-42.4",     N + "PL-4",     "medium"),

    ("DPA-43.1",     N + "IR-6",     "high"),
    ("DPA-43.1",     N + "IR-4",     "medium"),
    ("DPA-43.1",     N + "IR-8",     "medium"),
    ("DPA-43.1",     C + "RS.CO-02", "high"),

    ("DPA-43.3",     N + "IR-6",     "high"),
    ("DPA-43.3",     N + "SR-8",     "high"),

    ("DPA-43.8",     N + "IR-5",     "high"),

    ("DPR-ACCESS",   N + "AC-2",     "high"),
    ("DPR-ACCESS",   N + "AC-3",     "high"),
    ("DPR-ACCESS",   N + "AC-6",     "high"),
    ("DPR-ACCESS",   C + "PR.AA-05", "high"),

    ("DPR-LOGGING",  N + "AU-2",     "high"),
    ("DPR-LOGGING",  N + "AU-6",     "high"),
    ("DPR-LOGGING",  N + "AU-12",    "high"),
    ("DPR-LOGGING",  N + "CP-9",     "high"),

    ("DPR-VULN",     N + "RA-5",     "high"),
    ("DPR-VULN",     N + "CA-8",     "medium"),

    ("DPR-TRANSFER", N + "SC-8",     "high"),
    ("DPR-TRANSFER", C + "PR.DS-02", "high"),

    ("DPR-SEGREGATION", N + "SC-32", "medium"),
    ("DPR-SEGREGATION", N + "AC-4",  "medium"),

    ("DPR-DETECTION", N + "SI-4",    "high"),
    ("DPR-DETECTION", N + "IR-4",    "high"),
    ("DPR-DETECTION", C + "DE.CM-01", "high"),
]

MERGE_FRAMEWORK = """
    MERGE (f:Framework {id: $id})
    SET f.name = "KENYA_DPA", f.version = "2019 (+ General Regulations 2021)",
        f.owner = "Office of the Data Protection Commissioner (Kenya)",
        f.url = $url,
        f.license_note = "Public statute -- no licensing restriction"
    RETURN f.id AS id
"""

MERGE_CONTROLS = """
    UNWIND $batch AS row
    MERGE (fc:FrameworkControl {id: row.id})
    SET fc.control_reference           = row.ref,
        fc.title                       = row.title,
        fc.domain                      = row.domain,
        fc.requirement_type            = row.requirement_type,
        fc.graphrisk_summary           = row.summary,
        fc.legal_source                = row.legal_source,
        fc.notification_deadline_hours = row.deadline,
        fc.needs_verification          = row.needs_verification,
        fc.official_url                = row.url
    WITH fc
    MATCH (f:Framework {id: $fwid})
    MERGE (fc)-[:PART_OF]->(f)
"""

MERGE_MAPPINGS = """
    UNWIND $batch AS row
    MATCH (src:FrameworkControl {id: row.src})
    MATCH (dst:FrameworkControl {id: row.dst})
    MERGE (src)-[m:MAPS_TO]->(dst)
    SET m.source = "GraphRisk curated", m.confidence = row.confidence
"""

FIND_MISSING_TARGETS = """
    UNWIND $ids AS id
    OPTIONAL MATCH (fc:FrameworkControl {id: id})
    WITH id, fc WHERE fc IS NULL
    RETURN collect(id) AS missing
"""


def ingest():
    print("=" * 55)
    print("  DS-10: Kenya Data Protection Act 2019")
    print("=" * 55)

    ke_id = lambda ref: f"{FRAMEWORK_ID}_{ref}"
    batch = [{
        "id": ke_id(ref), "ref": ref, "domain": domain,
        "requirement_type": rtype, "title": title, "summary": summary,
        "legal_source": source, "deadline": deadline,
        "needs_verification": verify,
        "url": REGS_URL if ref.startswith("DPR-") else ACT_URL,
    } for ref, domain, rtype, title, summary, source, deadline, verify in REQUIREMENTS]

    known_refs = {r[0] for r in REQUIREMENTS}
    bad_src = sorted({m[0] for m in MAPPINGS} - known_refs)
    if bad_src:
        print(f"  ERROR: mappings reference unknown Kenya refs: {bad_src}")
        return
    legal_mapped = sorted({m[0] for m in MAPPINGS} & {r[0] for r in REQUIREMENTS if r[2] == "legal"})
    if legal_mapped:
        print(f"  ERROR: 'legal' requirements must not be mapped: {legal_mapped}")
        return

    db = Neo4jClient()

    print("\n[1/4] Checking NIST mapping targets exist in this graph...")
    targets = sorted({m[1] for m in MAPPINGS})
    missing = db.run(FIND_MISSING_TARGETS, {"ids": targets})[0]["missing"]
    if missing:
        print(f"  WARNING: {len(missing)} target(s) not found -- those edges will be skipped:")
        for m in missing:
            print(f"    - {m}")
        print("  (Run DS-01 / DS-02 against this graph first if NIST data is missing entirely.)")
    else:
        print(f"  All {len(targets)} targets present")

    print("\n[2/4] Creating Framework node...")
    db.run(MERGE_FRAMEWORK, {"id": FRAMEWORK_ID, "url": ACT_URL})

    print(f"\n[3/4] Loading {len(batch)} requirements...")
    with db.driver.session() as s:
        s.run(MERGE_CONTROLS, {"batch": batch, "fwid": FRAMEWORK_ID})

    print(f"\n[4/4] Creating {len(MAPPINGS)} MAPS_TO edges...")
    edges = [{"src": ke_id(k), "dst": t, "confidence": c} for k, t, c in MAPPINGS]
    db.run_batch(MERGE_MAPPINGS, edges, batch_size=200)

    counts = db.run("""
        MATCH (fc:FrameworkControl)-[:PART_OF]->(:Framework {id: $id})
        OPTIONAL MATCH (fc)-[m:MAPS_TO]->()
        RETURN count(DISTINCT fc) AS requirements, count(m) AS mappings
    """, {"id": FRAMEWORK_ID})[0]
    db.close()

    expected_edges = len(MAPPINGS) - sum(1 for m in MAPPINGS if m[1] in missing)
    print("\n" + "=" * 55)
    print("  Kenya DPA Ingestion Complete")
    print("=" * 55)
    print(f"  Requirements in graph : {counts['requirements']} (expected {len(batch)})")
    print(f"  MAPS_TO edges         : {counts['mappings']} (expected {expected_edges})")
    unmapped = sorted({r[0] for r in REQUIREMENTS} - {m[0] for m in MAPPINGS})
    print(f"  Attestation-only      : {', '.join(unmapped)}")
    print("=" * 55)


if __name__ == "__main__":
    ingest()
