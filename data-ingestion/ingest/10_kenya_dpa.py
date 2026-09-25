"""
DS-10: Kenya Data Protection Act 2019 (+ Data Protection (General)
Regulations 2021) -- requirements and NIST crosswalk.

Hand-curated, like DS-01 (CSF) and DS-05 (ATT&CK mappings): there's no
machine-readable feed for Kenyan statute. Requirement wording is taken
from the Act itself (Kenya Law, Act No. 24 of 2019); GraphRisk summaries
are plain-English paraphrases, not legal text.

Writes, via crosswalk_loader.py:
1. FrameworkControl nodes for each requirement, PART_OF Framework KE_DPA_2019.
2. MAPS_TO edges to the NIST 800-53 Rev5 / CSF 2.0 controls each one
   corresponds to, so a tenant Control that SATISFIES NIST IA-2 also covers
   any Kenya requirement that MAPS_TO IA-2. These mappings are GraphRisk's
   own interpretation -- no official Kenya DPA <-> NIST crosswalk exists
   that we're aware of. Coverage through a mapping means "technical
   controls are in place that map to this requirement", never "compliant".
   Not legal advice.
3. Notification metadata on the s.43 breach-notice duties, which drives the
   regulatory clocks in blast-radius / vulnerability-impact results.

requirement_type:
   technical  -- demonstrable through security controls/telemetry
   process    -- a documented process; mappable to NIST process controls
   legal      -- needs legal/manual attestation; deliberately NOT mapped

The DPR-* rows below implement Data Protection (General) Regulations 2021,
regulation 32 ("Elements for principle of integrity, confidentiality and
availability"), one row per lettered sub-clause 32(a)-(k) (32(g) and 32(h)
are combined into one row, DPR-LOGGING, since both are routine security-
control housekeeping). Six of these rows (DPR-ACCESS, DPR-LOGGING,
DPR-VULN, DPR-TRANSFER, DPR-SEGREGATION, DPR-DETECTION) were originally
sourced from secondary legal summaries citing only "Part V" and flagged
needs_verification=True; the remaining four (DPR-ISMS, DPR-RISK,
DPR-RESILIENCE, DPR-STORAGE) were drafted directly from the primary text.
All ten were verified 2026-09 against the regulation's primary text
(Office of the Data Protection Commissioner's published copy, cross-checked
against Kenya Law's AKN record for LN 263 of 2021); needs_verification is
False and legal_source cites the sub-clause directly. The NIST/CSF crosswalk
targets for the four new rows (PM-1, PL-1, RA-7, CP-2, SI-13, SI-7,
GV.PO-01, ID.RA-06, PR.IR-04) are standard Rev5/CSF-2.0 identifiers but
were not confirmed against this graph's own loaded control set before this
edit -- spot-check they exist as FrameworkControl nodes before relying on
the mapping (e.g. `MATCH (fc:FrameworkControl) WHERE fc.id IN [...] RETURN fc.id`)
and re-running 02_nist_800_53.py / 01_nist_csf.py first if any are missing.

Usage (from the data-ingestion folder, .env pointing at the target graph):
    python ingest/10_kenya_dpa.py
Safe to re-run: MERGE-based, and stale mappings are pruned.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from neo4j_utils import Neo4jClient
import crosswalk_loader

ACT_URL = "https://new.kenyalaw.org/akn/ke/act/2019/24/eng@2022-12-31"
REGS_URL = "https://new.kenyalaw.org/akn/ke/act/ln/2021/263/eng@2022-12-31"

FRAMEWORK = {
    "id": "KE_DPA_2019",
    "label": "DS-10: Kenya Data Protection Act 2019",
    "name": "KENYA_DPA",
    "version": "2019 (+ General Regulations 2021)",
    "owner": "Office of the Data Protection Commissioner (Kenya)",
    "url": ACT_URL,
    "license_note": "Public statute -- no licensing restriction",
    "category": "regulation",
}

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

    # ── Data Protection (General) Regulations 2021, reg. 32 -- verified 2026-09
    # against the ODPC's published text of the regulation, in (a)-(k) order. ──
    ("DPR-ISMS", "Security measures", "process",
     "Operative information-security policy and procedure management",
     "Maintain an operative means of managing information-security policies and "
     "procedures -- an active management process, not just a written policy on file.",
     "Data Protection (General) Regulations 2021, reg. 32(a)", None, False),

    ("DPR-RISK", "Security measures", "process",
     "Ongoing risk assessment for personal-data security",
     "Assess the risks to the security of personal data and put in place measures "
     "that counter the risks identified. Distinct from the one-off DPIA required "
     "before high-risk processing under s.31 -- this is a standing security risk "
     "assessment.",
     "Data Protection (General) Regulations 2021, reg. 32(b)", None, False),

    ("DPR-RESILIENCE", "Security measures", "technical",
     "Processing resilient to change, incidents and cyber-attacks",
     "Design processing so it stays robust through organisational change, evolving "
     "regulatory demands, security incidents and cyber-attacks -- ongoing "
     "operational resilience, not just post-incident recovery.",
     "Data Protection (General) Regulations 2021, reg. 32(c)", None, False),

    ("DPR-ACCESS", "Security measures", "technical",
     "Access restricted to authorised personnel",
     "Restrict access to personal data to personnel who need it.",
     "Data Protection (General) Regulations 2021, reg. 32(d)", None, False),

    ("DPR-TRANSFER", "Security measures", "technical",
     "Secure data transfers",
     "Protect personal data in transfer against unauthorised access and alteration.",
     "Data Protection (General) Regulations 2021, reg. 32(e)", None, False),

    ("DPR-STORAGE", "Security measures", "technical",
     "Secure data storage against unauthorised use, access and alteration",
     "Protect personal data as stored -- at rest -- against unauthorised use, "
     "access and alteration. Distinct from DPR-TRANSFER, which covers data in transit.",
     "Data Protection (General) Regulations 2021, reg. 32(f)", None, False),

    ("DPR-LOGGING", "Security measures", "technical",
     "Backups, audit logs and event monitoring",
     "Maintain backups and audit logs, with audit trails and event monitoring.",
     "Data Protection (General) Regulations 2021, reg. 32(g)-(h)", None, False),

    ("DPR-SEGREGATION", "Security measures", "technical",
     "Separate storage of sensitive personal data",
     "Keep sensitive personal data separate from other data where feasible.",
     "Data Protection (General) Regulations 2021, reg. 32(i)", None, False),

    ("DPR-DETECTION", "Security measures", "technical",
     "Breach detection and handling routines",
     "Have routines in place to detect and handle data breaches.",
     "Data Protection (General) Regulations 2021, reg. 32(j)", None, False),

    ("DPR-VULN", "Security measures", "technical",
     "Regular vulnerability testing",
     "Test software for vulnerabilities on a regular basis.",
     "Data Protection (General) Regulations 2021, reg. 32(k)", None, False),
]

# Breach-notice duties (s.43). The deadline column in REQUIREMENTS above
# is kept for readability; these entries are what actually drive the clocks,
# and main() checks the two agree.
NOTIFICATIONS = {
    "DPA-43.1": {
        "deadline_hours": 72,
        "notify_party": "Office of the Data Protection Commissioner (ODPC)",
        "trigger": "personal_data_breach",
        "condition": ("If personal data is accessed or acquired by an unauthorised person and there "
                      "is a real risk of harm. Affected data subjects must also be told in writing "
                      "within a reasonably practical period, unless the data was protected by "
                      "safeguards such as encryption (s.43(6))."),
    },
    "DPA-43.3": {
        "deadline_hours": 48,
        "notify_party": "The data controller you process the data for",
        "trigger": "personal_data_breach",
        "condition": "If you process the affected personal data on behalf of another organisation (as its data processor).",
        "applies_to": ["data_processor"],
    },
}

# (kenya ref, target FrameworkControl id, confidence)
# Targets are matched by FrameworkControl.id, not control_reference, so they
# can't collide with CIS/PCI references.
N = "NIST_800_53_R5_"
C = "NIST_CSF_2_"
MAPPINGS = [
    ("DPR-ISMS",     N + "PM-1",     "high"),
    ("DPR-ISMS",     N + "PL-1",     "medium"),
    ("DPR-ISMS",     C + "GV.PO-01", "high"),

    ("DPR-RISK",     N + "RA-3",     "high"),
    ("DPR-RISK",     N + "RA-7",     "medium"),
    ("DPR-RISK",     C + "ID.RA-06", "medium"),

    ("DPR-RESILIENCE", N + "CP-2",   "high"),
    ("DPR-RESILIENCE", N + "SI-13",  "medium"),
    ("DPR-RESILIENCE", C + "PR.IR-04", "medium"),

    ("DPR-STORAGE",  N + "SC-28",    "high"),
    ("DPR-STORAGE",  N + "AC-3",     "medium"),
    ("DPR-STORAGE",  N + "SI-7",     "medium"),
    ("DPR-STORAGE",  C + "PR.DS-01", "high"),

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


def requirements():
    rows = []
    for ref, domain, rtype, title, summary, source, deadline, verify in REQUIREMENTS:
        n = NOTIFICATIONS.get(ref)
        if (n or {}).get("deadline_hours") != deadline:
            raise SystemExit(f"{ref}: REQUIREMENTS deadline {deadline} disagrees with NOTIFICATIONS")
        rows.append({
            "ref": ref, "domain": domain, "requirement_type": rtype, "title": title,
            "summary": summary, "legal_source": source, "needs_verification": verify,
            "url": REGS_URL if ref.startswith("DPR-") else ACT_URL,
            "notification": n,
        })
    return rows


if __name__ == "__main__":
    db = Neo4jClient()
    ok = crosswalk_loader.load(db, FRAMEWORK, requirements(), MAPPINGS)
    db.close()
    sys.exit(0 if ok else 1)
