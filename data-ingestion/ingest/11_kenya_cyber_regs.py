"""
DS-11: Kenyan financial-sector cybersecurity obligations on the NIST crosswalk.

Three frameworks, all hand-curated from the primary documents:

  CBK_CYBER_BANKS_2017  CBK Guidance Note on Cybersecurity (August 2017),
                        commercial banks. Still in force.
  CBK_CYBER_PSP_2019    CBK Guideline on Cybersecurity for Payment Service
                        Providers (July 2019).
  KE_CMCA_CII_2024      Computer Misuse and Cybercrimes (Critical Information
                        Infrastructure and Cybercrime Management) Regulations,
                        2024 (Legal Notice 44 of 2024). Banks are a designated
                        critical-infrastructure sector; CBK has said banks must
                        comply with these alongside the 2017 note.

Section references in legal_source are the documents' own numbering.
GraphRisk summaries are plain-English paraphrases, not regulatory text.

As with DS-10, MAPS_TO edges are GraphRisk's own interpretation (never an
official crosswalk), "legal" requirements are deliberately unmapped, and
coverage through a mapping means "mapped controls are in place", never
"compliant". Not legal advice.

Notification duties carry notification_* metadata, which drives the
regulatory clocks. A Kenyan bank can face several clocks from one incident:
24h to CBK, 24h to the sector SOC (CMCA reg 65), and 72h to the Data
Commissioner if personal data is involved (DS-10).

Usage (from the data-ingestion folder, .env pointing at the target graph):
    python ingest/11_kenya_cyber_regs.py
Run DS-01/DS-02 (NIST) against the same graph first. Safe to re-run.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from neo4j_utils import Neo4jClient
import crosswalk_loader

N = "NIST_800_53_R5_"
C = "NIST_CSF_2_"


def req(ref, domain, rtype, title, summary, source, notification=None):
    return {"ref": ref, "domain": domain, "requirement_type": rtype, "title": title,
            "summary": summary, "legal_source": source, "notification": notification}


# ─────────────────────────────────────────────────────────────────────────────
# CBK Guidance Note on Cybersecurity (2017) -- commercial banks
# ─────────────────────────────────────────────────────────────────────────────
BANKS = {
    "id": "CBK_CYBER_BANKS_2017",
    "label": "DS-11a: CBK Guidance Note on Cybersecurity (banks, 2017)",
    "name": "CBK_CYBER_BANKS",
    "version": "August 2017",
    "owner": "Central Bank of Kenya",
    "url": "https://www.centralbank.go.ke/wp-content/uploads/2017/09/GUIDANCE-NOTE-ON-CYBERSECURITY-FOR-THE-BANKING-SECTOR.pdf",
    "license_note": "Public regulatory guidance -- no licensing restriction",
    "category": "regulation",
}
G = "CBK Guidance Note on Cybersecurity 2017"
BANK_REQS = [
    req("B-3.1a", "Governance", "process", "Board oversight of cybersecurity",
        "The board approves and continuously reviews the cybersecurity strategy, policy and "
        "framework, reviews implementation at least once every 12 months, and keeps "
        "cybersecurity as a standing board agenda item.",
        f"{G}, 3.1(a)(vi),(viii),(ix)"),
    req("B-3.1a.iii", "Governance", "process", "Adequate cybersecurity budget",
        "The board allocates cybersecurity funding proportionate to the institution's size and structure.",
        f"{G}, 3.1(a)(iii)"),
    req("B-3.1b.x", "Incident response", "process", "Documented incident response plan",
        "Senior management documents an incident response plan covering roles, detection, "
        "assessment, reporting, escalation and response strategies.",
        f"{G}, 3.1(b)(x)"),
    req("B-3.1b.xii", "Incident response", "process", "Post-incident analysis",
        "Senior management sets up a post-incident analysis framework to decide corrective actions.",
        f"{G}, 3.1(b)(xii)"),
    req("B-3.1b.xi", "Information sharing", "process", "Share threat information",
        "Collaborate with other institutions and security agencies to share the latest cyber threats and attacks.",
        f"{G}, 3.1(b)(xi)"),
    req("B-3.1c", "Governance", "process", "CISO in senior management",
        "A Chief Information Security Officer sits in senior management, reporting to the CEO, "
        "CIO, COO or risk function, and oversees and enforces the cybersecurity programme.",
        f"{G}, 3.1(c)"),
    req("B-3.1c.viii", "Governance", "process", "CISO reports to the CEO at least quarterly",
        "The CISO reports to the CEO at least once a quarter on the state of confidentiality, "
        "integrity and availability, policy exceptions, programme effectiveness and material events.",
        f"{G}, 3.1(c)(viii)"),
    req("B-3.1c.ii", "Asset management", "technical", "Enterprise-wide asset knowledge base",
        "Maintain a current inventory of users, devices, applications, software and hardware, "
        "with network maps and utilisation data.",
        f"{G}, 3.1(c)(ii)"),
    req("B-3.1c.vi", "Risk management", "process", "Regular cyber risk assessments",
        "Conduct regular and comprehensive cyber risk assessments.",
        f"{G}, 3.1(c)(vi)"),
    req("B-3.1c.vii", "Detection", "technical", "Timely detection of cyber events",
        "Have processes for monitoring IT systems to detect cybersecurity events and incidents in a timely manner.",
        f"{G}, 3.1(c)(vii)"),
    req("B-3.1c.xi", "Resilience", "technical", "Frequent backups to a separate location",
        "Take frequent backups of critical IT systems and store them in a separate location.",
        f"{G}, 3.1(c)(xi)"),
    req("B-3.1c.xiii", "Resilience", "process", "Test disaster recovery and BCP",
        "Continuously test disaster recovery and business continuity arrangements so the bank can "
        "keep operating and meet regulatory obligations during an attack.",
        f"{G}, 3.1(c)(xiii)"),
    req("B-3.2.1", "Independent assessment", "technical", "Internal audit testing",
        "Internal audit (with qualified ICT auditors) assesses the cybersecurity framework's design "
        "and effectiveness, runs regular independent threat and vulnerability assessments and "
        "comprehensive penetration tests, and reports findings to the board.",
        f"{G}, 3.2.1"),
    req("B-3.2.2", "Risk management", "process", "Risk registers, criticality and red teaming",
        "The risk function keeps cyber risk registers, an IT asset inventory classified by business "
        "criticality with business impact analysis, assesses residual risk against appetite, and "
        "runs red team exercises.",
        f"{G}, 3.2.2"),
    req("B-3.2.3", "Independent assessment", "process", "External audit reports annually",
        "External auditors run independent threat and vulnerability assessments and penetration "
        "tests, and report findings to the board and CBK annually.",
        f"{G}, 3.2.3"),
    req("B-3.3", "Third parties", "process", "Outsourcing governance",
        "Due diligence on providers, contracts requiring legal and regulatory compliance, "
        "security provisions in SLAs, ongoing monitoring of providers' cyber posture, and exit plans.",
        f"{G}, 3.3"),
    req("B-3.4", "Training", "process", "Security awareness and specialist training",
        "Awareness training for all staff including senior management and the board, a formal "
        "technical training plan for security specialists, and awareness for connected third parties.",
        f"{G}, 3.4"),
    req("B-IV.b", "Reporting", "process", "Notify CBK within 24 hours of a significant incident",
        "Notify the Central Bank within 24 hours of any cybersecurity incident that could significantly "
        "and adversely affect the bank, using the Annex II immediate report.",
        f"{G}, Part IV(b), Annex II",
        {"deadline_hours": 24,
         "notify_party": "Central Bank of Kenya (Annex II immediate report)",
         "trigger": "significant_incident",
         "condition": ("If the incident could have a significant and adverse impact on the bank's "
                       "ability to provide adequate services to customers, its reputation or its "
                       "financial condition.")}),
    req("B-IV.c", "Reporting", "process", "Quarterly incident report to CBK",
        "Submit a quarterly report of all cybersecurity incidents and how they were handled by the "
        "10th day after each quarter ends (Annex III).",
        f"{G}, Part IV(c), Annex III"),
]
BANK_MAPS = [
    ("B-3.1a", C + "GV.RR-01", "high"), ("B-3.1a", C + "GV.OV-01", "high"), ("B-3.1a", N + "PM-9", "medium"),
    ("B-3.1a.iii", N + "PM-3", "high"), ("B-3.1a.iii", C + "GV.RR-03", "high"),
    ("B-3.1b.x", N + "IR-8", "high"), ("B-3.1b.x", C + "RS.MA-01", "medium"),
    ("B-3.1b.xii", N + "IR-4", "medium"), ("B-3.1b.xii", C + "ID.IM-03", "medium"),
    ("B-3.1b.xi", N + "PM-15", "high"), ("B-3.1b.xi", N + "PM-16", "medium"), ("B-3.1b.xi", C + "ID.RA-02", "high"),
    ("B-3.1c", N + "PM-2", "high"), ("B-3.1c", C + "GV.RR-02", "high"),
    ("B-3.1c.viii", C + "GV.OV-03", "medium"),
    ("B-3.1c.ii", N + "CM-8", "high"), ("B-3.1c.ii", C + "ID.AM-01", "high"),
    ("B-3.1c.ii", C + "ID.AM-02", "high"), ("B-3.1c.ii", C + "ID.AM-03", "high"),
    ("B-3.1c.vi", N + "RA-3", "high"), ("B-3.1c.vi", C + "ID.RA-05", "high"),
    ("B-3.1c.vii", N + "SI-4", "high"), ("B-3.1c.vii", C + "DE.CM-01", "high"),
    ("B-3.1c.xi", N + "CP-9", "high"), ("B-3.1c.xi", N + "CP-6", "high"), ("B-3.1c.xi", C + "PR.DS-11", "high"),
    ("B-3.1c.xiii", N + "CP-4", "high"), ("B-3.1c.xiii", C + "ID.IM-04", "medium"),
    ("B-3.2.1", N + "CA-2", "high"), ("B-3.2.1", N + "RA-5", "high"), ("B-3.2.1", N + "CA-8", "high"),
    ("B-3.2.2", N + "RA-9", "medium"), ("B-3.2.2", N + "CA-8.2", "high"), ("B-3.2.2", C + "ID.AM-05", "high"),
    ("B-3.2.3", N + "CA-2.1", "high"), ("B-3.2.3", N + "CA-8", "medium"),
    ("B-3.3", N + "SA-9", "high"), ("B-3.3", N + "SR-6", "high"), ("B-3.3", C + "GV.SC-05", "high"),
    ("B-3.3", C + "GV.SC-07", "high"), ("B-3.3", C + "GV.SC-10", "medium"),
    ("B-3.4", N + "AT-2", "high"), ("B-3.4", N + "AT-3", "high"),
    ("B-3.4", C + "PR.AT-01", "high"), ("B-3.4", C + "PR.AT-02", "high"),
    ("B-IV.b", N + "IR-6", "high"), ("B-IV.b", C + "RS.CO-02", "high"),
    ("B-IV.c", N + "IR-5", "medium"),
]


# ─────────────────────────────────────────────────────────────────────────────
# CBK Guideline on Cybersecurity for Payment Service Providers (2019)
# ─────────────────────────────────────────────────────────────────────────────
PSP = {
    "id": "CBK_CYBER_PSP_2019",
    "label": "DS-11b: CBK Guideline on Cybersecurity for PSPs (2019)",
    "name": "CBK_CYBER_PSP",
    "version": "July 2019",
    "owner": "Central Bank of Kenya",
    "url": "https://www.centralbank.go.ke/wp-content/uploads/2019/07/GuidelinesonCybersecurityforPSPs.pdf",
    "license_note": "Public regulatory guidance -- no licensing restriction",
    "category": "regulation",
}
P = "CBK Guideline on Cybersecurity for PSPs 2019"
PSP_CONDITION = ("If the incident could have a significant and adverse impact on the PSP's ability to "
                 "provide adequate services to its customers, its reputation or its financial condition.")
PSP_REQS = [
    req("P-3.1.1", "Governance", "process", "Board sets direction and reviews the programme",
        "The board sets cybersecurity vision, risk appetite and direction, approves the risk "
        "assessment, and approves and reviews the programme at least annually.",
        f"{P}, 3.1.1"),
    req("P-3.1.2-auth", "Access control", "technical", "Strong authentication",
        "Senior management oversees strong authentication to protect customer data, transactions and systems.",
        f"{P}, 3.1.2"),
    req("P-3.1.2-ir", "Incident response", "process", "Incident response plan and breach handling",
        "Document an incident response plan; on becoming aware of a breach, immediately investigate, "
        "identify, contain and mitigate it; run post-incident analysis.",
        f"{P}, 3.1.2, 3.2.4"),
    req("P-3.1.3", "Governance", "process", "Mandatory CISO",
        "Every PSP must have a CISO who develops and runs the cybersecurity programme and reports to "
        "the CEO and the board at least quarterly.",
        f"{P}, 3.1.3"),
    req("P-3.1.3-outsourcing", "Governance", "legal", "CISO governance may not be outsourced",
        "The CISO's governance, oversight and management functions cannot be outsourced; operational "
        "security functions can only be outsourced with prior CBK approval.",
        f"{P}, 3.1.3"),
    req("P-3.1.3-assets", "Asset management", "technical", "Cyber asset and user register",
        "The CISO maintains a current, comprehensive register of cyber assets and users.",
        f"{P}, 3.1.3"),
    req("P-3.1.3-backup", "Resilience", "technical", "Backups to disaster-resistant sites",
        "Back up critical systems and data in line with recovery objectives to disaster-resistant sites.",
        f"{P}, 3.1.3"),
    req("P-3.1.4", "Governance", "process", "Board-approved cybersecurity policy",
        "A written, board-approved policy covering information security, data classification, asset "
        "inventory, access control, BCP/DR, network security and monitoring, secure development, "
        "physical security, customer data privacy, vendor management, risk assessment and incident response.",
        f"{P}, 3.1.4"),
    req("P-3.2.1", "Risk management", "process", "Annual risk assessment",
        "Carry out a risk assessment, updated at least annually, approved by the board.",
        f"{P}, 3.2.1"),
    req("P-3.2.2", "Risk management", "process", "Review and test systems on a schedule",
        "Review, audit and test systems annually for critical cyber assets, every two years for "
        "others, and after significant changes.",
        f"{P}, 3.2.2"),
    req("P-3.2.3", "Third parties", "process", "Internal and external dependency management",
        "Keep a criticality-ranked inventory of internal assets and external dependencies, and "
        "monitor external connections to critical assets.",
        f"{P}, 3.2.3"),
    req("P-3.2.4", "Resilience", "technical", "Offline storage and destructive-scenario testing",
        "Keep secure offline copies of critical records for restoration, and test against disruptive, "
        "destructive and corruptive cyber events.",
        f"{P}, 3.2.4"),
    req("P-3.2.5", "Testing", "technical", "Vulnerability scanning and penetration testing",
        "Without effective continuous monitoring: quarterly vulnerability scans of critical cyber "
        "assets, twice-yearly vulnerability assessments, and annual penetration tests.",
        f"{P}, 3.2.5"),
    req("P-3.3", "Systemic PSPs", "process", "CSIRT and ecosystem testing (SIPS/SWIPS)",
        "Systemically and system-wide important payment systems need a CSIRT and scenario-based "
        "response and recovery tests with ecosystem participants.",
        f"{P}, 3.3"),
    req("P-3.4", "Third parties", "process", "Outsourcing governance and contracts",
        "Due diligence, contracts covering security incident reporting, audit rights and data "
        "confidentiality, SLAs with security provisions, and third-party breach reporting within a "
        "set timeframe (48 hours is the benchmark given).",
        f"{P}, 3.4, 3.4.1"),
    req("P-3.4.2", "Third parties", "legal", "Notify CBK 30 days before outsourcing",
        "Notify CBK at least 30 days before entering an outsourcing agreement.",
        f"{P}, 3.4.2"),
    req("P-3.5", "Independent assessment", "process", "Risk, internal audit and external audit roles",
        "Cyber risk registers and criticality-based asset inventory, ICT auditors in internal audit "
        "overseeing penetration tests and scans, and annual external audit reporting to the board and CBK.",
        f"{P}, 3.5"),
    req("P-3.6", "Training", "process", "Training and awareness",
        "Awareness training for all staff including the board, ongoing technical training for "
        "specialists, and awareness for customers and connected third parties.",
        f"{P}, 3.6"),
    req("P-IV-24h", "Reporting", "process", "Notify CBK within 24 hours of a significant incident",
        "Report significant cybersecurity incidents to CBK within 24 hours using the Annex II template, "
        "followed by a comprehensive report.",
        f"{P}, Part IV, Annex II",
        {"deadline_hours": 24,
         "notify_party": "Central Bank of Kenya (nps@centralbank.go.ke, Annex II)",
         "trigger": "significant_incident",
         "condition": PSP_CONDITION}),
    req("P-IV-2h", "Reporting", "process", "SIPS/SWIPS: notify CBK within 2 hours",
        "Systemically and system-wide important payment systems must report significant incidents "
        "within 2 hours.",
        f"{P}, Part IV, Annex II",
        {"deadline_hours": 2,
         "notify_party": "Central Bank of Kenya (nps@centralbank.go.ke, Annex II)",
         "trigger": "significant_incident",
         "condition": PSP_CONDITION + " Applies to systemically or system-wide important payment systems.",
         "applies_to": ["sips_swips"]}),
    req("P-IV-q", "Reporting", "process", "Quarterly incident report to CBK",
        "Submit a quarterly incident report by the 10th day after each quarter ends (Annex III).",
        f"{P}, Part IV, Annex III"),
]
PSP_MAPS = [
    ("P-3.1.1", C + "GV.RR-01", "high"), ("P-3.1.1", C + "GV.RM-02", "high"), ("P-3.1.1", C + "GV.OV-01", "high"),
    ("P-3.1.2-auth", N + "IA-2", "high"), ("P-3.1.2-auth", N + "IA-2.1", "high"), ("P-3.1.2-auth", C + "PR.AA-03", "high"),
    ("P-3.1.2-ir", N + "IR-8", "high"), ("P-3.1.2-ir", N + "IR-4", "high"), ("P-3.1.2-ir", C + "RS.MA-01", "high"),
    ("P-3.1.3", N + "PM-2", "high"), ("P-3.1.3", C + "GV.RR-02", "high"),
    ("P-3.1.3-assets", N + "CM-8", "high"), ("P-3.1.3-assets", N + "AC-2", "medium"),
    ("P-3.1.3-assets", C + "ID.AM-01", "high"), ("P-3.1.3-assets", C + "ID.AM-02", "high"),
    ("P-3.1.3-backup", N + "CP-9", "high"), ("P-3.1.3-backup", N + "CP-6", "high"), ("P-3.1.3-backup", C + "PR.DS-11", "high"),
    ("P-3.1.4", C + "GV.PO-01", "high"),
    ("P-3.2.1", N + "RA-3", "high"), ("P-3.2.1", C + "ID.RA-05", "high"),
    ("P-3.2.2", N + "CA-2", "high"), ("P-3.2.2", N + "CA-7", "medium"),
    ("P-3.2.3", N + "CM-8", "medium"), ("P-3.2.3", N + "RA-9", "medium"), ("P-3.2.3", C + "ID.AM-04", "high"),
    ("P-3.2.3", C + "GV.SC-04", "high"),
    ("P-3.2.4", N + "CP-9", "high"), ("P-3.2.4", N + "CP-4", "high"), ("P-3.2.4", C + "PR.DS-11", "high"),
    ("P-3.2.5", N + "RA-5", "high"), ("P-3.2.5", N + "CA-8", "high"),
    ("P-3.3", N + "IR-3", "medium"), ("P-3.3", N + "IR-8", "medium"),
    ("P-3.4", N + "SA-9", "high"), ("P-3.4", N + "SR-6", "high"), ("P-3.4", N + "SR-8", "high"),
    ("P-3.4", C + "GV.SC-05", "high"),
    ("P-3.5", N + "RA-9", "medium"), ("P-3.5", N + "CA-2.1", "high"), ("P-3.5", N + "CA-8", "medium"),
    ("P-3.6", N + "AT-2", "high"), ("P-3.6", N + "AT-3", "high"), ("P-3.6", C + "PR.AT-01", "high"),
    ("P-3.6", C + "PR.AT-02", "high"),
    ("P-IV-24h", N + "IR-6", "high"), ("P-IV-24h", C + "RS.CO-02", "high"),
    ("P-IV-2h", N + "IR-6", "high"), ("P-IV-2h", C + "RS.CO-02", "high"),
    ("P-IV-q", N + "IR-5", "medium"),
]


# ─────────────────────────────────────────────────────────────────────────────
# CMCA Critical Information Infrastructure Regulations 2024 (LN 44/2024)
# ─────────────────────────────────────────────────────────────────────────────
CMCA = {
    "id": "KE_CMCA_CII_2024",
    "label": "DS-11c: CMCA Critical Information Infrastructure Regulations 2024",
    "name": "KENYA_CMCA_CII",
    "version": "Legal Notice 44 of 2024",
    "owner": "National Computer and Cybercrimes Coordination Committee (Kenya)",
    "url": "https://new.kenyalaw.org/akn/ke/act/ln/2024/44/eng@2024-02-16",
    "license_note": "Public statute -- no licensing restriction",
    "category": "regulation",
}
R = "Computer Misuse and Cybercrime (CII and Cybercrime Management) Regulations 2024"
CMCA_REQS = [
    req("CII-17", "Risk management", "process", "Annual cyber risk assessment and risk register",
        "Critical information infrastructure owners run an annual cyber risk assessment and "
        "business impact analysis, and submit a risk register to the Committee.",
        f"{R}, reg. 17"),
    req("CII-47", "Independent assessment", "process", "Annual audit",
        "Critical information infrastructure is audited annually, or at any time there is an imminent threat.",
        f"{R}, reg. 47"),
    req("CII-65", "Reporting", "process", "Report incidents to the sector SOC within 24 hours",
        "Report a cybersecurity incident to the relevant Sectoral Cybersecurity Operations Centre "
        "within 24 hours of becoming aware of it (Form CMCA 7), then help investigators and mitigate the impact.",
        f"{R}, reg. 65",
        {"deadline_hours": 24,
         "notify_party": "Sectoral Cybersecurity Operations Centre (for banks: the CBK Banking Sector SOC), Form CMCA 7",
         "trigger": "cybersecurity_incident",
         "condition": "If a cybersecurity incident affects critical information infrastructure."}),
]
CMCA_MAPS = [
    ("CII-17", N + "RA-3", "high"), ("CII-17", C + "ID.RA-05", "high"), ("CII-17", N + "RA-9", "medium"),
    ("CII-47", N + "CA-2", "high"), ("CII-47", N + "CA-2.1", "medium"),
    ("CII-65", N + "IR-6", "high"), ("CII-65", C + "RS.CO-02", "high"),
]

FRAMEWORKS = [(BANKS, BANK_REQS, BANK_MAPS), (PSP, PSP_REQS, PSP_MAPS), (CMCA, CMCA_REQS, CMCA_MAPS)]


if __name__ == "__main__":
    db = Neo4jClient()
    results = [crosswalk_loader.load(db, fw, reqs, maps) for fw, reqs, maps in FRAMEWORKS]
    db.close()
    print("\n" + "=" * 55)
    print("  All frameworks loaded" if all(results) else "  One or more frameworks FAILED -- see above")
    print("=" * 55)
    sys.exit(0 if all(results) else 1)
