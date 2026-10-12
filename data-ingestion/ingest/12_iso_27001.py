"""
DS-12: ISO/IEC 27001:2022 readiness on the NIST crosswalk.

ISO/IEC 27001 is a copyrighted, paid standard (© ISO/IEC). To stay within
ISO's copyright and trademark rules, this loader stores ONLY:

  * the standard's reference numbers (clauses 4-10 and Annex A 5.1-8.34),
    which are facts used by every compliance tool, and
  * short labels and summaries written by GraphRisk in its own words --
    deliberately NOT ISO's control titles or requirement text.

Organisations need their own licensed copy of the standard (from ISO, or in
Kenya from the Kenya Bureau of Standards) for the actual requirements.

GraphRisk presents this as READINESS / alignment only. It never claims an
organisation is "ISO certified" or "ISO compliant": only an accredited
certification body can certify. ISO 27001 is a voluntary standard
(category "standard"), so it only becomes one of an organisation's
obligations if it ticks it in its regulatory profile, and binding Kenyan law
(DS-10 Kenya DPA, DS-11 CBK/CMCA) always takes precedence where they overlap.

MAPS_TO edges are GraphRisk's own interpretation onto NIST SP 800-53 Rev5 /
CSF 2.0, informed by NIST's published SP 800-53 <-> ISO/IEC 27001 mapping
(which targets the 2013 edition, so 2022 references were remapped by hand).
Tagged "GraphRisk curated" like DS-10/11; coverage through a mapping means
"mapped controls are in place", never "conforms". Requirements GraphRisk
can't map sensibly are left unmapped and show as "no evidence yet" until the
organisation records them (attestation). Not legal advice.

Usage (from the data-ingestion folder, .env pointing at the target graph):
    python ingest/12_iso_27001.py
Run DS-01/DS-02 (NIST) against the same graph first. Safe to re-run.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from neo4j_utils import Neo4jClient
import crosswalk_loader

N = "NIST_800_53_R5_"
C = "NIST_CSF_2_"

FRAMEWORK = {
    "id": "ISO_27001_2022",
    "label": "DS-12: ISO/IEC 27001:2022 (readiness, reference numbers only)",
    "name": "ISO_27001",
    "version": "2022 (incl. Amd 1:2024)",
    "owner": "ISO/IEC",
    "url": "https://www.iso.org/standard/27001",
    "license_note": ("© ISO/IEC -- GraphRisk stores reference numbers and its own summaries only; "
                     "obtain the standard from ISO or the Kenya Bureau of Standards. "
                     "Readiness view, not certification."),
    "category": "standard",
}
SRC = "ISO/IEC 27001:2022"


def req(ref, domain, rtype, title, summary):
    """title/summary are GraphRisk's own wording, not ISO text."""
    return {"ref": ref, "domain": domain, "requirement_type": rtype, "title": title,
            "summary": summary, "legal_source": f"{SRC}, {ref}", "notification": None}


MS = "Management system"
ORG, PPL, PHY, TEC = "Organisational", "People", "Physical", "Technological"

REQUIREMENTS = [
    # ── Clauses 4-10: the management system itself ───────────────────────────
    req("4.1", MS, "process", "Understand your context",
        "Work out the internal and external issues (including climate-related ones) that affect what "
        "your security programme must achieve."),
    req("4.2", MS, "process", "Know interested parties' expectations",
        "List who has a stake in your information security -- regulators, customers, staff -- and "
        "which of their expectations you will meet, including legal ones."),
    req("4.3", MS, "legal", "Define the ISMS scope",
        "Write down which parts of the organisation, locations and systems the security programme covers."),
    req("4.4", MS, "process", "Run the ISMS as a system",
        "Establish, operate, maintain and keep improving the security programme as a managed set of processes."),
    req("5.1", MS, "legal", "Leadership commitment",
        "Top management visibly backs the programme: resources, integration into business processes, direction."),
    req("5.2", MS, "legal", "Security policy",
        "A management-approved information security policy exists, is communicated and fits the organisation."),
    req("5.3", MS, "legal", "Assign security roles",
        "Responsibilities and authority for security are assigned and communicated."),
    req("6.1.1", MS, "process", "Plan for risks and opportunities",
        "Plan how the programme will deal with the risks and opportunities identified from context and stakeholders."),
    req("6.1.2", MS, "process", "Information security risk assessment",
        "Have a repeatable way to identify, analyse and evaluate security risks, with owners and criteria."),
    req("6.1.3", MS, "process", "Risk treatment and Statement of Applicability",
        "Choose treatments for each risk, compare them with Annex A, and record which controls apply "
        "and why (the Statement of Applicability)."),
    req("6.2", MS, "process", "Security objectives",
        "Set measurable security objectives and plan how to reach them."),
    req("6.3", MS, "process", "Plan changes to the ISMS",
        "Make changes to the security programme in a planned way."),
    req("7.1", MS, "legal", "Resources",
        "Provide the people, budget and tools the programme needs."),
    req("7.2", MS, "process", "Competence",
        "People doing security work have the skills needed, with evidence."),
    req("7.3", MS, "process", "Awareness",
        "Staff know the policy, their part in it and the consequences of not following it."),
    req("7.4", MS, "legal", "Communication",
        "Decide what to communicate about security, to whom, when and how."),
    req("7.5", MS, "process", "Documented information",
        "Keep the programme's documents and records controlled, current and available."),
    req("8.1", MS, "process", "Operational planning and control",
        "Run the planned processes, control changes, and control outsourced processes."),
    req("8.2", MS, "process", "Perform risk assessments",
        "Carry out risk assessments at planned intervals and after significant change; keep the results."),
    req("8.3", MS, "process", "Implement risk treatment",
        "Carry out the risk treatment plan and keep the results."),
    req("9.1", MS, "process", "Monitoring and measurement",
        "Decide what to measure about security performance, how, and who reviews it."),
    req("9.2", MS, "process", "Internal audit",
        "Audit the programme internally at planned intervals with an audit programme."),
    req("9.3", MS, "legal", "Management review",
        "Top management reviews the programme at planned intervals and records decisions."),
    req("10.1", MS, "process", "Continual improvement",
        "Keep improving the suitability and effectiveness of the programme."),
    req("10.2", MS, "process", "Nonconformity and corrective action",
        "When something falls short, fix it, find the cause and prevent recurrence."),

    # ── Annex A 5: organisational controls ───────────────────────────────────
    req("A.5.1", ORG, "process", "Security policies", "Topic-specific security policies, approved, published and reviewed."),
    req("A.5.2", ORG, "process", "Security roles", "Define and assign who is responsible for what in security."),
    req("A.5.3", ORG, "process", "Separate conflicting duties", "Split duties so no one person can misuse a process alone."),
    req("A.5.4", ORG, "process", "Management expects compliance", "Managers require staff and contractors to follow security policy."),
    req("A.5.5", ORG, "process", "Keep in touch with authorities", "Maintain contacts with regulators and law enforcement (e.g. ODPC, CBK, KE-CIRT)."),
    req("A.5.6", ORG, "process", "Join security interest groups", "Maintain contact with specialist security forums and associations."),
    req("A.5.7", ORG, "process", "Use threat intelligence", "Collect and analyse information about threats relevant to you."),
    req("A.5.8", ORG, "process", "Security in projects", "Build security into project management."),
    req("A.5.9", ORG, "technical", "Asset inventory", "Keep an up-to-date inventory of information and the assets that hold it, with owners."),
    req("A.5.10", ORG, "process", "Acceptable use rules", "Rules for acceptable use of information and assets."),
    req("A.5.11", ORG, "process", "Return assets on leaving", "Staff and contractors return organisational assets when they leave."),
    req("A.5.12", ORG, "process", "Classify information", "Classify information by its sensitivity and requirements."),
    req("A.5.13", ORG, "process", "Label information", "Label information in line with its classification."),
    req("A.5.14", ORG, "technical", "Secure information transfer", "Rules and protections for transferring information, internally and externally."),
    req("A.5.15", ORG, "technical", "Access control policy", "Control access to information and assets based on business and security needs."),
    req("A.5.16", ORG, "technical", "Identity lifecycle", "Manage identities through their whole lifecycle."),
    req("A.5.17", ORG, "technical", "Credentials management", "Manage passwords and other authentication secrets securely."),
    req("A.5.18", ORG, "technical", "Grant and review access", "Provide, review, change and remove access rights per policy."),
    req("A.5.19", ORG, "process", "Supplier security", "Manage the security risks of using suppliers."),
    req("A.5.20", ORG, "process", "Security in supplier contracts", "Put security requirements into supplier agreements."),
    req("A.5.21", ORG, "process", "ICT supply chain risk", "Manage security risks in the ICT products and services supply chain."),
    req("A.5.22", ORG, "process", "Monitor suppliers", "Monitor, review and manage changes to suppliers' security practices."),
    req("A.5.23", ORG, "process", "Cloud service security", "Manage security when acquiring, using and leaving cloud services."),
    req("A.5.24", ORG, "process", "Incident response planning", "Plan and prepare for handling security incidents, with defined roles."),
    req("A.5.25", ORG, "process", "Triage security events", "Assess events and decide whether they are incidents."),
    req("A.5.26", ORG, "process", "Respond to incidents", "Respond to incidents according to documented procedures."),
    req("A.5.27", ORG, "process", "Learn from incidents", "Use what incidents teach to strengthen controls."),
    req("A.5.28", ORG, "process", "Preserve evidence", "Identify, collect and preserve evidence about security events."),
    req("A.5.29", ORG, "process", "Security during disruption", "Keep security at an appropriate level during a disruption."),
    req("A.5.30", ORG, "technical", "ICT continuity readiness", "Plan, test and maintain ICT readiness to meet continuity objectives."),
    req("A.5.31", ORG, "legal", "Know your legal obligations",
        "Identify and keep current the legal, regulatory and contractual requirements that apply -- in Kenya "
        "including the Data Protection Act and any CBK/CMCA rules (see those frameworks)."),
    req("A.5.32", ORG, "legal", "Intellectual property", "Protect intellectual property rights, including software licensing."),
    req("A.5.33", ORG, "process", "Protect records", "Protect records from loss, destruction, falsification and unauthorised access."),
    req("A.5.34", ORG, "legal", "Privacy and personal data",
        "Meet privacy and personal-data obligations. For Kenyan organisations the Kenya Data Protection "
        "Act 2019 sets the binding requirements -- see that framework."),
    req("A.5.35", ORG, "process", "Independent security review", "Have the security approach reviewed independently at intervals and after major change."),
    req("A.5.36", ORG, "process", "Check policy compliance", "Regularly check compliance with security policies and standards."),
    req("A.5.37", ORG, "process", "Documented procedures", "Document operating procedures and make them available."),

    # ── Annex A 6: people controls ───────────────────────────────────────────
    req("A.6.1", PPL, "legal", "Background checks", "Screen candidates before joining, in line with law and the role's risk."),
    req("A.6.2", PPL, "legal", "Security in employment terms", "Employment agreements state security responsibilities."),
    req("A.6.3", PPL, "process", "Security awareness and training", "Staff receive security awareness, education and training."),
    req("A.6.4", PPL, "legal", "Disciplinary process", "A formal process for security policy breaches."),
    req("A.6.5", PPL, "process", "Duties after leaving", "Security duties that continue after leaving or changing role are defined and enforced."),
    req("A.6.6", PPL, "legal", "Confidentiality agreements", "Confidentiality or non-disclosure agreements are in place and reviewed."),
    req("A.6.7", PPL, "technical", "Remote working security", "Protect information when people work remotely."),
    req("A.6.8", PPL, "process", "Report security events", "Staff have a way to report observed or suspected security events promptly."),

    # ── Annex A 7: physical controls ─────────────────────────────────────────
    req("A.7.1", PHY, "process", "Physical perimeters", "Define security perimeters around areas holding information and assets."),
    req("A.7.2", PHY, "process", "Entry controls", "Control physical entry to secure areas."),
    req("A.7.3", PHY, "process", "Secure offices and facilities", "Design and apply physical security for offices and rooms."),
    req("A.7.4", PHY, "process", "Physical monitoring", "Monitor premises for unauthorised physical access."),
    req("A.7.5", PHY, "process", "Environmental threats", "Protect against fire, flood, power and other physical threats."),
    req("A.7.6", PHY, "process", "Working in secure areas", "Rules for working in secure areas."),
    req("A.7.7", PHY, "process", "Clear desk and screen", "Keep desks clear of papers/media and screens locked when away."),
    req("A.7.8", PHY, "process", "Equipment placement", "Site and protect equipment securely."),
    req("A.7.9", PHY, "technical", "Assets off-site", "Protect devices and media used away from the premises."),
    req("A.7.10", PHY, "technical", "Storage media", "Manage removable and storage media through their lifecycle."),
    req("A.7.11", PHY, "process", "Supporting utilities", "Protect against power and other utility failures."),
    req("A.7.12", PHY, "process", "Cabling", "Protect power and data cabling."),
    req("A.7.13", PHY, "process", "Equipment maintenance", "Maintain equipment so it stays available and secure."),
    req("A.7.14", PHY, "technical", "Secure disposal and reuse", "Wipe or destroy data before equipment is disposed of or reused."),

    # ── Annex A 8: technological controls ────────────────────────────────────
    req("A.8.1", TEC, "technical", "Endpoint devices", "Protect information on and accessed through user devices."),
    req("A.8.2", TEC, "technical", "Privileged access", "Restrict and manage privileged (admin) access."),
    req("A.8.3", TEC, "technical", "Restrict access to information", "Limit access to information per the access control policy."),
    req("A.8.4", TEC, "technical", "Source code access", "Control read and write access to source code and dev tools."),
    req("A.8.5", TEC, "technical", "Secure authentication", "Use secure authentication methods, such as MFA, appropriate to the risk."),
    req("A.8.6", TEC, "technical", "Capacity", "Monitor and adjust capacity to current and expected needs."),
    req("A.8.7", TEC, "technical", "Malware protection", "Protect against malware, backed by user awareness."),
    req("A.8.8", TEC, "technical", "Technical vulnerabilities", "Find out about vulnerabilities, assess exposure and fix them (patching)."),
    req("A.8.9", TEC, "technical", "Secure configuration", "Define, apply and monitor secure configurations (e.g. CIS benchmarks)."),
    req("A.8.10", TEC, "technical", "Delete information", "Delete information when no longer needed."),
    req("A.8.11", TEC, "technical", "Mask data", "Mask or pseudonymise data where policy and law require."),
    req("A.8.12", TEC, "technical", "Data leakage prevention", "Detect and prevent unauthorised disclosure of sensitive data."),
    req("A.8.13", TEC, "technical", "Backups", "Back up information and software, and test restores."),
    req("A.8.14", TEC, "technical", "Redundancy", "Build enough redundancy into facilities and systems to stay available."),
    req("A.8.15", TEC, "technical", "Logging", "Produce, protect and analyse logs of activity, exceptions and faults."),
    req("A.8.16", TEC, "technical", "Monitoring for anomalies", "Monitor networks, systems and applications for anomalous behaviour and respond."),
    req("A.8.17", TEC, "technical", "Time synchronisation", "Synchronise system clocks to an approved time source."),
    req("A.8.18", TEC, "technical", "Powerful utility programs", "Restrict utilities that can override system and application controls."),
    req("A.8.19", TEC, "technical", "Controlled software installation", "Control installation of software on operational systems."),
    req("A.8.20", TEC, "technical", "Network security", "Secure, manage and control networks and devices on them."),
    req("A.8.21", TEC, "technical", "Network service security", "Define and monitor security of network services."),
    req("A.8.22", TEC, "technical", "Network segregation", "Separate groups of services, users and systems on networks."),
    req("A.8.23", TEC, "technical", "Web filtering", "Manage access to external websites to reduce exposure to malicious content."),
    req("A.8.24", TEC, "technical", "Cryptography", "Rules for using cryptography, including key management."),
    req("A.8.25", TEC, "process", "Secure development lifecycle", "Rules for developing software and systems securely."),
    req("A.8.26", TEC, "process", "Application security requirements", "Identify and approve security requirements when building or buying applications."),
    req("A.8.27", TEC, "process", "Secure architecture", "Principles for engineering secure systems, applied in development."),
    req("A.8.28", TEC, "technical", "Secure coding", "Apply secure coding principles."),
    req("A.8.29", TEC, "technical", "Security testing", "Test security during development and before acceptance."),
    req("A.8.30", TEC, "process", "Outsourced development", "Direct, monitor and review outsourced development."),
    req("A.8.31", TEC, "technical", "Separate environments", "Keep development, test and production separate and secured."),
    req("A.8.32", TEC, "process", "Change management", "Control changes to systems and facilities."),
    req("A.8.33", TEC, "technical", "Test data", "Select, protect and manage information used for testing."),
    req("A.8.34", TEC, "process", "Protect systems during audits", "Plan audit tests on operational systems to limit disruption."),
]

# GraphRisk's own crosswalk onto NIST (see module docstring). "legal"
# requirements are attestation-only and deliberately left unmapped.
MAPPINGS = [
    ("4.4",   N + "PM-1",  "medium"),
    ("6.1.1", N + "PM-9",  "medium"),
    ("6.1.2", N + "RA-3",  "high"),
    ("6.1.2", C + "ID.RA-05", "medium"),
    ("6.1.3", N + "PM-9",  "medium"),
    ("6.2",   N + "PM-6",  "medium"),
    ("7.2",   N + "AT-3",  "medium"),
    ("7.3",   N + "AT-2",  "high"),
    ("7.5",   N + "PL-1",  "low"),
    ("8.2",   N + "RA-3",  "high"),
    ("8.3",   N + "PM-4",  "medium"),
    ("9.1",   N + "PM-6",  "medium"),
    ("9.1",   N + "CA-7",  "medium"),
    ("9.2",   N + "CA-2",  "medium"),
    ("10.2",  N + "PM-4",  "medium"),

    ("A.5.1",  N + "PL-1",  "medium"),
    ("A.5.2",  N + "PM-2",  "medium"),
    ("A.5.3",  N + "AC-5",  "high"),
    ("A.5.5",  N + "IR-6",  "medium"),
    ("A.5.6",  N + "PM-15", "high"),
    ("A.5.7",  N + "PM-16", "high"),
    ("A.5.8",  N + "SA-3",  "medium"),
    ("A.5.9",  N + "CM-8",  "high"),
    ("A.5.10", N + "PL-4",  "high"),
    ("A.5.11", N + "PS-4",  "medium"),
    ("A.5.12", N + "RA-2",  "high"),
    ("A.5.13", N + "MP-3",  "medium"),
    ("A.5.14", N + "SC-8",  "high"),
    ("A.5.15", N + "AC-1",  "medium"),
    ("A.5.15", N + "AC-3",  "high"),
    ("A.5.16", N + "IA-4",  "high"),
    ("A.5.16", N + "AC-2",  "medium"),
    ("A.5.17", N + "IA-5",  "high"),
    ("A.5.18", N + "AC-2",  "high"),
    ("A.5.19", N + "SR-1",  "medium"),
    ("A.5.20", N + "SA-4",  "medium"),
    ("A.5.21", N + "SR-3",  "medium"),
    ("A.5.22", N + "SA-9",  "medium"),
    ("A.5.23", N + "SA-9",  "medium"),
    ("A.5.24", N + "IR-8",  "high"),
    ("A.5.25", N + "IR-4",  "medium"),
    ("A.5.26", N + "IR-4",  "high"),
    ("A.5.27", N + "IR-4",  "medium"),
    ("A.5.28", N + "AU-9",  "low"),
    ("A.5.29", N + "CP-2",  "medium"),
    ("A.5.30", N + "CP-2",  "high"),
    ("A.5.30", N + "CP-4",  "medium"),
    ("A.5.33", N + "AU-9",  "medium"),
    ("A.5.35", N + "CA-2",  "medium"),
    ("A.5.36", N + "CA-2",  "medium"),
    ("A.5.37", N + "SA-5",  "low"),

    ("A.6.3",  N + "AT-2",  "high"),
    ("A.6.5",  N + "PS-4",  "medium"),
    ("A.6.7",  N + "AC-17", "high"),
    ("A.6.8",  N + "IR-6",  "medium"),

    ("A.7.1",  N + "PE-3",  "medium"),
    ("A.7.2",  N + "PE-2",  "medium"),
    ("A.7.2",  N + "PE-3",  "high"),
    ("A.7.3",  N + "PE-3",  "medium"),
    ("A.7.4",  N + "PE-6",  "high"),
    ("A.7.5",  N + "PE-13", "medium"),
    ("A.7.5",  N + "PE-15", "medium"),
    ("A.7.7",  N + "AC-11", "medium"),
    ("A.7.8",  N + "PE-18", "medium"),
    ("A.7.9",  N + "PE-17", "medium"),
    ("A.7.10", N + "MP-7",  "medium"),
    ("A.7.11", N + "PE-11", "medium"),
    ("A.7.12", N + "PE-4",  "medium"),
    ("A.7.13", N + "MA-2",  "medium"),
    ("A.7.14", N + "MP-6",  "high"),

    ("A.8.1",  N + "AC-19", "medium"),
    ("A.8.1",  N + "SI-3",  "medium"),
    ("A.8.2",  N + "AC-6",  "high"),
    ("A.8.3",  N + "AC-3",  "high"),
    ("A.8.4",  N + "CM-5",  "medium"),
    ("A.8.5",  N + "IA-2",  "high"),
    ("A.8.6",  N + "SC-5",  "low"),
    ("A.8.7",  N + "SI-3",  "high"),
    ("A.8.8",  N + "RA-5",  "high"),
    ("A.8.8",  N + "SI-2",  "high"),
    ("A.8.9",  N + "CM-6",  "high"),
    ("A.8.9",  N + "CM-2",  "medium"),
    ("A.8.10", N + "SI-12", "medium"),
    ("A.8.11", N + "SI-19", "low"),
    ("A.8.12", N + "SC-7",  "low"),
    ("A.8.13", N + "CP-9",  "high"),
    ("A.8.14", N + "CP-7",  "medium"),
    ("A.8.15", N + "AU-2",  "high"),
    ("A.8.15", N + "AU-12", "medium"),
    ("A.8.16", N + "SI-4",  "high"),
    ("A.8.16", C + "DE.CM-01", "high"),
    ("A.8.17", N + "AU-8",  "high"),
    ("A.8.18", N + "AC-6",  "low"),
    ("A.8.19", N + "CM-11", "high"),
    ("A.8.20", N + "SC-7",  "medium"),
    ("A.8.21", N + "SA-9",  "low"),
    ("A.8.22", N + "SC-7",  "medium"),
    ("A.8.23", N + "SC-7",  "low"),
    ("A.8.24", N + "SC-13", "high"),
    ("A.8.24", N + "SC-12", "medium"),
    ("A.8.25", N + "SA-3",  "high"),
    ("A.8.26", N + "SA-4",  "medium"),
    ("A.8.27", N + "SA-8",  "high"),
    ("A.8.28", N + "SA-11", "low"),
    ("A.8.29", N + "SA-11", "high"),
    ("A.8.29", N + "CA-8",  "medium"),
    ("A.8.30", N + "SA-4",  "low"),
    ("A.8.31", N + "CM-4",  "low"),
    ("A.8.32", N + "CM-3",  "high"),
    ("A.8.33", N + "SA-3",  "low"),
    ("A.8.34", N + "CA-2",  "low"),
]


if __name__ == "__main__":
    db = Neo4jClient()
    ok = crosswalk_loader.load(db, FRAMEWORK, REQUIREMENTS, MAPPINGS)
    db.close()
    sys.exit(0 if ok else 1)
