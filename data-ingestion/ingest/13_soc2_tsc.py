"""
DS-13: SOC 2 readiness -- AICPA Trust Services Criteria (2017, points of
focus revised 2022) on the NIST crosswalk.

SOC 2 is not a standard an organisation "complies with" or a certificate:
it is an examination report on an organisation's controls against the Trust
Services Criteria (TSC), and only a CPA firm performing the engagement under
AICPA attestation standards can issue one. GraphRisk shows READINESS only and
never says "SOC 2 certified" or "SOC 2 compliant". "SOC 2" and the SOC logos
are AICPA marks; no logo is used.

The TSC are © AICPA. This loader stores ONLY the criterion identifiers
(CC1.1-CC9.2, A1, C1, PI1, P1-P8) and summaries GraphRisk wrote in its own
words -- never the criteria text or the points of focus. Organisations
preparing for an examination should use the AICPA's published criteria.

Scope: every SOC 2 report covers the common criteria (security, CC1-CC9).
Availability, confidentiality, processing integrity and privacy are optional
categories -- an organisation marks the ones outside its report scope "Not
applicable" so they leave its totals. Category "standard" (voluntary): it is
only an obligation if ticked in the regulatory profile. The privacy criteria
overlap the Kenya Data Protection Act 2019 (DS-10), which stays binding and
prevails where they differ.

MAPS_TO edges follow the AICPA's own published mapping of the 2017 TSC to
NIST SP 800-53 Rev5, expressed as GraphRisk's curated crosswalk (tagged
"GraphRisk curated" like DS-10/11/12) -- a mapping means "mapped controls are
in place", never "meets the criterion". Governance criteria GraphRisk can't
sensibly measure are left for the organisation to record. Not legal or audit
advice.

Usage (from the data-ingestion folder, .env pointing at the target graph):
    python ingest/13_soc2_tsc.py
Run DS-01/DS-02 (NIST) against the same graph first. Safe to re-run.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from neo4j_utils import Neo4jClient
import crosswalk_loader

N = "NIST_800_53_R5_"
C = "NIST_CSF_2_"

FRAMEWORK = {
    "id": "SOC2_TSC_2017",
    "label": "DS-13: SOC 2 readiness -- AICPA Trust Services Criteria (identifiers only)",
    "name": "SOC2_TSC",
    "version": "TSC 2017 (points of focus 2022)",
    "owner": "AICPA",
    "url": "https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022",
    "license_note": ("© AICPA -- GraphRisk stores criterion identifiers and its own summaries only. "
                     "Readiness view: only a CPA firm can issue a SOC 2 report."),
    "category": "standard",
}
SRC = "AICPA Trust Services Criteria (2017)"


def req(ref, domain, rtype, title, summary):
    """title/summary are GraphRisk's own wording, not AICPA text."""
    return {"ref": ref, "domain": domain, "requirement_type": rtype, "title": title,
            "summary": summary, "legal_source": f"{SRC}, {ref}", "notification": None}


CE, CI, RA, MO, CA = ("Control environment", "Communication", "Risk assessment",
                      "Monitoring", "Control activities")
AC, OP, CH, RM = "Access", "System operations", "Change management", "Risk mitigation"
AV, CO, PI, PR = ("Availability (optional)", "Confidentiality (optional)",
                  "Processing integrity (optional)", "Privacy (optional)")

REQUIREMENTS = [
    # ── Common criteria (security) -- in every SOC 2 report ──────────────────
    req("CC1.1", CE, "legal", "Integrity and ethics", "Leadership sets and upholds standards of integrity and ethical conduct."),
    req("CC1.2", CE, "legal", "Board oversight", "The board (or equivalent) is independent of management and oversees internal control."),
    req("CC1.3", CE, "process", "Structure and authority", "Reporting lines, authorities and responsibilities support the organisation's objectives."),
    req("CC1.4", CE, "process", "Competent people", "Attract, develop and keep people with the skills the objectives need."),
    req("CC1.5", CE, "legal", "Accountability", "People are held accountable for their internal-control responsibilities."),
    req("CC2.1", CI, "process", "Quality information", "Obtain and use relevant, good-quality information to run internal control."),
    req("CC2.2", CI, "process", "Internal communication", "Communicate control objectives and responsibilities inside the organisation, with a way to raise concerns."),
    req("CC2.3", CI, "legal", "External communication", "Communicate with customers, regulators and others about matters affecting internal control."),
    req("CC3.1", RA, "process", "Clear objectives", "Set objectives clearly enough that risks to them can be identified."),
    req("CC3.2", RA, "process", "Identify and analyse risks", "Identify risks to objectives across the organisation and analyse how to manage them."),
    req("CC3.3", RA, "process", "Fraud risk", "Consider the potential for fraud when assessing risks."),
    req("CC3.4", RA, "process", "Changes that affect risk", "Identify and assess changes that could significantly affect internal control."),
    req("CC4.1", MO, "process", "Evaluate controls", "Run ongoing and periodic checks that controls are present and working."),
    req("CC4.2", MO, "process", "Act on deficiencies", "Report control deficiencies promptly to those who can fix them."),
    req("CC5.1", CA, "process", "Choose control activities", "Select and build controls that bring risks down to acceptable levels."),
    req("CC5.2", CA, "process", "Technology controls", "Select and build general controls over technology."),
    req("CC5.3", CA, "process", "Policies and procedures", "Put controls into practice through policies and procedures."),
    req("CC6.1", AC, "technical", "Logical access protections", "Use access-control software, architecture and encryption to protect information assets."),
    req("CC6.2", AC, "technical", "Register and authorise users", "Register and approve users before issuing credentials; remove them when no longer needed."),
    req("CC6.3", AC, "technical", "Role-based, least-privilege access", "Grant, change and remove access by role, with least privilege and separation of duties."),
    req("CC6.4", AC, "process", "Physical access", "Restrict physical access to facilities and protected assets."),
    req("CC6.5", AC, "technical", "Retire assets safely", "Remove data and software protections properly when physical assets are disposed of."),
    req("CC6.6", AC, "technical", "External threats", "Protect against threats from outside the system's boundaries (firewalls, secure remote access)."),
    req("CC6.7", AC, "technical", "Protect data in transit and on media", "Restrict and protect how information is transmitted, moved or removed."),
    req("CC6.8", AC, "technical", "Malicious software", "Prevent or detect unauthorised or malicious software."),
    req("CC7.1", OP, "technical", "Detect vulnerabilities and config changes", "Use detection and monitoring to find configuration changes and new vulnerabilities."),
    req("CC7.2", OP, "technical", "Monitor for anomalies", "Monitor systems for anomalies that may indicate attacks, errors or failures."),
    req("CC7.3", OP, "process", "Evaluate security events", "Assess security events to decide whether they are incidents."),
    req("CC7.4", OP, "process", "Respond to incidents", "Respond to incidents with a defined programme to contain and fix them."),
    req("CC7.5", OP, "technical", "Recover from incidents", "Identify, develop and carry out activities to recover from incidents."),
    req("CC8.1", CH, "process", "Change management", "Authorise, design, test, approve and implement changes in a controlled way."),
    req("CC9.1", RM, "process", "Business disruption risk", "Identify and mitigate risks of business disruption."),
    req("CC9.2", RM, "process", "Vendor and partner risk", "Assess and manage risks from vendors and business partners."),

    # ── Availability ──────────────────────────────────────────────────────────
    req("A1.1", AV, "technical", "Capacity", "Monitor capacity and plan for demand so commitments can be met."),
    req("A1.2", AV, "technical", "Backups and recovery infrastructure", "Protect the environment and run backups and recovery infrastructure."),
    req("A1.3", AV, "process", "Test recovery", "Test recovery plan procedures."),

    # ── Confidentiality ───────────────────────────────────────────────────────
    req("C1.1", CO, "process", "Identify confidential information", "Identify and protect confidential information."),
    req("C1.2", CO, "technical", "Dispose of confidential information", "Dispose of confidential information when it is no longer needed."),

    # ── Processing integrity ─────────────────────────────────────────────────
    req("PI1.1", PI, "process", "Processing specifications", "Define and communicate what correct processing means for the system."),
    req("PI1.2", PI, "technical", "Inputs", "Check that system inputs are complete and accurate."),
    req("PI1.3", PI, "technical", "Processing", "Process data completely, accurately and on time."),
    req("PI1.4", PI, "technical", "Outputs", "Deliver complete, accurate output only to the intended parties."),
    req("PI1.5", PI, "technical", "Stored data", "Store inputs, in-progress items and outputs completely and accurately."),

    # ── Privacy (the Kenya DPA is the binding law here -- see DS-10) ──────────
    req("P1.1", PR, "legal", "Privacy notice", "Tell data subjects how their personal information is handled. (Kenya DPA s.29 applies.)"),
    req("P2.1", PR, "legal", "Choice and consent", "Give data subjects choices and get consent where needed. (Kenya DPA s.30, s.32.)"),
    req("P3.1", PR, "process", "Collect only what's needed", "Collect personal information only for stated purposes."),
    req("P3.2", PR, "legal", "Explicit consent", "Get explicit consent where the law or commitments require it."),
    req("P4.1", PR, "process", "Limit use", "Use personal information only for the purposes collected."),
    req("P4.2", PR, "technical", "Retention", "Keep personal information only as long as needed."),
    req("P4.3", PR, "technical", "Secure disposal", "Dispose of personal information securely."),
    req("P5.1", PR, "legal", "Access requests", "Let data subjects access their personal information. (Kenya DPA s.26.)"),
    req("P5.2", PR, "legal", "Corrections", "Correct personal information on request."),
    req("P6.1", PR, "legal", "Disclosure to third parties", "Disclose personal information to third parties only with consent or lawful basis."),
    req("P6.2", PR, "process", "Record authorised disclosures", "Keep a record of authorised disclosures."),
    req("P6.3", PR, "process", "Record unauthorised disclosures", "Keep a record of unauthorised disclosures and breaches."),
    req("P6.4", PR, "process", "Third-party commitments", "Bind third parties to privacy commitments."),
    req("P6.5", PR, "process", "Third parties report breaches", "Require third parties to report unauthorised disclosures."),
    req("P6.6", PR, "legal", "Notify of breaches",
        "Notify affected people and regulators of breaches. In Kenya the DPA's 72-hour notice to the "
        "Data Commissioner (s.43) is the binding duty."),
    req("P6.7", PR, "legal", "Account for disclosures", "Tell data subjects, on request, who their information was disclosed to."),
    req("P7.1", PR, "process", "Data quality", "Keep personal information accurate, complete and relevant."),
    req("P8.1", PR, "legal", "Privacy complaints", "Handle privacy inquiries, complaints and disputes."),
]

# GraphRisk's crosswalk onto NIST, following the AICPA's published TSC <->
# NIST 800-53 mapping. "legal" criteria are attestation-only and unmapped.
MAPPINGS = [
    ("CC1.3", N + "PM-2",  "medium"),
    ("CC1.4", N + "AT-3",  "medium"),
    ("CC1.4", N + "PS-3",  "low"),
    ("CC2.1", N + "PM-6",  "low"),
    ("CC2.2", N + "AT-2",  "medium"),
    ("CC3.1", N + "PM-11", "medium"),
    ("CC3.2", N + "RA-3",  "high"),
    ("CC3.2", C + "ID.RA-05", "medium"),
    ("CC3.3", N + "RA-3",  "low"),
    ("CC3.4", N + "CM-4",  "medium"),
    ("CC4.1", N + "CA-7",  "high"),
    ("CC4.1", N + "CA-2",  "medium"),
    ("CC4.2", N + "CA-5",  "high"),
    ("CC5.1", N + "PM-9",  "medium"),
    ("CC5.2", N + "PL-1",  "low"),
    ("CC5.3", N + "PL-1",  "medium"),
    ("CC6.1", N + "AC-3",  "high"),
    ("CC6.1", N + "SC-28", "medium"),
    ("CC6.1", N + "CM-8",  "medium"),
    ("CC6.2", N + "AC-2",  "high"),
    ("CC6.2", N + "IA-4",  "medium"),
    ("CC6.3", N + "AC-6",  "high"),
    ("CC6.3", N + "AC-5",  "medium"),
    ("CC6.4", N + "PE-3",  "high"),
    ("CC6.5", N + "MP-6",  "high"),
    ("CC6.6", N + "SC-7",  "high"),
    ("CC6.6", N + "AC-17", "medium"),
    ("CC6.6", N + "IA-2",  "medium"),
    ("CC6.7", N + "SC-8",  "high"),
    ("CC6.7", N + "MP-7",  "medium"),
    ("CC6.8", N + "SI-3",  "high"),
    ("CC6.8", N + "CM-7",  "medium"),
    ("CC7.1", N + "RA-5",  "high"),
    ("CC7.1", N + "CM-6",  "high"),
    ("CC7.1", N + "SI-2",  "medium"),
    ("CC7.2", N + "SI-4",  "high"),
    ("CC7.2", N + "AU-6",  "medium"),
    ("CC7.2", C + "DE.CM-01", "high"),
    ("CC7.3", N + "IR-4",  "medium"),
    ("CC7.4", N + "IR-4",  "high"),
    ("CC7.4", N + "IR-8",  "medium"),
    ("CC7.5", N + "CP-10", "high"),
    ("CC7.5", N + "IR-4",  "low"),
    ("CC8.1", N + "CM-3",  "high"),
    ("CC9.1", N + "CP-2",  "high"),
    ("CC9.2", N + "SR-6",  "medium"),
    ("CC9.2", N + "SA-9",  "medium"),

    ("A1.1",  N + "SC-5",  "low"),
    ("A1.2",  N + "CP-9",  "high"),
    ("A1.2",  N + "PE-13", "low"),
    ("A1.3",  N + "CP-4",  "high"),

    ("C1.1",  N + "RA-2",  "medium"),
    ("C1.1",  N + "SC-28", "medium"),
    ("C1.2",  N + "MP-6",  "high"),

    ("PI1.1", N + "SA-4",  "low"),
    ("PI1.2", N + "SI-10", "high"),
    ("PI1.3", N + "SI-7",  "medium"),
    ("PI1.4", N + "SI-15", "medium"),
    ("PI1.5", N + "SC-28", "low"),

    ("P3.1",  N + "PT-2",  "medium"),
    ("P4.1",  N + "PT-3",  "medium"),
    ("P4.2",  N + "SI-12", "high"),
    ("P4.3",  N + "MP-6",  "medium"),
    ("P6.2",  N + "AU-2",  "low"),
    ("P6.3",  N + "IR-6",  "medium"),
    ("P6.4",  N + "SA-9",  "medium"),
    ("P6.5",  N + "IR-6",  "low"),
    ("P7.1",  N + "SI-18", "medium"),
]


if __name__ == "__main__":
    db = Neo4jClient()
    ok = crosswalk_loader.load(db, FRAMEWORK, REQUIREMENTS, MAPPINGS)
    db.close()
    sys.exit(0 if ok else 1)
