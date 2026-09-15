import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from neo4j_utils import Neo4jClient

CSF_DATA = [
  ("GV","Govern","GV.OC","GV.OC-01","Organizational context, mission, stakeholder expectations, and legal/regulatory requirements are understood"),
  ("GV","Govern","GV.OC","GV.OC-02","Internal and external stakeholders are understood"),
  ("GV","Govern","GV.OC","GV.OC-03","Legal, regulatory, and contractual requirements regarding cybersecurity are understood"),
  ("GV","Govern","GV.OC","GV.OC-04","Critical objectives, capabilities, and services are understood"),
  ("GV","Govern","GV.OC","GV.OC-05","Outcomes, capabilities, and services that the organization depends on are understood"),
  ("GV","Govern","GV.RM","GV.RM-01","Risk management objectives are established and agreed to by organizational stakeholders"),
  ("GV","Govern","GV.RM","GV.RM-02","Risk appetite and risk tolerance statements are established"),
  ("GV","Govern","GV.RM","GV.RM-03","Cybersecurity risk management activities and outcomes are included in enterprise risk management processes"),
  ("GV","Govern","GV.RM","GV.RM-04","Strategic direction that describes appropriate risk response options is established"),
  ("GV","Govern","GV.RM","GV.RM-05","Lines of communication across the organization are established for cybersecurity risks"),
  ("GV","Govern","GV.RM","GV.RM-06","A standardized method for calculating, documenting, categorizing, and prioritizing cybersecurity risks is established"),
  ("GV","Govern","GV.RM","GV.RM-07","Strategic opportunities are characterized to inform risk decisions"),
  ("GV","Govern","GV.RR","GV.RR-01","Organizational leadership is responsible and accountable for cybersecurity risk"),
  ("GV","Govern","GV.RR","GV.RR-02","Roles, responsibilities, and authorities related to cybersecurity risk management are established"),
  ("GV","Govern","GV.RR","GV.RR-03","Adequate resources are allocated commensurate with the cybersecurity risk strategy"),
  ("GV","Govern","GV.RR","GV.RR-04","Cybersecurity is included in human resources practices"),
  ("GV","Govern","GV.PO","GV.PO-01","Policy for managing cybersecurity risks is established based on organizational context"),
  ("GV","Govern","GV.PO","GV.PO-02","Policy for managing cybersecurity risks is reviewed, updated, communicated, and enforced"),
  ("GV","Govern","GV.OV","GV.OV-01","Cybersecurity risk management strategy outcomes are reviewed to inform and adjust strategy and direction"),
  ("GV","Govern","GV.OV","GV.OV-02","The cybersecurity risk management strategy is reviewed and adjusted to ensure coverage of organizational requirements"),
  ("GV","Govern","GV.OV","GV.OV-03","Organizational cybersecurity risk management performance is evaluated and reviewed"),
  ("GV","Govern","GV.SC","GV.SC-01","A cybersecurity supply chain risk management program is established"),
  ("GV","Govern","GV.SC","GV.SC-02","Cybersecurity roles and responsibilities for suppliers, customers, and partners are established"),
  ("GV","Govern","GV.SC","GV.SC-03","Cybersecurity supply chain risk management is integrated into cybersecurity and enterprise risk management"),
  ("GV","Govern","GV.SC","GV.SC-04","Suppliers are known and prioritized by criticality"),
  ("GV","Govern","GV.SC","GV.SC-05","Requirements to address cybersecurity risks in supply chains are established"),
  ("GV","Govern","GV.SC","GV.SC-06","Planning and due diligence are performed to reduce risks before entering into formal supplier or other third-party relationships"),
  ("GV","Govern","GV.SC","GV.SC-07","The risks posed by a supplier, their products and services, and other third parties are understood"),
  ("GV","Govern","GV.SC","GV.SC-08","Relevant suppliers and other third parties are included in incident planning"),
  ("GV","Govern","GV.SC","GV.SC-09","Supply chain security practices are integrated into cybersecurity and enterprise risk management programs"),
  ("GV","Govern","GV.SC","GV.SC-10","Cybersecurity supply chain risk management plans include provisions for activities that occur after the conclusion of a partnership or service agreement"),
  ("ID","Identify","ID.AM","ID.AM-01","Inventories of hardware managed by the organization are maintained"),
  ("ID","Identify","ID.AM","ID.AM-02","Inventories of software, services, and systems managed by the organization are maintained"),
  ("ID","Identify","ID.AM","ID.AM-03","Representations of the authorized network communication and data flows are maintained"),
  ("ID","Identify","ID.AM","ID.AM-04","Inventories of services provided by suppliers are maintained"),
  ("ID","Identify","ID.AM","ID.AM-05","Assets are prioritized based on classification, criticality, resources, and impact on the mission"),
  ("ID","Identify","ID.AM","ID.AM-07","Inventories of data and corresponding metadata for designated data types are maintained"),
  ("ID","Identify","ID.AM","ID.AM-08","Systems, hardware, software, services, and data are managed throughout their life cycles"),
  ("ID","Identify","ID.RA","ID.RA-01","Vulnerabilities in assets are identified, validated, and recorded"),
  ("ID","Identify","ID.RA","ID.RA-02","Cyber threat intelligence is received from information sharing forums and sources"),
  ("ID","Identify","ID.RA","ID.RA-03","Internal and external threats to the organization are identified and recorded"),
  ("ID","Identify","ID.RA","ID.RA-04","Potential impacts and likelihoods of threats exploiting vulnerabilities are identified"),
  ("ID","Identify","ID.RA","ID.RA-05","Threats, vulnerabilities, likelihoods, and impacts are used to understand inherent risk"),
  ("ID","Identify","ID.RA","ID.RA-06","Risk responses are chosen, prioritized, planned, tracked, and communicated"),
  ("ID","Identify","ID.RA","ID.RA-07","Changes and exceptions are managed, assessed for risk impact, recorded, and tracked"),
  ("ID","Identify","ID.RA","ID.RA-08","Processes for receiving, analyzing, and responding to vulnerability disclosures are established"),
  ("ID","Identify","ID.RA","ID.RA-09","The authenticity and integrity of hardware and software are assessed prior to acquisition"),
  ("ID","Identify","ID.RA","ID.RA-10","Critical suppliers are assessed prior to acquisition"),
  ("ID","Identify","ID.IM","ID.IM-01","Improvements are identified from evaluations"),
  ("ID","Identify","ID.IM","ID.IM-02","Improvements are identified from security tests and exercises"),
  ("ID","Identify","ID.IM","ID.IM-03","Improvements are identified from execution of operational processes and activities"),
  ("ID","Identify","ID.IM","ID.IM-04","Incident response plans and other cybersecurity plans that affect operations are established"),
  ("PR","Protect","PR.AA","PR.AA-01","Identities and credentials for authorized users, services, and hardware are managed"),
  ("PR","Protect","PR.AA","PR.AA-02","Identities are proofed and bound to credentials based on the context of interactions"),
  ("PR","Protect","PR.AA","PR.AA-03","Users, services, and hardware are authenticated"),
  ("PR","Protect","PR.AA","PR.AA-04","Identity assertions are protected, conveyed, and verified"),
  ("PR","Protect","PR.AA","PR.AA-05","Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed"),
  ("PR","Protect","PR.AA","PR.AA-06","Physical access to assets is managed, monitored, and enforced commensurate with risk"),
  ("PR","Protect","PR.AT","PR.AT-01","Personnel are provided with awareness and training so they possess knowledge to perform general tasks with cybersecurity risks in mind"),
  ("PR","Protect","PR.AT","PR.AT-02","Individuals in specialized roles are provided with awareness and training for relevant tasks"),
  ("PR","Protect","PR.DS","PR.DS-01","The confidentiality, integrity, and availability of data-at-rest are protected"),
  ("PR","Protect","PR.DS","PR.DS-02","The confidentiality, integrity, and availability of data-in-transit are protected"),
  ("PR","Protect","PR.DS","PR.DS-10","The confidentiality, integrity, and availability of data-in-use are protected"),
  ("PR","Protect","PR.DS","PR.DS-11","Backups of data are created, protected, maintained, and tested"),
  ("PR","Protect","PR.PS","PR.PS-01","Configuration management practices are established and applied"),
  ("PR","Protect","PR.PS","PR.PS-02","Software is maintained, replaced, and removed commensurate with risk"),
  ("PR","Protect","PR.PS","PR.PS-03","Hardware is maintained, replaced, and removed commensurate with risk"),
  ("PR","Protect","PR.PS","PR.PS-04","Log records are generated and made available for continuous monitoring"),
  ("PR","Protect","PR.PS","PR.PS-05","Installation and execution of unauthorized software are prevented"),
  ("PR","Protect","PR.PS","PR.PS-06","Secure software development practices are integrated into the software development life cycle"),
  ("PR","Protect","PR.IR","PR.IR-01","Networks and environments are protected from unauthorized logical access and usage"),
  ("PR","Protect","PR.IR","PR.IR-02","The organization's technology assets are protected from environmental threats"),
  ("PR","Protect","PR.IR","PR.IR-03","Mechanisms are implemented to achieve resilience requirements in normal and adverse situations"),
  ("PR","Protect","PR.IR","PR.IR-04","Adequate resource capacity to ensure availability is maintained"),
  ("DE","Detect","DE.CM","DE.CM-01","Networks and network services are monitored to find potentially adverse events"),
  ("DE","Detect","DE.CM","DE.CM-02","The physical environment is monitored to find potentially adverse events"),
  ("DE","Detect","DE.CM","DE.CM-03","Personnel activity and technology usage are monitored to find potentially adverse events"),
  ("DE","Detect","DE.CM","DE.CM-06","External service provider activities and services are monitored to find potentially adverse events"),
  ("DE","Detect","DE.CM","DE.CM-09","Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events"),
  ("DE","Detect","DE.AE","DE.AE-02","Potentially adverse events are analyzed to better understand associated activities"),
  ("DE","Detect","DE.AE","DE.AE-03","Information is correlated from multiple sources"),
  ("DE","Detect","DE.AE","DE.AE-04","The estimated impact and scope of adverse events are understood"),
  ("DE","Detect","DE.AE","DE.AE-06","Information on adverse events is provided to authorized staff and tools"),
  ("DE","Detect","DE.AE","DE.AE-07","Cyber threat intelligence and other contextual information are integrated into the analysis"),
  ("DE","Detect","DE.AE","DE.AE-08","Incidents are declared when adverse events meet the defined criteria"),
  ("RS","Respond","RS.MA","RS.MA-01","The incident response plan is executed in coordination with relevant third parties once an incident is declared"),
  ("RS","Respond","RS.MA","RS.MA-02","Incident reports are triaged and validated"),
  ("RS","Respond","RS.MA","RS.MA-03","Incidents are categorized and prioritized"),
  ("RS","Respond","RS.MA","RS.MA-04","Incidents are escalated or elevated as needed"),
  ("RS","Respond","RS.MA","RS.MA-05","The criteria for initiating incident recovery are applied"),
  ("RS","Respond","RS.AN","RS.AN-03","Analysis is performed to establish what has taken place during an incident and the root cause"),
  ("RS","Respond","RS.AN","RS.AN-06","Actions performed during an investigation are recorded"),
  ("RS","Respond","RS.AN","RS.AN-07","Incident data and metadata are collected and their integrity and provenance are preserved"),
  ("RS","Respond","RS.AN","RS.AN-08","An incident magnitude is estimated and validated"),
  ("RS","Respond","RS.CO","RS.CO-02","Internal and external stakeholders are notified of incidents"),
  ("RS","Respond","RS.CO","RS.CO-03","Information is shared with designated internal and external stakeholders"),
  ("RS","Respond","RS.MI","RS.MI-01","Incidents are contained"),
  ("RS","Respond","RS.MI","RS.MI-02","Incidents are eradicated"),
  ("RC","Recover","RC.RP","RC.RP-01","The recovery portion of the incident response plan is executed once initiated"),
  ("RC","Recover","RC.RP","RC.RP-02","Recovery actions are selected, scoped, prioritized, and performed"),
  ("RC","Recover","RC.RP","RC.RP-03","The integrity of backups and other restoration assets is verified before using them for restoration"),
  ("RC","Recover","RC.RP","RC.RP-04","Critical mission functions and cybersecurity capabilities are re-established"),
  ("RC","Recover","RC.RP","RC.RP-05","The integrity of restored assets is verified, systems and services are restored, and normal operating status is confirmed"),
  ("RC","Recover","RC.RP","RC.RP-06","The end of incident recovery is declared based on criteria"),
  ("RC","Recover","RC.CO","RC.CO-03","Recovery activities and progress in restoring operational capabilities are communicated to designated internal and external stakeholders"),
  ("RC","Recover","RC.CO","RC.CO-04","Public updates on incident recovery are shared using approved methods and messaging"),
]

MERGE_FRAMEWORK = """
    MERGE (f:Framework {id: "NIST_CSF_2"})
    SET f.name="NIST_CSF", f.version="2.0", f.owner="NIST",
        f.url="https://www.nist.gov/cyberframework"
    RETURN f.id AS id
"""

MERGE_CONTROLS = """
    UNWIND $batch AS row
    MERGE (fc:FrameworkControl {id: row.id})
    SET fc.control_reference = row.ref,
        fc.title             = row.title,
        fc.domain            = row.domain,
        fc.function          = row.function,
        fc.function_id       = row.function_id,
        fc.official_url      = row.url
    WITH fc
    MATCH (f:Framework {id: "NIST_CSF_2"})
    MERGE (fc)-[:PART_OF]->(f)
"""

def ingest():
    print("=" * 55)
    print("  DS-01: NIST CSF 2.0 Ingestion")
    print("=" * 55)
    print("\n[1/3] Building batch from embedded CSF 2.0 data...")
    batch = []
    for fn_id, fn_name, cat, ref, title in CSF_DATA:
        batch.append({
            "id":          f"NIST_CSF_2_{ref}",
            "ref":         ref,
            "title":       title,
            "domain":      cat,
            "function":    fn_name,
            "function_id": fn_id,
            "url":         f"https://www.nist.gov/cyberframework"
        })
    print(f"  {len(batch)} subcategories ready")
    print("\n[2/3] Creating Framework node...")
    db = Neo4jClient()
    db.run(MERGE_FRAMEWORK)
    print("  Framework node: NIST_CSF_2 created")
    print("\n[3/3] Loading controls into Neo4j...")
    db.run_batch(MERGE_CONTROLS, batch)
    db.close()
    print("\n" + "=" * 55)
    print("  NIST CSF 2.0 Ingestion Complete")
    print("=" * 55)
    print(f"  Controls loaded : {len(batch)}")
    print(f"  Functions       : GV, ID, PR, DE, RS, RC")
    print("\n  Verify in Neo4j Browser:")
    print("  MATCH (fc:FrameworkControl)-[:PART_OF]->(f:Framework {id:'NIST_CSF_2'})")
    print("  RETURN count(fc) AS total")
    print("=" * 55)

if __name__ == "__main__":
    ingest()
