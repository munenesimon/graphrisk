from dotenv import load_dotenv
import os

load_dotenv()

NEO4J_URI      = os.getenv("NEO4J_URI",  "bolt://localhost:7687")
NEO4J_USER     = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
NVD_API_KEY       = os.getenv("NVD_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

NIST_CSF_URL      = "https://csrc.nist.gov/extensions/nudp/services/json/csf/download?olirids=all"
NIST_80053_URL    = "https://csrc.nist.gov/extensions/nudp/services/json/sp800-53/rev5/download?olirids=all"
MITRE_ATTACK_URL  = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
CISA_KEV_URL      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_CVE_URL       = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ATTACK_VERSION    = "19.1"
