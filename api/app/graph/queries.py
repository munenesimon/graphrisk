# All Cypher queries

GET_ALL_ASSETS = """
    MATCH (a:Asset {tenant_id: $tenant_id})
    RETURN a.id AS id, a.name AS name, a.asset_type AS asset_type,
           a.criticality AS criticality, a.owner AS owner, a.environment AS environment
    ORDER BY a.criticality, a.name
"""

GET_ASSET_BY_ID = """
    MATCH (a:Asset {id: $asset_id, tenant_id: $tenant_id})
    OPTIONAL MATCH (a)-[:SUPPORTS]->(bp:BusinessProcess)
    OPTIONAL MATCH (v:Vulnerability)-[:EXPOSES]->(a)
    RETURN a.id AS id, a.name AS name, a.asset_type AS asset_type,
           a.criticality AS criticality, a.owner AS owner, a.environment AS environment,
           collect(DISTINCT bp.name) AS business_processes,
           collect(DISTINCT v.cve_id)[..5] AS recent_vulnerabilities
"""

CREATE_ASSET = """
    CREATE (a:Asset {
        id: $id, name: $name, asset_type: $asset_type,
        criticality: $criticality, owner: $owner,
        environment: $environment, tenant_id: $tenant_id, created_at: datetime()
    })
    RETURN a.id AS id
"""

GET_ALL_RISKS = """
    MATCH (r:Risk {tenant_id: $tenant_id})
    RETURN r.id AS id, r.title AS title, r.likelihood AS likelihood,
           r.impact AS impact, r.risk_score AS risk_score,
           r.status AS status, r.owner AS owner
    ORDER BY r.risk_score DESC
"""

GET_RISK_BY_ID = """
    MATCH (r:Risk {id: $risk_id, tenant_id: $tenant_id})
    OPTIONAL MATCH (c:Control)-[:MITIGATES]->(r)
    OPTIONAL MATCH (r)-[:IMPACTS]->(a:Asset)
    RETURN r.id AS id, r.title AS title, r.description AS description,
           r.likelihood AS likelihood, r.impact AS impact,
           r.risk_score AS risk_score, r.status AS status,
           collect(DISTINCT c.title) AS mitigating_controls,
           collect(DISTINCT a.name)  AS affected_assets
"""

CREATE_RISK = """
    CREATE (r:Risk {
        id: $id, title: $title, description: $description,
        likelihood: $likelihood, impact: $impact, risk_score: $risk_score,
        status: $status, owner: $owner, tenant_id: $tenant_id, created_at: datetime()
    })
    RETURN r.id AS id
"""

GET_ALL_CONTROLS = """
    MATCH (c:Control {tenant_id: $tenant_id})
    RETURN c.id AS id, c.title AS title, c.control_type AS control_type,
           c.implementation_status AS implementation_status,
           c.effectiveness_score AS effectiveness_score,
           c.owner AS owner, c.last_tested_at AS last_tested_at
    ORDER BY c.implementation_status, c.title
"""

GET_CONTROL_BY_ID = """
    MATCH (c:Control {id: $control_id, tenant_id: $tenant_id})
    OPTIONAL MATCH (c)-[:MITIGATES]->(r:Risk)
    OPTIONAL MATCH (c)-[:SATISFIES]->(fc:FrameworkControl)-[:PART_OF]->(f:Framework)
    OPTIONAL MATCH (e:Evidence)-[:VALIDATES]->(c)
    RETURN c.id AS id, c.title AS title, c.description AS description,
           c.control_type AS control_type,
           c.implementation_status AS implementation_status,
           c.effectiveness_score AS effectiveness_score, c.owner AS owner,
           collect(DISTINCT r.title) AS risks_mitigated,
           collect(DISTINCT f.name)  AS frameworks_covered,
           collect(DISTINCT e.title) AS evidence_items
"""

CREATE_CONTROL = """
    CREATE (c:Control {
        id: $id, title: $title, description: $description,
        control_type: $control_type, implementation_status: $implementation_status,
        effectiveness_score: $effectiveness_score, owner: $owner,
        tenant_id: $tenant_id, created_at: datetime()
    })
    RETURN c.id AS id
"""

GET_ALL_FRAMEWORKS = """
    MATCH (f:Framework)
    OPTIONAL MATCH (fc:FrameworkControl)-[:PART_OF]->(f)
    RETURN f.id AS id, f.name AS name, f.version AS version,
           f.owner AS owner, f.url AS url, count(fc) AS total_controls
    ORDER BY f.name
"""

GET_FRAMEWORK_CONTROLS = """
    MATCH (fc:FrameworkControl)-[:PART_OF]->(f:Framework {id: $framework_id})
    RETURN fc.id AS id, fc.control_reference AS control_reference,
           fc.title AS title, fc.domain AS domain,
           fc.graphrisk_summary AS summary, fc.official_url AS official_url
    ORDER BY fc.control_reference
"""

GET_FRAMEWORK_COVERAGE = """
    MATCH (fc:FrameworkControl)-[:PART_OF]->(f:Framework {id: $framework_id})
    OPTIONAL MATCH (c:Control {tenant_id: $tenant_id})-[:SATISFIES]->(fc)
    RETURN f.name AS framework, count(fc) AS total_controls,
           count(c) AS covered_controls,
           round(toFloat(count(c)) / count(fc) * 100, 1) AS coverage_pct
"""

BLAST_RADIUS_CONTROL = """
    MATCH (c:Control {id: $control_id, tenant_id: $tenant_id})
    OPTIONAL MATCH (c)-[:MITIGATES]->(r:Risk)
    OPTIONAL MATCH (r)-[:IMPACTS]->(a:Asset)
    OPTIONAL MATCH (a)-[:SUPPORTS]->(bp:BusinessProcess)
    OPTIONAL MATCH (c)-[:SATISFIES]->(fc:FrameworkControl)-[:PART_OF]->(f:Framework)
    RETURN c.title AS control_title, c.implementation_status AS control_status,
           c.effectiveness_score AS effectiveness_score,
           collect(DISTINCT r.title)  AS exposed_risks,
           collect(DISTINCT a.name)   AS affected_assets,
           collect(DISTINCT bp.name)  AS impacted_processes,
           collect(DISTINCT f.name)   AS compliance_gaps,
           collect(DISTINCT fc.control_reference) AS framework_controls,
           size(collect(DISTINCT r))  AS risk_count,
           size(collect(DISTINCT a))  AS asset_count,
           size(collect(DISTINCT f))  AS framework_count
"""

BLAST_RADIUS_TECHNIQUE = """
    MATCH (tech:Technique {technique_id: $technique_id})
    OPTIONAL MATCH (tech)-[:MITIGATES]->(fc:FrameworkControl)
    OPTIONAL MATCH (fc)-[:PART_OF]->(f:Framework)
    RETURN tech.name AS technique_name, tech.technique_id AS technique_id,
           collect(DISTINCT fc.control_reference) AS controls_mitigated,
           collect(DISTINCT f.name) AS frameworks_covered,
           size(collect(DISTINCT fc)) AS control_count,
           size(collect(DISTINCT f))  AS framework_count
"""

VENDOR_BREACH_CASCADE = """
    MATCH (v:Vendor {id: $vendor_id, tenant_id: $tenant_id})
    OPTIONAL MATCH (v)-[:PROVIDES]->(a:Asset)
    OPTIONAL MATCH (a)-[:SUPPORTS]->(bp:BusinessProcess)
    OPTIONAL MATCH (r:Risk)-[:IMPACTS]->(a)
    OPTIONAL MATCH (c:Control)-[:MITIGATES]->(r)
    WHERE c.implementation_status <> "Implemented"
    RETURN v.name AS vendor_name,
           collect(DISTINCT a.name)  AS exposed_assets,
           collect(DISTINCT bp.name) AS impacted_processes,
           collect(DISTINCT r.title) AS activated_risks,
           collect(DISTINCT c.title) AS missing_controls,
           size(collect(DISTINCT a)) AS asset_count,
           size(collect(DISTINCT r)) AS risk_count
"""

DASHBOARD_SUMMARY = """
    OPTIONAL MATCH (r:Risk {tenant_id: $tenant_id})
    OPTIONAL MATCH (c:Control {tenant_id: $tenant_id})
    OPTIONAL MATCH (a:Asset {tenant_id: $tenant_id})
    RETURN count(DISTINCT r) AS total_risks, count(DISTINCT c) AS total_controls,
           count(DISTINCT a) AS total_assets, avg(r.risk_score) AS avg_risk_score,
           sum(CASE WHEN r.status = "Open" THEN 1 ELSE 0 END) AS open_risks,
           sum(CASE WHEN c.implementation_status = "Implemented" THEN 1 ELSE 0 END) AS implemented_controls
"""

TOP_RISKS = """
    MATCH (r:Risk {tenant_id: $tenant_id, status: "Open"})
    RETURN r.id AS id, r.title AS title, r.risk_score AS risk_score,
           r.likelihood AS likelihood, r.impact AS impact
    ORDER BY r.risk_score DESC LIMIT 5
"""

VULNERABILITY_STATS = """
    MATCH (v:Vulnerability)
    RETURN v.source AS source, count(v) AS total,
           sum(CASE WHEN v.ransomware_use = "Known" THEN 1 ELSE 0 END) AS ransomware_count
    ORDER BY total DESC
"""
