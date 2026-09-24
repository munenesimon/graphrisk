
class DashboardSummary {
  final int    totalRisks;
  final int    openRisks;
  final double avgScore;
  final int    totalControls;
  final int    implementedControls;
  final int    totalAssets;
  final List<TopRisk> topRisks;

  DashboardSummary({
    required this.totalRisks,
    required this.openRisks,
    required this.avgScore,
    required this.totalControls,
    required this.implementedControls,
    required this.totalAssets,
    required this.topRisks,
  });

  factory DashboardSummary.fromJson(Map<String, dynamic> j) => DashboardSummary(
    totalRisks:          j['risks']['total']       ?? 0,
    openRisks:           j['risks']['open']        ?? 0,
    avgScore:            (j['risks']['avg_score']  ?? 0).toDouble(),
    totalControls:       j['controls']['total']    ?? 0,
    implementedControls: j['controls']['implemented'] ?? 0,
    totalAssets:         j['assets']['total']      ?? 0,
    topRisks: (j['risks']['top_risks'] as List? ?? [])
        .map((r) => TopRisk.fromJson(r)).toList(),
  );
}

class TopRisk {
  final String id;
  final String title;
  final double riskScore;
  final int    likelihood;
  final int    impact;

  TopRisk({required this.id, required this.title,
           required this.riskScore, required this.likelihood, required this.impact});

  factory TopRisk.fromJson(Map<String, dynamic> j) => TopRisk(
    id:         j['id']         ?? '',
    title:      j['title']      ?? '',
    riskScore:  (j['risk_score'] ?? 0).toDouble(),
    likelihood: j['likelihood'] ?? 0,
    impact:     j['impact']     ?? 0,
  );
}

class BlastRadius {
  final String       controlTitle;
  final String       controlStatus;
  final double       effectivenessScore;
  final List<String> exposedRisks;
  final List<String> affectedAssets;
  final List<String> complianceGaps;
  final List<String> frameworkControls;
  final int          riskCount;
  final int          assetCount;
  final int          frameworkCount;
  // Kenya-regulation additions -- see README's "Regulatory crosswalk" /
  // "Regulatory notification clocks" sections for the backend semantics.
  final String                scope;
  final FrameworkGroups       frameworkGroups;
  final List<String>          mappedFrameworkControls;
  final RegulatoryObligations regulatoryObligations;

  BlastRadius({
    required this.controlTitle,
    required this.controlStatus,
    required this.effectivenessScore,
    required this.exposedRisks,
    required this.affectedAssets,
    required this.complianceGaps,
    required this.frameworkControls,
    required this.riskCount,
    required this.assetCount,
    required this.frameworkCount,
    required this.scope,
    required this.frameworkGroups,
    required this.mappedFrameworkControls,
    required this.regulatoryObligations,
  });

  factory BlastRadius.fromJson(Map<String, dynamic> j) {
    final br = j['blast_radius'] as Map<String, dynamic>? ?? {};
    final sm = j['summary']     as Map<String, dynamic>? ?? {};
    return BlastRadius(
      controlTitle:       j['control_title']      ?? '',
      controlStatus:      j['control_status']     ?? '',
      effectivenessScore: (j['effectiveness_score'] ?? 0).toDouble(),
      exposedRisks:       List<String>.from(br['exposed_risks']      ?? []),
      affectedAssets:     List<String>.from(br['affected_assets']    ?? []),
      complianceGaps:     List<String>.from(br['compliance_gaps']    ?? []),
      frameworkControls:  List<String>.from(br['framework_controls'] ?? []),
      riskCount:          sm['risk_count']      ?? 0,
      assetCount:         sm['asset_count']     ?? 0,
      frameworkCount:     sm['framework_count'] ?? 0,
      scope:                   j['scope']?.toString() ?? 'all',
      frameworkGroups:         FrameworkGroups.fromJson(br['frameworks'] as Map<String, dynamic>?),
      mappedFrameworkControls: List<String>.from(br['mapped_framework_controls'] ?? []),
      regulatoryObligations:   RegulatoryObligations.fromJson(j['regulatory_obligations'] as Map<String, dynamic>?),
    );
  }
}

/// A control's frameworks split into voluntary standards (always shown),
/// regulations the tenant has declared itself subject to, and -- only when
/// the blast-radius query was run with scope=all -- regulations it isn't
/// subject to. Mirrors blast_radius.py's `_group_frameworks`.
class FrameworkGroups {
  final List<String> standards;
  final List<String> yourRegulations;
  final List<String> otherRegulations;

  FrameworkGroups({
    required this.standards,
    required this.yourRegulations,
    required this.otherRegulations,
  });

  factory FrameworkGroups.fromJson(Map<String, dynamic>? j) {
    if (j == null) return FrameworkGroups(standards: [], yourRegulations: [], otherRegulations: []);
    return FrameworkGroups(
      standards:        List<String>.from(j['standards'] ?? []),
      yourRegulations:  List<String>.from(j['your_regulations'] ?? []),
      otherRegulations: List<String>.from(j['other_regulations'] ?? []),
    );
  }
}

/// One notification duty ("tell the ODPC within 72 hours") that would apply
/// if the exposed assets were involved in a breach or incident. See
/// blast_radius.py's CLOCK_NOTE for the exact caveat this data carries.
class RegulatoryObligation {
  final String       frameworkId;
  final String       framework;
  final String       requirement;
  final String       title;
  final String       notify;
  final int          deadlineHours;
  final String       trigger;
  final String?      condition;
  final String?      legalSource;
  final List<String> triggeredByAssets;

  RegulatoryObligation({
    required this.frameworkId,
    required this.framework,
    required this.requirement,
    required this.title,
    required this.notify,
    required this.deadlineHours,
    required this.trigger,
    this.condition,
    this.legalSource,
    required this.triggeredByAssets,
  });

  factory RegulatoryObligation.fromJson(Map<String, dynamic> j) => RegulatoryObligation(
    frameworkId:       j['framework_id']?.toString() ?? '',
    framework:         j['framework']?.toString()    ?? '',
    requirement:       j['requirement']?.toString()  ?? '',
    title:             j['title']?.toString()         ?? '',
    notify:            j['notify']?.toString()        ?? '',
    deadlineHours:     j['deadline_hours'] is num ? (j['deadline_hours'] as num).toInt() : 0,
    trigger:           j['trigger']?.toString()       ?? '',
    condition:         j['condition']?.toString(),
    legalSource:       j['legal_source']?.toString(),
    triggeredByAssets: List<String>.from(j['triggered_by_assets'] ?? []),
  );
}

/// Wraps a list of [RegulatoryObligation]s with the caveat note the API
/// always sends, and -- only when the list is empty -- an optional hint
/// (e.g. "no regulatory profile set") explaining why.
class RegulatoryObligations {
  final String                     note;
  final List<RegulatoryObligation> obligations;
  final String?                    hint;

  RegulatoryObligations({required this.note, required this.obligations, this.hint});

  factory RegulatoryObligations.fromJson(Map<String, dynamic>? j) {
    if (j == null) return RegulatoryObligations(note: '', obligations: const []);
    return RegulatoryObligations(
      note: j['note']?.toString() ?? '',
      obligations: (j['obligations'] as List? ?? [])
          .map((o) => RegulatoryObligation.fromJson(o as Map<String, dynamic>))
          .toList(),
      hint: j['hint']?.toString(),
    );
  }
}

/// A framework as it appears inside a [RegulatoryProfile] -- id + display
/// fields, as opposed to the plain framework-id strings the PUT endpoint
/// takes to set the profile.
class FrameworkRef {
  final String id;
  final String name;
  final String version;

  FrameworkRef({required this.id, required this.name, required this.version});

  factory FrameworkRef.fromJson(Map<String, dynamic> j) => FrameworkRef(
    id:      j['id']?.toString()      ?? '',
    name:    j['name']?.toString()    ?? '',
    version: j['version']?.toString() ?? '',
  );
}

/// GET/PUT /organisation/regulatory-profile -- which frameworks the tenant
/// is legally subject to, plus any qualifiers that narrow specific duties
/// (see organisation.py's AVAILABLE_QUALIFIERS, sent by the server so the
/// client never has to hardcode what they mean).
class RegulatoryProfile {
  final List<FrameworkRef>  frameworks;
  final List<String>        qualifiers;
  final Map<String, String> availableQualifiers;

  RegulatoryProfile({
    required this.frameworks,
    required this.qualifiers,
    required this.availableQualifiers,
  });

  factory RegulatoryProfile.fromJson(Map<String, dynamic> j) => RegulatoryProfile(
    frameworks: (j['frameworks'] as List? ?? [])
        .map((f) => FrameworkRef.fromJson(f as Map<String, dynamic>))
        .toList(),
    qualifiers: List<String>.from(j['qualifiers'] ?? []),
    availableQualifiers: Map<String, String>.from(j['available_qualifiers'] ?? {}),
  );
}

/// An asset as returned by GET /assets/ -- used by AssetsScreen to show and
/// toggle the holds_personal_data flag that drives data-protection clocks.
class Asset {
  final String  id;
  final String  name;
  final String  assetType;
  final String  criticality;
  final String  owner;
  final String  environment;
  final String? vendor;
  final String? product;
  final bool    holdsPersonalData;

  Asset({
    required this.id,
    required this.name,
    required this.assetType,
    required this.criticality,
    required this.owner,
    required this.environment,
    this.vendor,
    this.product,
    required this.holdsPersonalData,
  });

  factory Asset.fromJson(Map<String, dynamic> j) => Asset(
    id:                j['id']?.toString()          ?? '',
    name:              j['name']?.toString()        ?? '',
    assetType:         j['asset_type']?.toString()  ?? '',
    criticality:       j['criticality']?.toString() ?? '',
    owner:             j['owner']?.toString()        ?? '',
    environment:       j['environment']?.toString()  ?? '',
    vendor:            j['vendor']?.toString(),
    product:           j['product']?.toString(),
    holdsPersonalData: j['holds_personal_data'] == true,
  );

  Asset copyWith({bool? holdsPersonalData}) => Asset(
    id: id, name: name, assetType: assetType, criticality: criticality,
    owner: owner, environment: environment, vendor: vendor, product: product,
    holdsPersonalData: holdsPersonalData ?? this.holdsPersonalData,
  );
}

/// One of a CVE's exposed assets, as returned by
/// GET /graph/vulnerability-impact/{cve_id}.
class ExposedAsset {
  final String id;
  final String name;
  final String criticality;
  final bool   holdsPersonalData;

  ExposedAsset({
    required this.id,
    required this.name,
    required this.criticality,
    required this.holdsPersonalData,
  });

  factory ExposedAsset.fromJson(Map<String, dynamic> j) => ExposedAsset(
    id:                j['id']?.toString()          ?? '',
    name:              j['name']?.toString()        ?? '',
    criticality:       j['criticality']?.toString() ?? '',
    holdsPersonalData: j['holds_personal_data'] == true,
  );
}

class VulnImpactRisk {
  final String id;
  final String title;
  final double riskScore;

  VulnImpactRisk({required this.id, required this.title, required this.riskScore});

  factory VulnImpactRisk.fromJson(Map<String, dynamic> j) => VulnImpactRisk(
    id:        j['id']?.toString()    ?? '',
    title:     j['title']?.toString() ?? '',
    riskScore: (j['risk_score'] ?? 0).toDouble(),
  );
}

class MitigatingControl {
  final String id;
  final String title;
  final String implementationStatus;
  final double effectivenessScore;

  MitigatingControl({
    required this.id,
    required this.title,
    required this.implementationStatus,
    required this.effectivenessScore,
  });

  factory MitigatingControl.fromJson(Map<String, dynamic> j) => MitigatingControl(
    id:                    j['id']?.toString()    ?? '',
    title:                 j['title']?.toString() ?? '',
    implementationStatus: j['implementation_status']?.toString() ?? '',
    effectivenessScore:   (j['effectiveness_score'] ?? 0).toDouble(),
  );
}

/// GET /graph/vulnerability-impact/{cve_id} -- "this CVE was published
/// today, what does it mean for us?".
class VulnerabilityImpact {
  final String                cveId;
  final String                title;
  final String                description;
  final String                severity;
  final double                cvssScore;
  final bool                  knownRansomwareUse;
  final String                source;
  final bool                  affectsYou;
  final List<ExposedAsset>    exposedAssets;
  final List<VulnImpactRisk>  risks;
  final List<MitigatingControl> mitigatingControls;
  final List<String>          impactedProcesses;
  final RegulatoryObligations regulatoryObligations;

  VulnerabilityImpact({
    required this.cveId,
    required this.title,
    required this.description,
    required this.severity,
    required this.cvssScore,
    required this.knownRansomwareUse,
    required this.source,
    required this.affectsYou,
    required this.exposedAssets,
    required this.risks,
    required this.mitigatingControls,
    required this.impactedProcesses,
    required this.regulatoryObligations,
  });

  factory VulnerabilityImpact.fromJson(Map<String, dynamic> j) => VulnerabilityImpact(
    cveId:              j['cve_id']?.toString()      ?? '',
    title:              j['title']?.toString()        ?? '',
    description:        j['description']?.toString()  ?? '',
    severity:           j['severity']?.toString()      ?? '',
    cvssScore:          (j['cvss_score'] ?? 0).toDouble(),
    knownRansomwareUse: j['known_ransomware_use'] == true,
    source:             j['source']?.toString() ?? '',
    affectsYou:         j['affects_you'] == true,
    exposedAssets: (j['exposed_assets'] as List? ?? [])
        .map((a) => ExposedAsset.fromJson(a as Map<String, dynamic>)).toList(),
    risks: (j['risks'] as List? ?? [])
        .map((r) => VulnImpactRisk.fromJson(r as Map<String, dynamic>)).toList(),
    mitigatingControls: (j['mitigating_controls'] as List? ?? [])
        .map((c) => MitigatingControl.fromJson(c as Map<String, dynamic>)).toList(),
    impactedProcesses: List<String>.from(j['impacted_processes'] ?? []),
    regulatoryObligations: RegulatoryObligations.fromJson(j['regulatory_obligations'] as Map<String, dynamic>?),
  );
}

class GraphStats {
  final int totalNodes;
  final int totalEdges;
  final List<Map<String, dynamic>> nodes;
  final List<Map<String, dynamic>> relationships;

  GraphStats({required this.totalNodes, required this.totalEdges,
              required this.nodes, required this.relationships});

  factory GraphStats.fromJson(Map<String, dynamic> j) => GraphStats(
    totalNodes:    j['total_nodes'] ?? 0,
    totalEdges:    j['total_edges'] ?? 0,
    nodes:         List<Map<String, dynamic>>.from(j['nodes'] ?? []),
    relationships: List<Map<String, dynamic>>.from(j['relationships'] ?? []),
  );
}
