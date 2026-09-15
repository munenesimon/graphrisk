
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
    );
  }
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
