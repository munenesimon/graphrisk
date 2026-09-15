"""
GraphRisk UI — Flutter Setup Script
Creates all Dart source files with correct encoding.
Run from graphrisk_ui folder.
Usage: python setup_ui.py
"""
import os

BASE = os.path.dirname(os.path.abspath(__file__))
LIB  = os.path.join(BASE, "lib")


def write(rel_path, content):
    full = os.path.join(LIB, rel_path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  Written: lib/{rel_path}")


# ── constants/api.dart ────────────────────────────────────────────────────────
write("constants/api.dart", """
const String kBaseUrl   = 'http://localhost:8000/api/v1';
const String kTenantId  = 'demo';
""")

# ── constants/colors.dart ─────────────────────────────────────────────────────
write("constants/colors.dart", """
import 'package:flutter/material.dart';

const kDarkBlue   = Color(0xFF1B2A4A);
const kMidBlue    = Color(0xFF2E5B9A);
const kAccent     = Color(0xFF3B82F6);
const kLightBlue  = Color(0xFFEBF2FB);
const kDarkGrey   = Color(0xFF374151);
const kLightGrey  = Color(0xFFF5F7FA);
const kGreen      = Color(0xFF16A34A);
const kOrange     = Color(0xFFD97706);
const kRed        = Color(0xFFDC2626);
const kPurple     = Color(0xFF7C3AED);
const kBackground = Color(0xFF0F172A);
const kSurface    = Color(0xFF1E293B);
const kSurface2   = Color(0xFF334155);
""")

# ── models/dashboard.dart ─────────────────────────────────────────────────────
write("models/dashboard.dart", """
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
""")

# ── services/api_service.dart ─────────────────────────────────────────────────
write("services/api_service.dart", """
import 'dart:convert';
import 'package:http/http.dart' as http;
import '../constants/api.dart';
import '../models/dashboard.dart';

class ApiService {
  static final _client = http.Client();

  static Future<Map<String, dynamic>> _get(String path) async {
    final uri = Uri.parse('\$kBaseUrl\$path');
    final res = await _client.get(uri);
    if (res.statusCode == 200) {
      return json.decode(res.body) as Map<String, dynamic>;
    }
    throw Exception('API error \${res.statusCode}: \$path');
  }

  static Future<DashboardSummary> getDashboardSummary() async {
    final data = await _get('/dashboard/summary?tenant_id=\$kTenantId');
    return DashboardSummary.fromJson(data);
  }

  static Future<GraphStats> getGraphStats() async {
    final data = await _get('/dashboard/graph-stats');
    return GraphStats.fromJson(data);
  }

  static Future<BlastRadius> getBlastRadiusControl(String controlId) async {
    final data = await _get('/graph/blast-radius/control/\$controlId?tenant_id=\$kTenantId');
    return BlastRadius.fromJson(data);
  }

  static Future<Map<String, dynamic>> getBlastRadiusTechnique(String techniqueId) async {
    return await _get('/graph/blast-radius/technique/\$techniqueId');
  }

  static Future<List<dynamic>> getAssets() async {
    final data = await _get('/assets/?tenant_id=\$kTenantId');
    return data['assets'] as List? ?? [];
  }

  static Future<List<dynamic>> getRisks() async {
    final data = await _get('/risks/?tenant_id=\$kTenantId');
    return data['risks'] as List? ?? [];
  }

  static Future<List<dynamic>> getControls() async {
    final data = await _get('/controls/?tenant_id=\$kTenantId');
    return data['controls'] as List? ?? [];
  }

  static Future<List<dynamic>> getFrameworks() async {
    final data = await _get('/frameworks/');
    return data['frameworks'] as List? ?? [];
  }

  static Future<Map<String, dynamic>> getVulnerabilityIntel() async {
    return await _get('/dashboard/vulnerability-intel');
  }

  static Future<Map<String, dynamic>> getFrameworkCoverage() async {
    return await _get('/dashboard/framework-coverage?tenant_id=\$kTenantId');
  }
}
""")

# ── widgets/stat_card.dart ────────────────────────────────────────────────────
write("widgets/stat_card.dart", """
import 'package:flutter/material.dart';
import '../constants/colors.dart';

class StatCard extends StatelessWidget {
  final String  label;
  final String  value;
  final String? subtitle;
  final Color   color;
  final IconData icon;

  const StatCard({
    super.key,
    required this.label,
    required this.value,
    this.subtitle,
    required this.color,
    required this.icon,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: kSurface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withOpacity(0.3), width: 1),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          Row(children: [
            Icon(icon, color: color, size: 20),
            const SizedBox(width: 8),
            Text(label, style: TextStyle(color: Colors.white60, fontSize: 13)),
          ]),
          const SizedBox(height: 12),
          Text(value, style: TextStyle(color: color, fontSize: 28, fontWeight: FontWeight.bold)),
          if (subtitle != null) ...[
            const SizedBox(height: 4),
            Text(subtitle!, style: const TextStyle(color: Colors.white38, fontSize: 12)),
          ],
        ],
      ),
    );
  }
}
""")

# ── widgets/risk_row.dart ─────────────────────────────────────────────────────
write("widgets/risk_row.dart", """
import 'package:flutter/material.dart';
import '../constants/colors.dart';

class RiskRow extends StatelessWidget {
  final String title;
  final double score;
  final int    likelihood;
  final int    impact;

  const RiskRow({super.key, required this.title,
                 required this.score, required this.likelihood, required this.impact});

  Color get _scoreColor {
    if (score >= 20) return kRed;
    if (score >= 12) return kOrange;
    return kGreen;
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      decoration: BoxDecoration(
        color: kSurface2,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: _scoreColor.withOpacity(0.3)),
      ),
      child: Row(children: [
        Container(
          width: 48, height: 48,
          decoration: BoxDecoration(color: _scoreColor.withOpacity(0.15), borderRadius: BorderRadius.circular(8)),
          child: Center(child: Text(score.toInt().toString(),
              style: TextStyle(color: _scoreColor, fontWeight: FontWeight.bold, fontSize: 18))),
        ),
        const SizedBox(width: 16),
        Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(title, style: const TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.w500)),
          const SizedBox(height: 4),
          Text('Likelihood: \$likelihood  ·  Impact: \$impact',
              style: const TextStyle(color: Colors.white54, fontSize: 12)),
        ])),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
          decoration: BoxDecoration(color: _scoreColor.withOpacity(0.15), borderRadius: BorderRadius.circular(20)),
          child: Text(score >= 20 ? 'Critical' : score >= 12 ? 'High' : 'Medium',
              style: TextStyle(color: _scoreColor, fontSize: 11, fontWeight: FontWeight.bold)),
        ),
      ]),
    );
  }
}
""")

# ── widgets/section_header.dart ───────────────────────────────────────────────
write("widgets/section_header.dart", """
import 'package:flutter/material.dart';
import '../constants/colors.dart';

class SectionHeader extends StatelessWidget {
  final String title;
  final Widget? trailing;

  const SectionHeader({super.key, required this.title, this.trailing});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: Row(children: [
        Container(width: 4, height: 20, decoration: BoxDecoration(color: kAccent, borderRadius: BorderRadius.circular(2))),
        const SizedBox(width: 10),
        Text(title, style: const TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold)),
        const Spacer(),
        if (trailing != null) trailing!,
      ]),
    );
  }
}
""")

# ── screens/dashboard_screen.dart ─────────────────────────────────────────────
write("screens/dashboard_screen.dart", """
import 'package:flutter/material.dart';
import '../constants/colors.dart';
import '../models/dashboard.dart';
import '../services/api_service.dart';
import '../widgets/stat_card.dart';
import '../widgets/risk_row.dart';
import '../widgets/section_header.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  DashboardSummary? _summary;
  GraphStats?       _graphStats;
  bool              _loading = true;
  String?           _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final s = await ApiService.getDashboardSummary();
      final g = await ApiService.getGraphStats();
      setState(() { _summary = s; _graphStats = g; _loading = false; });
    } catch (e) {
      setState(() { _error = e.toString(); _loading = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator(color: kAccent));
    if (_error != null) return Center(child: Text('Error: \$_error', style: const TextStyle(color: kRed)));

    final s = _summary!;
    final g = _graphStats!;
    final controlPct = s.totalControls > 0
        ? (s.implementedControls / s.totalControls * 100).toStringAsFixed(0)
        : '0';

    return RefreshIndicator(
      onRefresh: _load,
      color: kAccent,
      child: SingleChildScrollView(
        physics: const AlwaysScrollableScrollPhysics(),
        padding: const EdgeInsets.all(24),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [

          // Header
          Row(children: [
            const Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text('GraphRisk Intelligence Platform',
                  style: TextStyle(color: Colors.white, fontSize: 22, fontWeight: FontWeight.bold)),
              SizedBox(height: 4),
              Text('Risk graph · Live data', style: TextStyle(color: Colors.white54, fontSize: 13)),
            ]),
            const Spacer(),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              decoration: BoxDecoration(color: kGreen.withOpacity(0.15), borderRadius: BorderRadius.circular(20), border: Border.all(color: kGreen.withOpacity(0.4))),
              child: const Row(children: [
                Icon(Icons.circle, color: kGreen, size: 8),
                SizedBox(width: 6),
                Text('API Connected', style: TextStyle(color: kGreen, fontSize: 12)),
              ]),
            ),
          ]),

          const SizedBox(height: 28),

          // Stat cards
          LayoutBuilder(builder: (ctx, constraints) {
            final cols = constraints.maxWidth > 800 ? 4 : constraints.maxWidth > 500 ? 2 : 1;
            return Wrap(spacing: 16, runSpacing: 16, children: [
              SizedBox(width: (constraints.maxWidth - (cols - 1) * 16) / cols,
                child: StatCard(label: 'Open Risks',     value: s.openRisks.toString(),
                    subtitle: 'Avg score: \${s.avgScore}', color: kRed,    icon: Icons.warning_amber_rounded)),
              SizedBox(width: (constraints.maxWidth - (cols - 1) * 16) / cols,
                child: StatCard(label: 'Controls',       value: '\${s.implementedControls}/\${s.totalControls}',
                    subtitle: '\$controlPct%% implemented',  color: kGreen,  icon: Icons.shield_outlined)),
              SizedBox(width: (constraints.maxWidth - (cols - 1) * 16) / cols,
                child: StatCard(label: 'Assets',         value: s.totalAssets.toString(),
                    subtitle: 'Monitored',                    color: kAccent, icon: Icons.devices_outlined)),
              SizedBox(width: (constraints.maxWidth - (cols - 1) * 16) / cols,
                child: StatCard(label: 'Graph Nodes',    value: '${g.totalNodes}',
                    subtitle: '${g.totalEdges} relationships', color: kPurple, icon: Icons.hub_outlined)),
            ]);
          }),

          const SizedBox(height: 32),

          // Top Risks
          const SectionHeader(title: 'Top Risks by Score'),
          ...s.topRisks.map((r) => RiskRow(
            title: r.title, score: r.riskScore,
            likelihood: r.likelihood, impact: r.impact,
          )),

          const SizedBox(height: 32),

          // Graph breakdown
          const SectionHeader(title: 'Graph Node Breakdown'),
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(color: kSurface, borderRadius: BorderRadius.circular(12)),
            child: Column(children: g.nodes.map((n) {
              final total   = g.totalNodes;
              final count   = n['total'] as int;
              final pct     = total > 0 ? count / total : 0.0;
              final colors  = [kAccent, kRed, kPurple, kOrange, kGreen, kMidBlue];
              final idx     = g.nodes.indexOf(n) % colors.length;
              return Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Row(children: [
                    Text(n['type'] ?? '', style: const TextStyle(color: Colors.white70, fontSize: 13)),
                    const Spacer(),
                    Text(count.toString(), style: TextStyle(color: colors[idx], fontWeight: FontWeight.bold)),
                  ]),
                  const SizedBox(height: 6),
                  ClipRRect(
                    borderRadius: BorderRadius.circular(4),
                    child: LinearProgressIndicator(
                      value: pct, minHeight: 6,
                      backgroundColor: kSurface2,
                      valueColor: AlwaysStoppedAnimation(colors[idx]),
                    ),
                  ),
                ]),
              );
            }).toList()),
          ),

        ]),
      ),
    );
  }
}
""")

# ── screens/blast_radius_screen.dart ──────────────────────────────────────────
write("screens/blast_radius_screen.dart", """
import 'package:flutter/material.dart';
import '../constants/colors.dart';
import '../models/dashboard.dart';
import '../services/api_service.dart';
import '../widgets/section_header.dart';

class BlastRadiusScreen extends StatefulWidget {
  const BlastRadiusScreen({super.key});

  @override
  State<BlastRadiusScreen> createState() => _BlastRadiusScreenState();
}

class _BlastRadiusScreenState extends State<BlastRadiusScreen> {
  final _ctrl      = TextEditingController();
  BlastRadius? _result;
  bool         _loading = false;
  String?      _error;

  // Pre-filled with MFA control from seed data
  static const _defaultId = 'a3c44acb-937a-4514-8b16-7bafea69d88b';

  @override
  void initState() {
    super.initState();
    _ctrl.text = _defaultId;
    _run(_defaultId);
  }

  Future<void> _run(String id) async {
    if (id.isEmpty) return;
    setState(() { _loading = true; _error = null; });
    try {
      final r = await ApiService.getBlastRadiusControl(id);
      setState(() { _result = r; _loading = false; });
    } catch (e) {
      setState(() { _error = e.toString(); _loading = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [

        // Header
        const Text('Blast Radius Engine',
            style: TextStyle(color: Colors.white, fontSize: 22, fontWeight: FontWeight.bold)),
        const SizedBox(height: 4),
        const Text('Enter a control ID to see its full impact chain',
            style: TextStyle(color: Colors.white54, fontSize: 13)),
        const SizedBox(height: 24),

        // Input
        Row(children: [
          Expanded(child: TextField(
            controller: _ctrl,
            style: const TextStyle(color: Colors.white, fontSize: 13, fontFamily: 'monospace'),
            decoration: InputDecoration(
              hintText: 'Control UUID...',
              hintStyle: const TextStyle(color: Colors.white38),
              filled: true, fillColor: kSurface,
              border: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: BorderSide(color: kAccent.withOpacity(0.3))),
              enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: BorderSide(color: kAccent.withOpacity(0.3))),
              focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: const BorderSide(color: kAccent)),
              contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
            ),
          )),
          const SizedBox(width: 12),
          ElevatedButton.icon(
            onPressed: () => _run(_ctrl.text.trim()),
            icon: const Icon(Icons.bolt, size: 18),
            label: const Text('Run'),
            style: ElevatedButton.styleFrom(
              backgroundColor: kAccent, foregroundColor: Colors.white,
              padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
            ),
          ),
        ]),

        const SizedBox(height: 28),

        if (_loading) const Center(child: CircularProgressIndicator(color: kAccent)),
        if (_error != null) Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(color: kRed.withOpacity(0.1), borderRadius: BorderRadius.circular(8), border: Border.all(color: kRed.withOpacity(0.3))),
          child: Text(_error!, style: const TextStyle(color: kRed)),
        ),

        if (_result != null) ...[
          // Control info
          Container(
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(color: kSurface, borderRadius: BorderRadius.circular(12), border: Border.all(color: kAccent.withOpacity(0.3))),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Row(children: [
                const Icon(Icons.shield_outlined, color: kAccent, size: 20),
                const SizedBox(width: 10),
                Expanded(child: Text(_result!.controlTitle,
                    style: const TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold))),
                _StatusBadge(status: _result!.controlStatus),
              ]),
              const SizedBox(height: 12),
              Text('Effectiveness: \${(_result!.effectivenessScore * 100).toInt()}%%',
                  style: const TextStyle(color: Colors.white60, fontSize: 13)),
            ]),
          ),

          const SizedBox(height: 20),

          // Summary chips
          Row(children: [
            _ImpactChip(label: '\${_result!.riskCount} Risks',      color: kRed,    icon: Icons.warning_amber),
            const SizedBox(width: 10),
            _ImpactChip(label: '\${_result!.assetCount} Assets',     color: kOrange, icon: Icons.devices),
            const SizedBox(width: 10),
            _ImpactChip(label: '\${_result!.frameworkCount} Frameworks', color: kPurple, icon: Icons.policy),
          ]),

          const SizedBox(height: 24),

          // Impact sections
          _ImpactSection(title: 'Exposed Risks',       items: _result!.exposedRisks,      color: kRed,    icon: Icons.warning_amber_rounded),
          const SizedBox(height: 16),
          _ImpactSection(title: 'Affected Assets',     items: _result!.affectedAssets,    color: kOrange, icon: Icons.devices_outlined),
          const SizedBox(height: 16),
          _ImpactSection(title: 'Compliance Gaps',     items: _result!.complianceGaps,    color: kPurple, icon: Icons.policy_outlined),
          const SizedBox(height: 16),
          _ImpactSection(title: 'Framework Controls',  items: _result!.frameworkControls, color: kAccent, icon: Icons.list_alt_outlined),
        ],

      ]),
    );
  }
}

class _StatusBadge extends StatelessWidget {
  final String status;
  const _StatusBadge({required this.status});

  Color get _color {
    if (status == 'Implemented') return kGreen;
    if (status == 'PartiallyImplemented') return kOrange;
    return kRed;
  }

  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
    decoration: BoxDecoration(color: _color.withOpacity(0.15), borderRadius: BorderRadius.circular(20)),
    child: Text(status.replaceAll('Implemented', ' Implemented').trim(),
        style: TextStyle(color: _color, fontSize: 11, fontWeight: FontWeight.bold)),
  );
}

class _ImpactChip extends StatelessWidget {
  final String label;
  final Color  color;
  final IconData icon;
  const _ImpactChip({required this.label, required this.color, required this.icon});

  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
    decoration: BoxDecoration(color: color.withOpacity(0.1), borderRadius: BorderRadius.circular(8), border: Border.all(color: color.withOpacity(0.3))),
    child: Row(mainAxisSize: MainAxisSize.min, children: [
      Icon(icon, color: color, size: 16),
      const SizedBox(width: 6),
      Text(label, style: TextStyle(color: color, fontWeight: FontWeight.bold, fontSize: 13)),
    ]),
  );
}

class _ImpactSection extends StatelessWidget {
  final String       title;
  final List<String> items;
  final Color        color;
  final IconData     icon;

  const _ImpactSection({required this.title, required this.items, required this.color, required this.icon});

  @override
  Widget build(BuildContext context) {
    if (items.isEmpty) return const SizedBox.shrink();
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      SectionHeader(title: title),
      Wrap(spacing: 8, runSpacing: 8, children: items.map((item) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        decoration: BoxDecoration(color: color.withOpacity(0.1), borderRadius: BorderRadius.circular(6), border: Border.all(color: color.withOpacity(0.3))),
        child: Row(mainAxisSize: MainAxisSize.min, children: [
          Icon(icon, color: color, size: 14),
          const SizedBox(width: 6),
          Text(item, style: TextStyle(color: color, fontSize: 13)),
        ]),
      )).toList()),
    ]);
  }
}
""")

# ── screens/frameworks_screen.dart ────────────────────────────────────────────
write("screens/frameworks_screen.dart", """
import 'package:flutter/material.dart';
import '../constants/colors.dart';
import '../services/api_service.dart';

class FrameworksScreen extends StatefulWidget {
  const FrameworksScreen({super.key});

  @override
  State<FrameworksScreen> createState() => _FrameworksScreenState();
}

class _FrameworksScreenState extends State<FrameworksScreen> {
  List<dynamic>? _frameworks;
  Map<String, dynamic>? _coverage;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final f = await ApiService.getFrameworks();
      final c = await ApiService.getFrameworkCoverage();
      setState(() { _frameworks = f; _coverage = c; _loading = false; });
    } catch (e) {
      setState(() { _loading = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator(color: kAccent));
    final frameworks = _frameworks ?? [];
    final coverageList = (_coverage?['frameworks'] as List? ?? []);

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const Text('Compliance Frameworks', style: TextStyle(color: Colors.white, fontSize: 22, fontWeight: FontWeight.bold)),
        const SizedBox(height: 4),
        const Text('Framework control coverage for your tenant', style: TextStyle(color: Colors.white54, fontSize: 13)),
        const SizedBox(height: 28),

        // Coverage cards
        if (coverageList.isNotEmpty) ...[
          const Text('Coverage Overview', style: TextStyle(color: Colors.white70, fontSize: 14, fontWeight: FontWeight.bold)),
          const SizedBox(height: 16),
          ...coverageList.map((c) {
            final pct = (c['coverage_pct'] ?? 0.0).toDouble();
            final color = pct >= 80 ? kGreen : pct >= 40 ? kOrange : kRed;
            return Container(
              margin: const EdgeInsets.only(bottom: 12),
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(color: kSurface, borderRadius: BorderRadius.circular(12)),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Row(children: [
                  Text(c['framework'] ?? '', style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                  const Spacer(),
                  Text('\${pct.toStringAsFixed(1)}%%', style: TextStyle(color: color, fontWeight: FontWeight.bold, fontSize: 16)),
                ]),
                const SizedBox(height: 4),
                Text('\${c['covered_controls']} / \${c['total_controls']} controls covered',
                    style: const TextStyle(color: Colors.white54, fontSize: 12)),
                const SizedBox(height: 10),
                ClipRRect(
                  borderRadius: BorderRadius.circular(4),
                  child: LinearProgressIndicator(
                    value: pct / 100, minHeight: 8,
                    backgroundColor: kSurface2,
                    valueColor: AlwaysStoppedAnimation(color),
                  ),
                ),
              ]),
            );
          }),
          const SizedBox(height: 28),
        ],

        // Framework list
        const Text('All Frameworks', style: TextStyle(color: Colors.white70, fontSize: 14, fontWeight: FontWeight.bold)),
        const SizedBox(height: 16),
        ...frameworks.map((f) => Container(
          margin: const EdgeInsets.only(bottom: 10),
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(color: kSurface, borderRadius: BorderRadius.circular(10),
              border: Border.all(color: kAccent.withOpacity(0.2))),
          child: Row(children: [
            Container(width: 40, height: 40,
              decoration: BoxDecoration(color: kAccent.withOpacity(0.1), borderRadius: BorderRadius.circular(8)),
              child: const Icon(Icons.policy_outlined, color: kAccent, size: 20)),
            const SizedBox(width: 14),
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(f['name'] ?? '', style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
              Text('v\${f['version'] ?? ''} · \${f['total_controls']} controls',
                  style: const TextStyle(color: Colors.white54, fontSize: 12)),
            ])),
            const Icon(Icons.chevron_right, color: Colors.white38),
          ]),
        )),
      ]),
    );
  }
}
""")

# ── screens/vulnerability_screen.dart ────────────────────────────────────────
write("screens/vulnerability_screen.dart", """
import 'package:flutter/material.dart';
import '../constants/colors.dart';
import '../services/api_service.dart';

class VulnerabilityScreen extends StatefulWidget {
  const VulnerabilityScreen({super.key});

  @override
  State<VulnerabilityScreen> createState() => _VulnerabilityScreenState();
}

class _VulnerabilityScreenState extends State<VulnerabilityScreen> {
  Map<String, dynamic>? _intel;
  bool _loading = true;

  @override
  void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    try {
      final data = await ApiService.getVulnerabilityIntel();
      setState(() { _intel = data; _loading = false; });
    } catch (e) {
      setState(() { _loading = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator(color: kAccent));

    final sources  = (_intel?['vulnerability_sources'] as List? ?? []);
    final recent   = (_intel?['recent_ransomware_kev']  as List? ?? []);

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const Text('Vulnerability Intelligence', style: TextStyle(color: Colors.white, fontSize: 22, fontWeight: FontWeight.bold)),
        const SizedBox(height: 4),
        const Text('Live data from CISA KEV + NVD', style: TextStyle(color: Colors.white54, fontSize: 13)),
        const SizedBox(height: 28),

        // Source stats
        ...sources.map((s) {
          final total      = s['total'] as int;
          final ransomware = s['ransomware'] as int? ?? 0;
          final source     = s['source'] as String? ?? '';
          final isKev      = source == 'CISA_KEV';
          return Container(
            margin: const EdgeInsets.only(bottom: 12),
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: kSurface, borderRadius: BorderRadius.circular(12),
              border: Border.all(color: (isKev ? kRed : kOrange).withOpacity(0.3)),
            ),
            child: Row(children: [
              Container(width: 48, height: 48,
                decoration: BoxDecoration(color: (isKev ? kRed : kOrange).withOpacity(0.1), borderRadius: BorderRadius.circular(8)),
                child: Icon(isKev ? Icons.warning_amber_rounded : Icons.bug_report_outlined,
                    color: isKev ? kRed : kOrange, size: 24)),
              const SizedBox(width: 16),
              Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(isKev ? 'CISA KEV — Actively Exploited' : 'NVD — Critical Severity',
                    style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                Text('\$total vulnerabilities · \$ransomware ransomware',
                    style: const TextStyle(color: Colors.white54, fontSize: 12)),
              ])),
              Text(total.toString(),
                  style: TextStyle(color: isKev ? kRed : kOrange, fontSize: 22, fontWeight: FontWeight.bold)),
            ]),
          );
        }),

        const SizedBox(height: 28),

        // Recent ransomware KEV
        if (recent.isNotEmpty) ...[
          const Text('Recent Ransomware-Linked CVEs (CISA KEV)',
              style: TextStyle(color: Colors.white70, fontSize: 14, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          ...recent.map((v) => Container(
            margin: const EdgeInsets.only(bottom: 8),
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(color: kSurface, borderRadius: BorderRadius.circular(8),
                border: Border.all(color: kRed.withOpacity(0.2))),
            child: Row(children: [
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(color: kRed.withOpacity(0.1), borderRadius: BorderRadius.circular(4)),
                child: Text(v['cve_id'] ?? '', style: const TextStyle(color: kRed, fontSize: 11, fontFamily: 'monospace', fontWeight: FontWeight.bold)),
              ),
              const SizedBox(width: 12),
              Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(v['title'] ?? '', style: const TextStyle(color: Colors.white, fontSize: 13), maxLines: 1, overflow: TextOverflow.ellipsis),
                Text('\${v['vendor'] ?? ''} · \${v['product'] ?? ''}',
                    style: const TextStyle(color: Colors.white54, fontSize: 11)),
              ])),
            ]),
          )),
        ],
      ]),
    );
  }
}
""")

# ── main.dart ─────────────────────────────────────────────────────────────────
write("main.dart", """
import 'package:flutter/material.dart';
import 'constants/colors.dart';
import 'screens/dashboard_screen.dart';
import 'screens/blast_radius_screen.dart';
import 'screens/frameworks_screen.dart';
import 'screens/vulnerability_screen.dart';

void main() {
  runApp(const GraphRiskApp());
}

class GraphRiskApp extends StatelessWidget {
  const GraphRiskApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'GraphRisk Intelligence Platform',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: kBackground,
        colorScheme: const ColorScheme.dark(primary: kAccent, surface: kSurface),
        fontFamily: 'Inter',
      ),
      home: const MainShell(),
    );
  }
}

class MainShell extends StatefulWidget {
  const MainShell({super.key});

  @override
  State<MainShell> createState() => _MainShellState();
}

class _MainShellState extends State<MainShell> {
  int _selectedIndex = 0;

  final _screens = const [
    DashboardScreen(),
    BlastRadiusScreen(),
    FrameworksScreen(),
    VulnerabilityScreen(),
  ];

  final _navItems = const [
    NavigationRailDestination(icon: Icon(Icons.dashboard_outlined),    selectedIcon: Icon(Icons.dashboard),    label: Text('Dashboard')),
    NavigationRailDestination(icon: Icon(Icons.bolt_outlined),         selectedIcon: Icon(Icons.bolt),         label: Text('Blast Radius')),
    NavigationRailDestination(icon: Icon(Icons.policy_outlined),       selectedIcon: Icon(Icons.policy),       label: Text('Frameworks')),
    NavigationRailDestination(icon: Icon(Icons.bug_report_outlined),   selectedIcon: Icon(Icons.bug_report),   label: Text('Vulnerabilities')),
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Row(children: [
        NavigationRail(
          backgroundColor: kSurface,
          selectedIndex: _selectedIndex,
          onDestinationSelected: (i) => setState(() => _selectedIndex = i),
          extended: MediaQuery.of(context).size.width > 900,
          leading: Padding(
            padding: const EdgeInsets.symmetric(vertical: 24, horizontal: 8),
            child: Column(children: [
              Container(width: 36, height: 36,
                decoration: BoxDecoration(color: kAccent, borderRadius: BorderRadius.circular(8)),
                child: const Icon(Icons.hub, color: Colors.white, size: 20)),
              if (MediaQuery.of(context).size.width > 900) ...[
                const SizedBox(height: 8),
                const Text('GraphRisk', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 14)),
              ],
            ]),
          ),
          selectedIconTheme: const IconThemeData(color: kAccent),
          unselectedIconTheme: const IconThemeData(color: Colors.white38),
          selectedLabelTextStyle: const TextStyle(color: kAccent, fontWeight: FontWeight.bold),
          unselectedLabelTextStyle: const TextStyle(color: Colors.white38),
          indicatorColor: kAccent.withOpacity(0.15),
          destinations: _navItems,
        ),
        const VerticalDivider(width: 1, color: Color(0xFF334155)),
        Expanded(child: _screens[_selectedIndex]),
      ]),
    );
  }
}
""")

print("\n" + "="*55)
print("  GraphRisk UI — All files created")
print("="*55)
print("\n  Run the app:")
print("  flutter run -d chrome --web-port=3000")
print("="*55)
