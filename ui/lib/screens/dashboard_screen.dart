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
  void initState() { super.initState(); _load(); }

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
    if (_error != null) return Center(child: Text('Error: ' + _error!, style: const TextStyle(color: kRed)));

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
              decoration: BoxDecoration(
                color: kGreen.withOpacity(0.15),
                borderRadius: BorderRadius.circular(20),
                border: Border.all(color: kGreen.withOpacity(0.4))),
              child: const Row(children: [
                Icon(Icons.circle, color: kGreen, size: 8),
                SizedBox(width: 6),
                Text('API Connected', style: TextStyle(color: kGreen, fontSize: 12)),
              ]),
            ),
          ]),
          const SizedBox(height: 28),
          LayoutBuilder(builder: (ctx, constraints) {
            final cols = constraints.maxWidth > 800 ? 4 : constraints.maxWidth > 500 ? 2 : 1;
            final w = (constraints.maxWidth - (cols - 1) * 16) / cols;
            return Wrap(spacing: 16, runSpacing: 16, children: [
              SizedBox(width: w, child: StatCard(label: 'Open Risks', value: s.openRisks.toString(),
                  subtitle: 'Avg score: ' + s.avgScore.toString(), color: kRed, icon: Icons.warning_amber_rounded)),
              SizedBox(width: w, child: StatCard(label: 'Controls', value: s.implementedControls.toString() + '/' + s.totalControls.toString(),
                  subtitle: controlPct + '% implemented', color: kGreen, icon: Icons.shield_outlined)),
              SizedBox(width: w, child: StatCard(label: 'Assets', value: s.totalAssets.toString(),
                  subtitle: 'Monitored', color: kAccent, icon: Icons.devices_outlined)),
              SizedBox(width: w, child: StatCard(label: 'Graph Nodes', value: g.totalNodes.toString(),
                  subtitle: g.totalEdges.toString() + ' relationships', color: kPurple, icon: Icons.hub_outlined)),
            ]);
          }),
          const SizedBox(height: 32),
          const SectionHeader(title: 'Top Risks by Score'),
          ...s.topRisks.map((r) => RiskRow(
            title: r.title, score: r.riskScore,
            likelihood: r.likelihood, impact: r.impact,
          )),
          const SizedBox(height: 32),
          const SectionHeader(title: 'Graph Node Breakdown'),
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(color: kSurface, borderRadius: BorderRadius.circular(12)),
            child: Column(children: g.nodes.map((n) {
              final total = g.totalNodes;
              final count = n['total'] as int;
              final pct   = total > 0 ? count / total : 0.0;
              final colors = [kAccent, kRed, kPurple, kOrange, kGreen, kMidBlue];
              final idx   = g.nodes.indexOf(n) % colors.length;
              final label = n['type']?.toString() ?? '';
              return Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Row(children: [
                    Text(label, style: const TextStyle(color: Colors.white70, fontSize: 13)),
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