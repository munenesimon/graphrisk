import 'package:flutter/material.dart';
import '../constants/colors.dart';
import '../models/dashboard.dart';
import '../services/api_service.dart';
import '../widgets/stat_card.dart';
import '../widgets/risk_row.dart';
import '../widgets/section_header.dart';
import '../widgets/motion.dart';

class DashboardScreen extends StatefulWidget {
  /// Called with the NavigationRail index to switch to when a drillable
  /// stat card is tapped. Index mapping mirrors MainShell's _screens list:
  /// 0 = Dashboard, 1 = Blast Radius, 2 = Frameworks, 3 = Vulnerabilities,
  /// 4 = Assets.
  final void Function(int index)? onNavigate;
  /// Opens one control (its blast radius) when tapped in Control health.
  final void Function(String controlId)? onOpenControl;

  const DashboardScreen({super.key, this.onNavigate, this.onOpenControl});
  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  DashboardSummary? _summary;
  GraphStats?       _graphStats;
  bool              _loading = true;
  String?           _error;
  final             _controlsKey = GlobalKey();

  @override
  void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    try {
      final s = await ApiService.getDashboardSummary();
      final g = await ApiService.getGraphStats();
      if (!mounted) return;
      setState(() { _summary = s; _graphStats = g; _loading = false; });
    } catch (e) {
      if (!mounted) return;
      // A session-expiry redirect is already in flight (ApiService's
      // onSessionExpired hook swaps this whole screen out for the login
      // screen) -- no need to also flash a dying error here.
      if (e is AuthException) return;
      setState(() { _error = e.toString(); _loading = false; });
    }
  }

  void _showControls() {
    final ctx = _controlsKey.currentContext;
    if (ctx != null) {
      Scrollable.ensureVisible(ctx, duration: const Duration(milliseconds: 400), curve: Curves.easeOut);
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const PageSkeleton(layout: SkeletonLayout.dashboard);
    if (_error != null) return Center(child: Text('Error: ' + _error!, style: const TextStyle(color: kRed)));

    final s = _summary!;
    final g = _graphStats!;
    // Average health of the controls (from their latest checks), so fixing
    // findings moves the figure even before a control passes outright.
    // Falls back to the old implemented count for an older API.
    final health = s.avgControlHealthPct;
    final controlValue = health != null
        ? '${health.round()}%'
        : '${s.implementedControls}/${s.totalControls}';
    final controlSubtitle = health != null
        ? 'average health · ${s.workingControls} of ${s.totalControls} fully working'
        : '${s.totalControls > 0 ? (s.implementedControls / s.totalControls * 100).toStringAsFixed(0) : '0'}% implemented';
    final controlColor = health == null ? kGreen : _healthColor(health / 100);

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
              staggerIn(0, SizedBox(width: w, child: StatCard(label: 'Open Risks', value: s.openRisks.toString(),
                  subtitle: 'Avg score: ' + s.avgScore.toString(), color: kRed, icon: Icons.warning_amber_rounded,
                  onTap: widget.onNavigate == null ? null : () => widget.onNavigate!(1)))),
              staggerIn(1, SizedBox(width: w, child: StatCard(label: 'Controls', value: controlValue,
                  subtitle: controlSubtitle, color: controlColor, icon: Icons.shield_outlined,
                  onTap: s.controls.isEmpty ? null : _showControls))),
              staggerIn(2, SizedBox(width: w, child: StatCard(label: 'Assets', value: s.totalAssets.toString(),
                  subtitle: 'Monitored', color: kAccent, icon: Icons.devices_outlined,
                  onTap: widget.onNavigate == null ? null : () => widget.onNavigate!(4)))),
              staggerIn(3, SizedBox(width: w, child: StatCard(label: 'Graph Nodes', value: g.totalNodes.toString(),
                  subtitle: g.totalEdges.toString() + ' relationships', color: kPurple, icon: Icons.hub_outlined))),
            ]);
          }),
          const SizedBox(height: 32),
          const SectionHeader(title: 'Top Risks by Score'),
          ...s.topRisks.indexed.map((e) => staggerIn(e.$1, RiskRow(
            title: e.$2.title, score: e.$2.riskScore,
            likelihood: e.$2.likelihood, impact: e.$2.impact,
          ), start: const Duration(milliseconds: 220))),
          if (s.controls.isNotEmpty) ...[
            const SizedBox(height: 32),
            SectionHeader(key: _controlsKey, title: 'Control Health'),
            ...s.controls.indexed.map((e) => staggerIn(e.$1, _ControlHealthRow(
              control: e.$2,
              onTap: widget.onOpenControl == null || e.$2.id.isEmpty
                  ? null : () => widget.onOpenControl!(e.$2.id),
            ), start: const Duration(milliseconds: 260))),
          ],
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
                  AnimatedBar(value: pct, color: colors[idx]),
                ]),
              );
            }).toList()),
          ),
        ]),
      ),
    );
  }
}

Color _healthColor(double h) => h >= 0.8 ? kGreen : h >= 0.4 ? kOrange : kRed;

/// One control: name, health bar and where the figure came from.
class _ControlHealthRow extends StatelessWidget {
  final ControlHealth control;
  final VoidCallback? onTap;
  const _ControlHealthRow({required this.control, this.onTap});

  String get _stateLabel => switch (control.state) {
        'working' => 'Working',
        'partial' => 'Partly working',
        _ => 'Not working',
      };

  String get _sourceLine {
    if (!control.measured) {
      final status = control.status ?? 'not set';
      return 'Set by hand: $status';
    }
    final src = control.source ?? 'connector';
    final name = src.isEmpty ? src : src[0].toUpperCase() + src.substring(1);
    final when = control.lastTestedAt;
    final at = (when == null || when.length < 16) ? '' : ', checked ${when.substring(0, 16).replaceFirst('T', ' ')} UTC';
    return 'From $name$at';
  }

  @override
  Widget build(BuildContext context) {
    final color = _healthColor(control.health);
    final card = Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(color: kSurface, borderRadius: BorderRadius.circular(12)),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(children: [
          Expanded(child: Text(control.title,
              style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600))),
          Text('${(control.health * 100).round()}%',
              style: TextStyle(color: color, fontWeight: FontWeight.bold, fontSize: 16)),
        ]),
        const SizedBox(height: 8),
        AnimatedBar(value: control.health, color: color, height: 6),
        const SizedBox(height: 8),
        Text('$_stateLabel · $_sourceLine',
            style: const TextStyle(color: Colors.white54, fontSize: 12)),
        if ((control.detail ?? '').isNotEmpty) ...[
          const SizedBox(height: 4),
          Text(control.detail!, maxLines: 2, overflow: TextOverflow.ellipsis,
              style: const TextStyle(color: Colors.white38, fontSize: 11)),
        ],
      ]),
    );
    if (onTap == null) return card;
    return Material(
      color: Colors.transparent,
      child: InkWell(borderRadius: BorderRadius.circular(12), onTap: onTap, child: card),
    );
  }
}
