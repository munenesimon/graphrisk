import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../constants/colors.dart';
import '../constants/frameworks.dart';
import '../services/api_service.dart';
import '../widgets/adherence.dart';
import '../widgets/motion.dart';

/// Frameworks split into the organisation's obligations (its regulatory
/// profile, set on the Risk Appetite & Regulations page) and everything
/// else, which is shown only for reference. Each framework's requirements
/// are broken down into met / partly met / gaps / self-declared / no
/// evidence yet, so "GraphRisk can't see this" never reads as "failed".
class FrameworksScreen extends StatefulWidget {
  const FrameworksScreen({super.key});
  @override
  State<FrameworksScreen> createState() => _FrameworksScreenState();
}

class _FrameworksScreenState extends State<FrameworksScreen> {
  Map<String, dynamic>? _data;
  bool _loading = true;
  String? _error;
  bool _showOther = false;

  @override
  void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    try {
      final data = await ApiService.getFrameworkAdherence();
      if (!mounted) return;
      setState(() { _data = data; _loading = false; _error = null; });
    } catch (e) {
      if (!mounted) return;
      // Session-expiry redirect is already in flight -- see dashboard_screen.dart.
      if (e is AuthException) return;
      setState(() { _loading = false; _error = e.toString().replaceFirst('Exception: ', ''); });
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const PageSkeleton();
    if (_error != null) {
      return Center(child: Text('Error: $_error', style: const TextStyle(color: kRed)));
    }
    final obligations = (_data?['obligations'] as List? ?? []).cast<Map<String, dynamic>>();
    final other = (_data?['other'] as List? ?? []).cast<Map<String, dynamic>>();
    final hidden = (_data?['hidden_sector_frameworks'] as List? ?? []).cast<Map<String, dynamic>>();

    return RefreshIndicator(
      onRefresh: _load,
      color: kAccent,
      child: SingleChildScrollView(
        physics: const AlwaysScrollableScrollPhysics(),
        padding: const EdgeInsets.all(24),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          const Text('Compliance Frameworks',
              style: TextStyle(color: Colors.white, fontSize: 22, fontWeight: FontWeight.bold)),
          const SizedBox(height: 4),
          const Text('How well your obligations are met, from what your connectors measure and what you record',
              style: TextStyle(color: Colors.white54, fontSize: 13)),
          const SizedBox(height: 20),
          const _Legend(),
          const SizedBox(height: 24),

          _SectionTitle('Your obligations',
              obligations.isEmpty ? null : 'From your regulatory profile'),
          const SizedBox(height: 12),
          if (obligations.isEmpty)
            _NoProfileCard(onSet: () => context.go('/regulatory'))
          else
            ...obligations.map((f) => _FrameworkCard(framework: f, emphasised: true)),

          const SizedBox(height: 28),
          InkWell(
            borderRadius: BorderRadius.circular(8),
            onTap: () => setState(() => _showOther = !_showOther),
            child: Padding(
              padding: const EdgeInsets.symmetric(vertical: 6),
              child: Row(children: [
                Icon(_showOther ? Icons.expand_less : Icons.expand_more, color: Colors.white54, size: 20),
                const SizedBox(width: 6),
                Text('Other frameworks (${other.length})',
                    style: const TextStyle(color: Colors.white70, fontSize: 14, fontWeight: FontWeight.bold)),
                const SizedBox(width: 8),
                const Expanded(
                  child: Text('Not in your profile -- for reference only',
                      style: TextStyle(color: Colors.white38, fontSize: 12), overflow: TextOverflow.ellipsis),
                ),
              ]),
            ),
          ),
          if (_showOther) ...[
            const SizedBox(height: 12),
            ...other.map((f) => _FrameworkCard(framework: f, emphasised: false)),
          ],
          if (hidden.isNotEmpty) ...[
            const SizedBox(height: 20),
            _HiddenSectorNote(hidden: hidden, onManage: () => context.go('/regulatory')),
          ],
        ]),
      ),
    );
  }
}

class _SectionTitle extends StatelessWidget {
  final String title;
  final String? subtitle;
  const _SectionTitle(this.title, this.subtitle);

  @override
  Widget build(BuildContext context) {
    return Row(crossAxisAlignment: CrossAxisAlignment.end, children: [
      Text(title, style: const TextStyle(color: Colors.white70, fontSize: 14, fontWeight: FontWeight.bold)),
      if (subtitle != null) ...[
        const SizedBox(width: 8),
        Text(subtitle!, style: const TextStyle(color: Colors.white38, fontSize: 12)),
      ],
    ]);
  }
}

class _Legend extends StatelessWidget {
  const _Legend();

  @override
  Widget build(BuildContext context) {
    return Wrap(spacing: 14, runSpacing: 6, children: [
      for (final s in RequirementStatus.all)
        if (s != RequirementStatus.notApplicable)
          Row(mainAxisSize: MainAxisSize.min, children: [
            Container(width: 10, height: 10, decoration: BoxDecoration(
                color: s == RequirementStatus.noEvidence ? kSurface2 : s.color,
                borderRadius: BorderRadius.circular(3))),
            const SizedBox(width: 6),
            Text(s.label, style: const TextStyle(color: Colors.white54, fontSize: 11)),
          ]),
    ]);
  }
}

class _NoProfileCard extends StatelessWidget {
  final VoidCallback onSet;
  const _NoProfileCard({required this.onSet});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: kSurface, borderRadius: BorderRadius.circular(12),
        border: Border.all(color: kAccent.withOpacity(0.3)),
      ),
      child: Row(children: [
        const Icon(Icons.gavel_outlined, color: kAccent),
        const SizedBox(width: 12),
        const Expanded(
          child: Text(
            "You haven't said which regulations or standards apply to you yet, so nothing is "
            'treated as an obligation. Choose them on the Risk Appetite & Regulations page.',
            style: TextStyle(color: Colors.white70, fontSize: 13),
          ),
        ),
        const SizedBox(width: 12),
        TextButton(onPressed: onSet, child: const Text('Choose')),
      ]),
    );
  }
}

class _FrameworkCard extends StatelessWidget {
  final Map<String, dynamic> framework;
  final bool emphasised;
  const _FrameworkCard({required this.framework, required this.emphasised});

  @override
  Widget build(BuildContext context) {
    final id = framework['framework_id']?.toString() ?? '';
    final slug = framework['framework']?.toString() ?? id;
    final name = frameworkDisplayName(slug);
    final pct = (framework['adherence_pct'] as num?)?.toDouble();
    final evidenced = (framework['evidenced'] as num?)?.toInt() ?? 0;
    final applicable = (framework['applicable'] as num?)?.toInt() ?? 0;
    final thin = evidenceIsThin(framework);
    final color = emphasised && !thin ? adherenceColor(pct) : Colors.white54;

    final card = Container(
      margin: const EdgeInsets.only(bottom: 12),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: emphasised ? kSurface : kSurface.withOpacity(0.6),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(children: [
          Expanded(
            child: Text(name,
                style: TextStyle(color: emphasised ? Colors.white : Colors.white70, fontWeight: FontWeight.bold),
                overflow: TextOverflow.ellipsis),
          ),
          const SizedBox(width: 8),
          Text(pct == null ? '—' : '${pct.toStringAsFixed(1)}% met',
              style: TextStyle(color: color, fontWeight: FontWeight.bold, fontSize: 16)),
        ]),
        const SizedBox(height: 4),
        Text(
          applicable == 0
              ? 'Every requirement is marked not applicable'
              : 'Evidence for $evidenced of $applicable requirements · ${adherenceBreakdown(framework)}',
          style: const TextStyle(color: Colors.white54, fontSize: 12),
        ),
        if (thin && applicable > 0) ...[
          const SizedBox(height: 2),
          const Text(kThinEvidenceNote,
              style: TextStyle(color: Colors.white38, fontSize: 11, fontStyle: FontStyle.italic)),
        ],
        const SizedBox(height: 10),
        AdherenceBar(framework: framework),
      ]),
    );
    if (id.isEmpty) return card;
    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(12),
        onTap: () => context.go('/frameworks/${Uri.encodeComponent(id)}?name=${Uri.encodeQueryComponent(name)}'),
        child: card,
      ),
    );
  }
}

/// Sector-specific frameworks (a bank's or card handler's obligations) the
/// organisation hasn't switched on: named here so it's clear they were left
/// out on purpose, with a way to switch them on.
class _HiddenSectorNote extends StatelessWidget {
  final List<Map<String, dynamic>> hidden;
  final VoidCallback onManage;
  const _HiddenSectorNote({required this.hidden, required this.onManage});

  @override
  Widget build(BuildContext context) {
    final names = hidden.map((h) => frameworkShortName(h['framework']?.toString() ?? '')).join(', ');
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: kSurface2.withOpacity(0.5),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Row(children: [
        const Icon(Icons.visibility_off_outlined, color: Colors.white38, size: 18),
        const SizedBox(width: 10),
        Expanded(
          child: Text(
            '${hidden.length} sector-specific framework${hidden.length == 1 ? ' is' : 's are'} hidden '
            '($names) because ${hidden.length == 1 ? 'it only applies' : 'they only apply'} to certain '
            'kinds of organisation. Switch on any that apply to you.',
            style: const TextStyle(color: Colors.white54, fontSize: 12, height: 1.4),
          ),
        ),
        const SizedBox(width: 8),
        TextButton(onPressed: onManage, child: const Text('Your sector')),
      ]),
    );
  }
}
