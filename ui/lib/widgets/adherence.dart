import 'package:flutter/material.dart';
import '../constants/colors.dart';

/// How a framework requirement stands for this organisation -- see
/// FRAMEWORK_REQUIREMENTS in api/app/graph/queries.py. "No evidence" is
/// deliberately grey, not red: GraphRisk can't see it, which isn't the same
/// as it being missing.
class RequirementStatus {
  final String key;
  final String label;
  final String shortLabel;
  final Color color;
  final IconData icon;
  const RequirementStatus(this.key, this.label, this.shortLabel, this.color, this.icon);

  static const met = RequirementStatus('met', 'Met', 'met', kGreen, Icons.check_circle_outline);
  static const partial = RequirementStatus('partial', 'Partly met', 'partly met', kOrange, Icons.timelapse);
  static const gap = RequirementStatus('gap', 'Gap', 'gaps', kRed, Icons.error_outline);
  static const attested = RequirementStatus(
      'attested', 'Self-declared', 'self-declared', kTeal, Icons.verified_user_outlined);
  static const noEvidence = RequirementStatus(
      'no_evidence', 'No evidence yet', 'no evidence yet', Colors.white38, Icons.help_outline);
  static const notApplicable = RequirementStatus(
      'not_applicable', 'Not applicable', 'not applicable', Colors.white24, Icons.remove_circle_outline);

  /// Order used in bars, legends and filters.
  static const all = [met, partial, gap, attested, noEvidence, notApplicable];

  static RequirementStatus of(String? key) =>
      all.firstWhere((s) => s.key == key, orElse: () => noEvidence);
}

int _count(Map<String, dynamic> f, String key) => (f[key] as num?)?.toInt() ?? 0;

/// A stacked bar of a framework's applicable requirements by status, so a
/// low score that's mostly "no evidence yet" looks different from one
/// that's mostly gaps.
class AdherenceBar extends StatelessWidget {
  final Map<String, dynamic> framework;
  final double height;
  const AdherenceBar({super.key, required this.framework, this.height = 8});

  @override
  Widget build(BuildContext context) {
    final parts = [
      for (final s in RequirementStatus.all)
        if (s != RequirementStatus.notApplicable && _count(framework, s.key) > 0)
          (s, _count(framework, s.key)),
    ];
    if (parts.isEmpty) {
      return Container(height: height, decoration: BoxDecoration(
          color: kSurface2, borderRadius: BorderRadius.circular(height)));
    }
    return ClipRRect(
      borderRadius: BorderRadius.circular(height),
      child: SizedBox(
        height: height,
        child: Row(children: [
          for (final (s, n) in parts)
            Expanded(
              flex: n,
              child: Container(color: s == RequirementStatus.noEvidence ? kSurface2 : s.color),
            ),
        ]),
      ),
    );
  }
}

/// "1 met · 2 self-declared · 24 no evidence yet" -- only non-zero parts.
String adherenceBreakdown(Map<String, dynamic> f) {
  final parts = [
    for (final s in RequirementStatus.all)
      if (_count(f, s.key) > 0) '${_count(f, s.key)} ${s.shortLabel}',
  ];
  return parts.isEmpty ? 'No requirements' : parts.join(' · ');
}

/// True when most applicable requirements have no evidence yet. The headline
/// percentage then says more about what GraphRisk can't see than about how
/// well the framework is met, so screens show it greyed out.
bool evidenceIsThin(Map<String, dynamic> f) {
  final evidencePct = (f['evidence_pct'] as num?)?.toDouble();
  return evidencePct != null && evidencePct < 50;
}

const String kThinEvidenceNote =
    'Most requirements have no evidence yet, so this figure is provisional.';

/// Colour for a percentage, or grey when there's nothing to judge.
Color adherenceColor(double? pct) {
  if (pct == null) return Colors.white38;
  return pct >= 80 ? kGreen : pct >= 40 ? kOrange : kRed;
}
