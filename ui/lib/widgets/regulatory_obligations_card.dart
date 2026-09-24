import 'package:flutter/material.dart';
import '../constants/colors.dart';
import '../constants/frameworks.dart';
import '../models/dashboard.dart';

/// Renders the notification duties ("tell the ODPC within 72 hours") that
/// would apply if a set of exposed assets were involved in a breach or
/// incident. Shared by BlastRadiusScreen and VulnerabilityScreen -- both
/// call GraphRisk endpoints that return a `regulatory_obligations` block
/// with the same shape (see RegulatoryObligations in models/dashboard.dart).
class RegulatoryObligationsSection extends StatelessWidget {
  final RegulatoryObligations obligations;
  /// Optional: lets the caller offer a way to jump to the Regulatory
  /// Profile screen when there's nothing to show because no profile is set.
  final VoidCallback? onManageProfile;

  const RegulatoryObligationsSection({
    super.key,
    required this.obligations,
    this.onManageProfile,
  });

  @override
  Widget build(BuildContext context) {
    final items = obligations.obligations;
    return Container(
      decoration: BoxDecoration(
        color: kSurface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: kOrange.withOpacity(0.25)),
      ),
      child: Column(children: [
        Padding(
          padding: const EdgeInsets.all(16),
          child: Row(children: [
            Container(
              width: 32, height: 32,
              decoration: BoxDecoration(
                  color: kOrange.withOpacity(0.12), borderRadius: BorderRadius.circular(8)),
              child: const Icon(Icons.timer_outlined, color: kOrange, size: 17),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                const Text('Regulatory Notification Clocks',
                    style: TextStyle(color: Colors.white, fontWeight: FontWeight.w600, fontSize: 13)),
                Text(
                  items.isEmpty
                      ? 'None apply here'
                      : '${items.length} clock${items.length == 1 ? '' : 's'} would start',
                  style: TextStyle(color: kOrange.withOpacity(0.8), fontSize: 11),
                ),
              ]),
            ),
          ]),
        ),
        Divider(height: 1, color: kOrange.withOpacity(0.15)),
        Padding(
          padding: const EdgeInsets.all(12),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            if (obligations.note.isNotEmpty)
              Padding(
                padding: const EdgeInsets.only(bottom: 10, left: 4, right: 4),
                child: Text(obligations.note,
                    style: const TextStyle(color: Colors.white38, fontSize: 11, height: 1.5)),
              ),
            if (items.isEmpty) _EmptyState(hint: obligations.hint, onManageProfile: onManageProfile),
            ...items.map((o) => Padding(
                  padding: const EdgeInsets.only(bottom: 6),
                  child: _ObligationItem(obligation: o),
                )),
          ]),
        ),
      ]),
    );
  }
}

class _EmptyState extends StatelessWidget {
  final String? hint;
  final VoidCallback? onManageProfile;
  const _EmptyState({this.hint, this.onManageProfile});

  @override
  Widget build(BuildContext context) {
    if (hint == null) return const SizedBox.shrink();
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      margin: const EdgeInsets.only(bottom: 6),
      decoration: BoxDecoration(
        color: kSurface2.withOpacity(0.5),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(children: [
          const Icon(Icons.info_outline, color: Colors.white38, size: 14),
          const SizedBox(width: 8),
          Expanded(child: Text(hint!, style: const TextStyle(color: Colors.white54, fontSize: 12, height: 1.4))),
        ]),
        if (onManageProfile != null) ...[
          const SizedBox(height: 8),
          Align(
            alignment: Alignment.centerLeft,
            child: TextButton.icon(
              onPressed: onManageProfile,
              icon: const Icon(Icons.gavel_outlined, size: 14, color: kAccent),
              label: const Text('Set regulatory profile', style: TextStyle(color: kAccent, fontSize: 12)),
              style: TextButton.styleFrom(padding: EdgeInsets.zero, minimumSize: const Size(0, 0)),
            ),
          ),
        ],
      ]),
    );
  }
}

class _ObligationItem extends StatefulWidget {
  final RegulatoryObligation obligation;
  const _ObligationItem({required this.obligation});

  @override
  State<_ObligationItem> createState() => _ObligationItemState();
}

class _ObligationItemState extends State<_ObligationItem> {
  bool _expanded = false;

  String get _deadlineLabel {
    final h = widget.obligation.deadlineHours;
    if (h % 24 == 0 && h >= 24) {
      final days = h ~/ 24;
      return '$h h ($days day${days == 1 ? '' : 's'})';
    }
    return '$h h';
  }

  @override
  Widget build(BuildContext context) {
    final o = widget.obligation;
    return GestureDetector(
      onTap: () => setState(() => _expanded = !_expanded),
      child: Container(
        width: double.infinity,
        margin: const EdgeInsets.only(bottom: 6),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: kOrange.withOpacity(0.07),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: kOrange.withOpacity(0.2)),
        ),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              decoration: BoxDecoration(color: kOrange.withOpacity(0.18), borderRadius: BorderRadius.circular(6)),
              child: Text(_deadlineLabel,
                  style: const TextStyle(color: kOrange, fontSize: 12, fontWeight: FontWeight.bold)),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(o.title.isEmpty ? o.requirement : o.title,
                    style: const TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.w500)),
                const SizedBox(height: 2),
                Text('${frameworkDisplayName(o.framework)} · ${o.requirement} · notify ${o.notify}',
                    style: const TextStyle(color: Colors.white54, fontSize: 11)),
              ]),
            ),
            Icon(_expanded ? Icons.expand_less : Icons.expand_more, color: kOrange.withOpacity(0.6), size: 16),
          ]),
          if (_expanded) ...[
            const SizedBox(height: 10),
            const Divider(height: 1, color: Colors.white10),
            const SizedBox(height: 10),
            _detailRow('Triggered by', o.trigger.replaceAll('_', ' ')),
            if (o.condition != null && o.condition!.isNotEmpty) _detailRow('Condition', o.condition!),
            if (o.legalSource != null && o.legalSource!.isNotEmpty) _detailRow('Legal source', o.legalSource!),
            if (o.triggeredByAssets.isNotEmpty) _detailRow('Assets involved', o.triggeredByAssets.join(', ')),
          ],
        ]),
      ),
    );
  }

  Widget _detailRow(String label, String value) => Padding(
        padding: const EdgeInsets.only(bottom: 6),
        child: RichText(
          text: TextSpan(children: [
            TextSpan(text: '$label: ', style: const TextStyle(color: Colors.white38, fontSize: 11, fontWeight: FontWeight.w600)),
            TextSpan(text: value, style: const TextStyle(color: Colors.white60, fontSize: 11, height: 1.5)),
          ]),
        ),
      );
}
