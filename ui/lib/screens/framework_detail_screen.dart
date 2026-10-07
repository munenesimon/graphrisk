import 'package:flutter/material.dart';
import '../constants/colors.dart';
import '../services/api_service.dart';
import '../widgets/motion.dart';

/// Drill-down from FrameworksScreen's "All Frameworks" list: every
/// requirement (FrameworkControl) in one framework, split into covered
/// and not-yet-covered, instead of only the aggregate percentage the
/// overview bars show. "Covered" here means the same thing the backend's
/// coverage percentage means -- a tenant Control SATISFIES the
/// requirement directly, or SATISFIES something it MAPS_TO via a
/// curated crosswalk -- so the two numbers always agree.
class FrameworkDetailScreen extends StatefulWidget {
  final String frameworkId;
  final String frameworkName;
  const FrameworkDetailScreen({super.key, required this.frameworkId, required this.frameworkName});

  @override
  State<FrameworkDetailScreen> createState() => _FrameworkDetailScreenState();
}

enum _Filter { all, covered, notCovered }

class _FrameworkDetailScreenState extends State<FrameworkDetailScreen> {
  Map<String, dynamic>? _data;
  bool _loading = true;
  String? _error;
  _Filter _filter = _Filter.all;

  @override
  void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() { _loading = true; _error = null; });
    try {
      final data = await ApiService.getFrameworkControls(widget.frameworkId);
      if (!mounted) return;
      setState(() { _data = data; _loading = false; });
    } catch (e) {
      if (!mounted) return;
      if (e is AuthException) return;
      setState(() { _error = e.toString().replaceFirst('Exception: ', ''); _loading = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: kBackground,
      appBar: AppBar(
        backgroundColor: kBackground,
        elevation: 0,
        iconTheme: const IconThemeData(color: Colors.white),
        title: Text(widget.frameworkName, style: const TextStyle(color: Colors.white, fontSize: 18)),
      ),
      body: _loading
          ? const PageSkeleton()
          : _error != null
              ? Center(child: Text('Error: $_error', style: const TextStyle(color: kRed)))
              : _buildBody(),
    );
  }

  Widget _buildBody() {
    final data     = _data!;
    final controls = (data['controls'] as List? ?? []);
    final total    = data['total'] as int? ?? controls.length;
    final covered  = data['covered'] as int? ?? 0;
    final pct      = total > 0 ? covered / total * 100 : 0.0;
    final pctColor = pct >= 80 ? kGreen : pct >= 40 ? kOrange : kRed;

    final shown = switch (_filter) {
      _Filter.all        => controls,
      _Filter.covered    => controls.where((c) => c['status'] != 'not_covered').toList(),
      _Filter.notCovered => controls.where((c) => c['status'] == 'not_covered').toList(),
    };

    return RefreshIndicator(
      onRefresh: _load,
      color: kAccent,
      child: SingleChildScrollView(
        physics: const AlwaysScrollableScrollPhysics(),
        padding: const EdgeInsets.all(24),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(color: kSurface, borderRadius: BorderRadius.circular(12)),
            child: Row(children: [
              Expanded(
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text('$covered / $total requirements covered',
                      style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                  const SizedBox(height: 8),
                  ClipRRect(
                    borderRadius: BorderRadius.circular(4),
                    child: LinearProgressIndicator(
                      value: total > 0 ? covered / total : 0,
                      minHeight: 8,
                      backgroundColor: kSurface2,
                      valueColor: AlwaysStoppedAnimation(pctColor),
                    ),
                  ),
                ]),
              ),
              const SizedBox(width: 16),
              Text('${pct.toStringAsFixed(1)}%',
                  style: TextStyle(color: pctColor, fontWeight: FontWeight.bold, fontSize: 20)),
            ]),
          ),
          const SizedBox(height: 20),

          Row(children: [
            _FilterChip(label: 'All ($total)', selected: _filter == _Filter.all,
                onTap: () => setState(() => _filter = _Filter.all)),
            const SizedBox(width: 8),
            _FilterChip(label: 'Covered ($covered)', selected: _filter == _Filter.covered,
                color: kGreen, onTap: () => setState(() => _filter = _Filter.covered)),
            const SizedBox(width: 8),
            _FilterChip(label: 'Not covered (${total - covered})', selected: _filter == _Filter.notCovered,
                color: kRed, onTap: () => setState(() => _filter = _Filter.notCovered)),
          ]),
          const SizedBox(height: 20),

          if (shown.isEmpty)
            const Padding(
              padding: EdgeInsets.all(4),
              child: Text('No requirements match this filter.', style: TextStyle(color: Colors.white38, fontSize: 13)),
            )
          else
            ...shown.map((c) => _ControlRow(control: c as Map<String, dynamic>)),
        ]),
      ),
    );
  }
}

class _FilterChip extends StatelessWidget {
  final String label;
  final bool selected;
  final Color color;
  final VoidCallback onTap;
  const _FilterChip({required this.label, required this.selected, required this.onTap, this.color = kAccent});

  @override
  Widget build(BuildContext context) {
    return Material(
      color: selected ? color.withOpacity(0.18) : kSurface,
      borderRadius: BorderRadius.circular(20),
      child: InkWell(
        borderRadius: BorderRadius.circular(20),
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(20),
            border: Border.all(color: selected ? color : Colors.white12),
          ),
          child: Text(label,
              style: TextStyle(
                  color: selected ? color : Colors.white60,
                  fontSize: 12,
                  fontWeight: selected ? FontWeight.bold : FontWeight.normal)),
        ),
      ),
    );
  }
}

class _ControlRow extends StatelessWidget {
  final Map<String, dynamic> control;
  const _ControlRow({required this.control});

  @override
  Widget build(BuildContext context) {
    final status = control['status']?.toString() ?? 'not_covered';
    final isCovered = status != 'not_covered';
    final isMapped  = status == 'mapped';
    final color     = isCovered ? kGreen : kRed;
    final icon      = isCovered ? Icons.check_circle_outline : Icons.radio_button_unchecked;

    final direct = (control['direct_controls'] as List? ?? []).cast<String>();
    final mapped = (control['mapped_controls'] as List? ?? []).cast<String>();
    final satisfiedBy = direct.isNotEmpty ? direct : mapped;

    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: kSurface,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withOpacity(0.25)),
      ),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Icon(icon, color: color, size: 20),
        const SizedBox(width: 12),
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Text(control['control_reference']?.toString() ?? '',
                  style: const TextStyle(color: Colors.white54, fontSize: 11, fontWeight: FontWeight.bold)),
              const SizedBox(width: 8),
              if ((control['domain'] ?? '').toString().isNotEmpty)
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                  decoration: BoxDecoration(color: kSurface2, borderRadius: BorderRadius.circular(10)),
                  child: Text(control['domain'].toString(),
                      style: const TextStyle(color: Colors.white54, fontSize: 10)),
                ),
            ]),
            const SizedBox(height: 4),
            Text(control['title']?.toString() ?? '',
                style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600, fontSize: 13)),
            if ((control['summary'] ?? '').toString().isNotEmpty) ...[
              const SizedBox(height: 4),
              Text(control['summary'].toString(),
                  style: const TextStyle(color: Colors.white38, fontSize: 12), maxLines: 2, overflow: TextOverflow.ellipsis),
            ],
            const SizedBox(height: 6),
            Text(
              isCovered
                  ? 'Covered ${isMapped ? "via crosswalk" : "directly"} by ${satisfiedBy.join(", ")}'
                  : 'Not covered by any implemented control',
              style: TextStyle(color: color, fontSize: 11, fontWeight: FontWeight.w600),
            ),
          ]),
        ),
      ]),
    );
  }
}
