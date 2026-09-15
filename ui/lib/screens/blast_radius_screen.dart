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
  final _ctrl  = TextEditingController();
  BlastRadius? _result;
  bool         _loading = false;
  String?      _error;
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
        const Text('Blast Radius Engine',
            style: TextStyle(color: Colors.white, fontSize: 22, fontWeight: FontWeight.bold)),
        const SizedBox(height: 4),
        const Text('Enter a control ID to see its full impact chain',
            style: TextStyle(color: Colors.white54, fontSize: 13)),
        const SizedBox(height: 24),
        Row(children: [
          Expanded(child: TextField(
            controller: _ctrl,
            style: const TextStyle(color: Colors.white, fontSize: 13, fontFamily: 'monospace'),
            decoration: InputDecoration(
              hintText: 'Control UUID...',
              hintStyle: const TextStyle(color: Colors.white38),
              filled: true, fillColor: kSurface,
              border: OutlineInputBorder(borderRadius: BorderRadius.circular(8),
                  borderSide: BorderSide(color: kAccent.withOpacity(0.3))),
              enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(8),
                  borderSide: BorderSide(color: kAccent.withOpacity(0.3))),
              focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(8),
                  borderSide: const BorderSide(color: kAccent)),
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
          decoration: BoxDecoration(color: kRed.withOpacity(0.1),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: kRed.withOpacity(0.3))),
          child: Text('Error: ' + _error!, style: const TextStyle(color: kRed)),
        ),
        if (_result != null) ...[
          Container(
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(color: kSurface,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: kAccent.withOpacity(0.3))),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Row(children: [
                const Icon(Icons.shield_outlined, color: kAccent, size: 20),
                const SizedBox(width: 10),
                Expanded(child: Text(_result!.controlTitle,
                    style: const TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold))),
                _StatusBadge(status: _result!.controlStatus),
              ]),
              const SizedBox(height: 12),
              Text('Effectiveness: ' + (_result!.effectivenessScore * 100).toInt().toString() + '%',
                  style: const TextStyle(color: Colors.white60, fontSize: 13)),
            ]),
          ),
          const SizedBox(height: 20),
          Wrap(spacing: 10, runSpacing: 10, children: [
            _ImpactChip(label: _result!.riskCount.toString() + ' Risks',           color: kRed,    icon: Icons.warning_amber),
            _ImpactChip(label: _result!.assetCount.toString() + ' Assets',         color: kOrange, icon: Icons.devices),
            _ImpactChip(label: _result!.frameworkCount.toString() + ' Frameworks', color: kPurple, icon: Icons.policy),
          ]),
          const SizedBox(height: 24),
          _ImpactSection(title: 'Exposed Risks',      items: _result!.exposedRisks,      color: kRed,    icon: Icons.warning_amber_rounded),
          const SizedBox(height: 16),
          _ImpactSection(title: 'Affected Assets',    items: _result!.affectedAssets,    color: kOrange, icon: Icons.devices_outlined),
          const SizedBox(height: 16),
          _ImpactSection(title: 'Compliance Gaps',    items: _result!.complianceGaps,    color: kPurple, icon: Icons.policy_outlined),
          const SizedBox(height: 16),
          _ImpactSection(title: 'Framework Controls', items: _result!.frameworkControls, color: kAccent, icon: Icons.list_alt_outlined),
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
  String get _label {
    if (status == 'PartiallyImplemented') return 'Partial';
    return status;
  }
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
    decoration: BoxDecoration(color: _color.withOpacity(0.15), borderRadius: BorderRadius.circular(20)),
    child: Text(_label, style: TextStyle(color: _color, fontSize: 11, fontWeight: FontWeight.bold)),
  );
}

class _ImpactChip extends StatelessWidget {
  final String   label;
  final Color    color;
  final IconData icon;
  const _ImpactChip({required this.label, required this.color, required this.icon});
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
    decoration: BoxDecoration(color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color.withOpacity(0.3))),
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
  const _ImpactSection({required this.title, required this.items,
                         required this.color, required this.icon});
  @override
  Widget build(BuildContext context) {
    if (items.isEmpty) return const SizedBox.shrink();
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      SectionHeader(title: title),
      Wrap(spacing: 8, runSpacing: 8, children: items.map((item) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        decoration: BoxDecoration(color: color.withOpacity(0.1),
            borderRadius: BorderRadius.circular(6),
            border: Border.all(color: color.withOpacity(0.3))),
        child: Row(mainAxisSize: MainAxisSize.min, children: [
          Icon(icon, color: color, size: 14),
          const SizedBox(width: 6),
          Text(item, style: TextStyle(color: color, fontSize: 13)),
        ]),
      )).toList()),
    ]);
  }
}
