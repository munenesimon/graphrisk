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
  void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    try {
      final f = await ApiService.getFrameworks();
      final c = await ApiService.getFrameworkCoverage();
      if (!mounted) return;
      setState(() { _frameworks = f; _coverage = c; _loading = false; });
    } catch (e) {
      if (!mounted) return;
      // Session-expiry redirect is already in flight -- see dashboard_screen.dart.
      if (e is AuthException) return;
      setState(() { _loading = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator(color: kAccent));
    final frameworks   = _frameworks ?? [];
    final coverageList = (_coverage?['frameworks'] as List? ?? []);

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const Text('Compliance Frameworks',
            style: TextStyle(color: Colors.white, fontSize: 22, fontWeight: FontWeight.bold)),
        const SizedBox(height: 4),
        const Text('Framework control coverage for your tenant',
            style: TextStyle(color: Colors.white54, fontSize: 13)),
        const SizedBox(height: 28),

        if (coverageList.isNotEmpty) ...[
          const Text('Coverage Overview',
              style: TextStyle(color: Colors.white70, fontSize: 14, fontWeight: FontWeight.bold)),
          const SizedBox(height: 16),
          ...coverageList.map((c) {
            final pct     = (c['coverage_pct'] ?? 0.0).toDouble();
            final color   = pct >= 80 ? kGreen : pct >= 40 ? kOrange : kRed;
            final covered = c['covered_controls']?.toString() ?? '0';
            final total   = c['total_controls']?.toString()   ?? '0';
            return Container(
              margin: const EdgeInsets.only(bottom: 12),
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(color: kSurface, borderRadius: BorderRadius.circular(12)),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Row(children: [
                  Text(c['framework']?.toString() ?? '',
                      style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                  const Spacer(),
                  Text('${pct.toStringAsFixed(1)}%',
                      style: TextStyle(color: color, fontWeight: FontWeight.bold, fontSize: 16)),
                ]),
                const SizedBox(height: 4),
                Text('$covered / $total controls covered',
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

        const Text('All Frameworks',
            style: TextStyle(color: Colors.white70, fontSize: 14, fontWeight: FontWeight.bold)),
        const SizedBox(height: 16),
        ...frameworks.map((f) {
          final name     = f['name']?.toString()           ?? '';
          final version  = f['version']?.toString()        ?? '';
          final controls = f['total_controls']?.toString() ?? '0';
          return Container(
            margin: const EdgeInsets.only(bottom: 10),
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: kSurface, borderRadius: BorderRadius.circular(10),
              border: Border.all(color: kAccent.withOpacity(0.2))),
            child: Row(children: [
              Container(width: 40, height: 40,
                decoration: BoxDecoration(
                  color: kAccent.withOpacity(0.1), borderRadius: BorderRadius.circular(8)),
                child: const Icon(Icons.policy_outlined, color: kAccent, size: 20)),
              const SizedBox(width: 14),
              Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(name, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                Text('v$version - $controls controls',
                    style: const TextStyle(color: Colors.white54, fontSize: 12)),
              ])),
              const Icon(Icons.chevron_right, color: Colors.white38),
            ]),
          );
        }),
      ]),
    );
  }
}