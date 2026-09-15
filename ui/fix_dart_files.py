"""
Rewrites the two Dart files with correct string interpolation.
Run from graphrisk_ui folder: python fix_dart_files.py
"""
import os

LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib")

def write(rel_path, content):
    full = os.path.join(LIB, rel_path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  Fixed: lib/{rel_path}")

write("screens/frameworks_screen.dart", r"""
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
      setState(() { _frameworks = f; _coverage = c; _loading = false; });
    } catch (e) {
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
            final pct   = (c['coverage_pct'] ?? 0.0).toDouble();
            final color = pct >= 80 ? kGreen : pct >= 40 ? kOrange : kRed;
            final covered = c['covered_controls']?.toString() ?? '0';
            final total   = c['total_controls']?.toString()   ?? '0';
            final version = c['version']?.toString() ?? '';
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
                Text('v$version · $controls controls',
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
""")

write("screens/vulnerability_screen.dart", r"""
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

    final sources = (_intel?['vulnerability_sources'] as List? ?? []);
    final recent  = (_intel?['recent_ransomware_kev']  as List? ?? []);

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const Text('Vulnerability Intelligence',
            style: TextStyle(color: Colors.white, fontSize: 22, fontWeight: FontWeight.bold)),
        const SizedBox(height: 4),
        const Text('Live data from CISA KEV + NVD',
            style: TextStyle(color: Colors.white54, fontSize: 13)),
        const SizedBox(height: 28),

        ...sources.map((s) {
          final total      = s['total'] as int? ?? 0;
          final ransomware = s['ransomware'] as int? ?? 0;
          final source     = s['source']?.toString() ?? '';
          final isKev      = source == 'CISA_KEV';
          final color      = isKev ? kRed : kOrange;
          return Container(
            margin: const EdgeInsets.only(bottom: 12),
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: kSurface, borderRadius: BorderRadius.circular(12),
              border: Border.all(color: color.withOpacity(0.3))),
            child: Row(children: [
              Container(width: 48, height: 48,
                decoration: BoxDecoration(
                  color: color.withOpacity(0.1), borderRadius: BorderRadius.circular(8)),
                child: Icon(
                  isKev ? Icons.warning_amber_rounded : Icons.bug_report_outlined,
                  color: color, size: 24)),
              const SizedBox(width: 16),
              Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(isKev ? 'CISA KEV — Actively Exploited' : 'NVD — Critical Severity',
                    style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                Text('$total vulnerabilities · $ransomware ransomware',
                    style: const TextStyle(color: Colors.white54, fontSize: 12)),
              ])),
              Text(total.toString(),
                  style: TextStyle(color: color, fontSize: 22, fontWeight: FontWeight.bold)),
            ]),
          );
        }),

        const SizedBox(height: 28),

        if (recent.isNotEmpty) ...[
          const Text('Recent Ransomware-Linked CVEs (CISA KEV)',
              style: TextStyle(color: Colors.white70, fontSize: 14, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          ...recent.map((v) {
            final cveId   = v['cve_id']?.toString()  ?? '';
            final title   = v['title']?.toString()   ?? '';
            final vendor  = v['vendor']?.toString()  ?? '';
            final product = v['product']?.toString() ?? '';
            return Container(
              margin: const EdgeInsets.only(bottom: 8),
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: kSurface, borderRadius: BorderRadius.circular(8),
                border: Border.all(color: kRed.withOpacity(0.2))),
              child: Row(children: [
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(
                    color: kRed.withOpacity(0.1), borderRadius: BorderRadius.circular(4)),
                  child: Text(cveId,
                      style: const TextStyle(
                          color: kRed, fontSize: 11,
                          fontFamily: 'monospace', fontWeight: FontWeight.bold))),
                const SizedBox(width: 12),
                Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(title,
                      style: const TextStyle(color: Colors.white, fontSize: 13),
                      maxLines: 1, overflow: TextOverflow.ellipsis),
                  Text('$vendor · $product',
                      style: const TextStyle(color: Colors.white54, fontSize: 11)),
                ])),
              ]),
            );
          }),
        ],
      ]),
    );
  }
}
""")

print("\nAll files fixed. Run: flutter run -d chrome --web-port=3000")
