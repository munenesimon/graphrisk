import 'package:flutter/material.dart';
import '../constants/colors.dart';
import '../models/dashboard.dart';
import '../services/api_service.dart';

/// Lists the tenant's assets and lets an owner/admin flag which ones hold
/// personal data. That flag is what turns on data-protection breach-notice
/// clocks (e.g. the Kenya DPA's 72-hour ODPC notice) for that asset in
/// Blast Radius and Vulnerability Impact -- see REGULATORY_OBLIGATIONS_FOR_ASSETS
/// in graphrisk_core, which only fires a personal_data_breach trigger when
/// the asset carries this flag.
class AssetsScreen extends StatefulWidget {
  const AssetsScreen({super.key});
  @override
  State<AssetsScreen> createState() => _AssetsScreenState();
}

class _AssetsScreenState extends State<AssetsScreen> {
  List<Asset>? _assets;
  bool _loading = true;
  String? _error;
  final Set<String> _pending = {}; // asset ids with an in-flight toggle

  bool get _canEdit => ApiService.role == 'owner' || ApiService.role == 'admin';

  @override
  void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() { _loading = true; _error = null; });
    try {
      final assets = await ApiService.getAssetsFull();
      if (!mounted) return;
      setState(() { _assets = assets; _loading = false; });
    } catch (e) {
      if (!mounted) return;
      if (e is AuthException) return;
      setState(() { _error = e.toString().replaceFirst('Exception: ', ''); _loading = false; });
    }
  }

  Future<void> _toggle(Asset asset, bool value) async {
    final assets = _assets;
    if (assets == null) return;
    final idx = assets.indexWhere((a) => a.id == asset.id);
    if (idx == -1) return;

    // Optimistic update, rolled back on failure.
    setState(() {
      _pending.add(asset.id);
      assets[idx] = asset.copyWith(holdsPersonalData: value);
    });
    try {
      await ApiService.setAssetDataClassification(asset.id, value);
    } catch (e) {
      if (!mounted) return;
      setState(() => assets[idx] = asset.copyWith(holdsPersonalData: !value));
      if (e is! AuthException) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Could not update ${asset.name}: ${e.toString().replaceFirst('Exception: ', '')}')),
        );
      }
    } finally {
      if (mounted) setState(() => _pending.remove(asset.id));
    }
  }

  IconData _iconFor(Asset a) {
    final n = a.name.toLowerCase();
    if (n.contains('gateway') || n.contains('vpn')) return Icons.router_outlined;
    if (n.contains('database') || n.contains('db') || n.contains('sql')) return Icons.storage_outlined;
    if (n.contains('365') || n.contains('email') || n.contains('mail')) return Icons.mail_outlined;
    if (n.contains('payroll') || n.contains('hr')) return Icons.people_outlined;
    return Icons.devices_outlined;
  }

  Color _criticalityColor(String c) {
    switch (c) {
      case 'Critical': return kRed;
      case 'High':     return kOrange;
      case 'Medium':   return kAccent;
      default:          return kGreen;
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator(color: kAccent));
    if (_error != null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Text('Error: $_error', style: const TextStyle(color: kRed)),
        ),
      );
    }

    final assets = _assets ?? [];
    final personalDataCount = assets.where((a) => a.holdsPersonalData).length;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const Text('Assets',
            style: TextStyle(color: Colors.white, fontSize: 22, fontWeight: FontWeight.w700, letterSpacing: -0.3)),
        const SizedBox(height: 4),
        Text(
          '${assets.length} asset${assets.length == 1 ? '' : 's'} · $personalDataCount holding personal data',
          style: const TextStyle(color: Colors.white54, fontSize: 13),
        ),
        const SizedBox(height: 8),
        const Text(
          "Flag which assets hold personal data -- this decides whether a data-protection "
          "breach-notice clock (e.g. the Kenya DPA's 72-hour ODPC notice) applies if the asset "
          "is compromised.",
          style: TextStyle(color: Colors.white38, fontSize: 12, height: 1.5),
        ),
        const SizedBox(height: 20),

        if (!_canEdit)
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(14),
            margin: const EdgeInsets.only(bottom: 16),
            decoration: BoxDecoration(color: kSurface2.withOpacity(0.5), borderRadius: BorderRadius.circular(10)),
            child: Row(children: [
              const Icon(Icons.lock_outline, color: Colors.white38, size: 18),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  'Your role${ApiService.role == null ? '' : ' (${ApiService.role})'} can view assets but '
                  'only an owner or admin can change data classification.',
                  style: const TextStyle(color: Colors.white54, fontSize: 12, height: 1.4),
                ),
              ),
            ]),
          ),

        if (assets.isEmpty)
          const Padding(
            padding: EdgeInsets.all(4),
            child: Text('No assets found for this tenant.', style: TextStyle(color: Colors.white38, fontSize: 13)),
          )
        else
          ...assets.map((a) {
            final busy = _pending.contains(a.id);
            return Container(
              margin: const EdgeInsets.only(bottom: 10),
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: kSurface,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(
                  color: a.holdsPersonalData ? kOrange.withOpacity(0.3) : Colors.white.withOpacity(0.06),
                ),
              ),
              child: Row(children: [
                Container(
                  width: 40, height: 40,
                  decoration: BoxDecoration(
                    color: _criticalityColor(a.criticality).withOpacity(0.1),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Icon(_iconFor(a), color: _criticalityColor(a.criticality), size: 20),
                ),
                const SizedBox(width: 14),
                Expanded(
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text(a.name, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                    const SizedBox(height: 2),
                    Text(
                      [a.assetType, a.criticality, a.environment].where((s) => s.isNotEmpty).join(' · '),
                      style: const TextStyle(color: Colors.white54, fontSize: 12),
                    ),
                    if ((a.vendor ?? '').isNotEmpty || (a.product ?? '').isNotEmpty) ...[
                      const SizedBox(height: 2),
                      Text('${a.vendor ?? ''} ${a.product ?? ''}'.trim(),
                          style: const TextStyle(color: Colors.white38, fontSize: 11)),
                    ],
                  ]),
                ),
                const SizedBox(width: 12),
                Column(crossAxisAlignment: CrossAxisAlignment.end, children: [
                  Text('Personal data',
                      style: TextStyle(
                          color: a.holdsPersonalData ? kOrange : Colors.white38,
                          fontSize: 10, fontWeight: FontWeight.w600)),
                  const SizedBox(height: 2),
                  busy
                      ? const SizedBox(
                          width: 20, height: 20,
                          child: Padding(
                            padding: EdgeInsets.all(2),
                            child: CircularProgressIndicator(strokeWidth: 2, color: kOrange),
                          ),
                        )
                      : Switch(
                          value: a.holdsPersonalData,
                          onChanged: _canEdit ? (v) => _toggle(a, v) : null,
                          activeColor: kOrange,
                        ),
                ]),
              ]),
            );
          }),
      ]),
    );
  }
}
