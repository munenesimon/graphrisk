import 'package:flutter/material.dart';
import '../constants/colors.dart';
import '../constants/connectors.dart';
import '../services/api_service.dart';

/// Lets a tenant see every connector adapter registered in this GraphRisk
/// deployment (the "Universal Connector Architecture" from the README),
/// what checks each one runs, and -- for owner/admin roles -- save
/// credentials for one (encrypted server-side, see api/app/connectors/
/// crypto.py) and/or run it.
///
/// Saving is optional: a connector can still be run ad hoc by filling in
/// its fields and tapping Run without ever saving -- that config is used
/// for that one call only, exactly as before this screen could persist
/// anything. Once a field is saved, leaving it blank on a later run reuses
/// the saved value automatically (the backend merges saved config with
/// whatever's in the request body); typing a new value overrides it for
/// that run without changing what's saved. Saved values are never sent
/// back to this screen -- GET /connectors/config reports which keys are
/// set, never their values -- so a "saved" field always renders empty
/// here, not pre-filled.
class ConnectorsScreen extends StatefulWidget {
  const ConnectorsScreen({super.key});
  @override
  State<ConnectorsScreen> createState() => _ConnectorsScreenState();
}

class _ConnectorsScreenState extends State<ConnectorsScreen> {
  bool _loading = true;
  String? _error;
  List<String> _connectorIds = [];
  Map<String, List<String>> _checksByConnector = {};

  String? _expandedId;
  final Map<String, Map<String, TextEditingController>> _controllers = {};
  final Set<String> _running = {};
  final Set<String> _saving = {};
  final Set<String> _deleting = {};
  final Map<String, Map<String, dynamic>> _lastResult = {};
  final Map<String, String> _lastError = {};
  // connector_id -> which of its REQUIRED_CONFIG_KEYS have a saved value.
  // Populated from GET /connectors/config; never contains actual values.
  Map<String, List<String>> _savedKeys = {};

  bool get _canRun => ApiService.role == 'owner' || ApiService.role == 'admin';

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    for (final fields in _controllers.values) {
      for (final c in fields.values) {
        c.dispose();
      }
    }
    super.dispose();
  }

  Future<void> _load() async {
    setState(() { _loading = true; _error = null; });
    try {
      // Run together: the connector catalog is global, the saved-config
      // map is tenant-scoped, and neither depends on the other.
      final results = await Future.wait([
        ApiService.getConnectors(),
        ApiService.getConnectorConfigs(),
      ]);
      final data = results[0];
      final configs = results[1];

      final ids = (data['connectors'] as List? ?? []).cast<String>();
      final checksMap = (data['checks'] as Map? ?? {}).cast<String, dynamic>();
      final byConnector = <String, List<String>>{ for (final id in ids) id: [] };
      checksMap.forEach((checkId, connectorId) {
        byConnector.putIfAbsent(connectorId as String, () => []).add(checkId);
      });

      final savedKeys = <String, List<String>>{};
      configs.forEach((connectorId, entry) {
        final keys = ((entry as Map?)?['config_keys'] as List?) ?? [];
        savedKeys[connectorId] = keys.cast<String>();
      });

      if (!mounted) return;
      setState(() {
        _connectorIds = ids;
        _checksByConnector = byConnector;
        _savedKeys = savedKeys;
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      if (e is AuthException) return;
      setState(() { _error = e.toString().replaceFirst('Exception: ', ''); _loading = false; });
    }
  }

  Map<String, TextEditingController> _controllersFor(ConnectorSpec spec) {
    return _controllers.putIfAbsent(spec.id, () => {
      for (final f in spec.fields) f.key: TextEditingController(),
    });
  }

  Future<void> _run(ConnectorSpec spec) async {
    final controllers = _controllersFor(spec);
    final config = <String, String>{
      for (final entry in controllers.entries)
        if (entry.value.text.trim().isNotEmpty) entry.key: entry.value.text.trim(),
    };
    setState(() {
      _running.add(spec.id);
      _lastResult.remove(spec.id);
      _lastError.remove(spec.id);
    });
    try {
      final result = await ApiService.runConnector(spec.id, config);
      if (!mounted) return;
      setState(() => _lastResult[spec.id] = result);
    } catch (e) {
      if (!mounted) return;
      if (e is AuthException) return;
      setState(() => _lastError[spec.id] = e.toString().replaceFirst('Exception: ', ''));
    } finally {
      if (mounted) setState(() => _running.remove(spec.id));
    }
  }

  Future<void> _save(ConnectorSpec spec) async {
    final controllers = _controllersFor(spec);
    final config = <String, String>{
      for (final entry in controllers.entries)
        if (entry.value.text.trim().isNotEmpty) entry.key: entry.value.text.trim(),
    };
    if (config.isEmpty) {
      setState(() => _lastError[spec.id] = 'Enter at least one field before saving.');
      return;
    }
    setState(() {
      _saving.add(spec.id);
      _lastError.remove(spec.id);
    });
    try {
      final result = await ApiService.saveConnectorConfig(spec.id, config);
      if (!mounted) return;
      final keys = ((result['config_keys'] as List?) ?? []).cast<String>();
      setState(() {
        _savedKeys[spec.id] = keys;
        // Saved values are never shown back to this screen, so there's
        // nothing useful left in the fields -- clear them rather than
        // leave plaintext secrets sitting visible after a successful save.
        for (final c in controllers.values) {
          c.clear();
        }
      });
    } catch (e) {
      if (!mounted) return;
      if (e is AuthException) return;
      setState(() => _lastError[spec.id] = e.toString().replaceFirst('Exception: ', ''));
    } finally {
      if (mounted) setState(() => _saving.remove(spec.id));
    }
  }

  Future<void> _clearSaved(ConnectorSpec spec) async {
    setState(() {
      _deleting.add(spec.id);
      _lastError.remove(spec.id);
    });
    try {
      await ApiService.deleteConnectorConfig(spec.id);
      if (!mounted) return;
      setState(() => _savedKeys.remove(spec.id));
    } catch (e) {
      if (!mounted) return;
      if (e is AuthException) return;
      setState(() => _lastError[spec.id] = e.toString().replaceFirst('Exception: ', ''));
    } finally {
      if (mounted) setState(() => _deleting.remove(spec.id));
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

    final totalChecks = _checksByConnector.values.fold<int>(0, (sum, v) => sum + v.length);

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const Text('Connectors',
            style: TextStyle(color: Colors.white, fontSize: 22, fontWeight: FontWeight.w700, letterSpacing: -0.3)),
        const SizedBox(height: 4),
        Text(
          '${_connectorIds.length} connector${_connectorIds.length == 1 ? '' : 's'} registered · '
          '$totalChecks check${totalChecks == 1 ? '' : 's'}',
          style: const TextStyle(color: Colors.white54, fontSize: 13),
        ),
        const SizedBox(height: 8),
        const Text(
          'The universal connector architecture: any security tool plugs into the graph through '
          'a per-vendor adapter. Running one here tests it end-to-end against your own tenant, '
          'writing results straight to the Control nodes it maps to.',
          style: TextStyle(color: Colors.white38, fontSize: 12, height: 1.5),
        ),
        const SizedBox(height: 12),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(12),
          margin: const EdgeInsets.only(bottom: 16),
          decoration: BoxDecoration(color: kSurface2.withOpacity(0.5), borderRadius: BorderRadius.circular(10)),
          child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            const Icon(Icons.lock_outline, color: Colors.white38, size: 16),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                "Run tests a connector without saving anything. Save encrypts credentials and "
                "stores them for this connector so future runs don't need them re-entered -- "
                "saved values are never shown back here, only which fields are set.",
                style: TextStyle(color: Colors.white54, fontSize: 12, height: 1.4),
              ),
            ),
          ]),
        ),

        if (!_canRun)
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(14),
            margin: const EdgeInsets.only(bottom: 16),
            decoration: BoxDecoration(color: kSurface2.withOpacity(0.5), borderRadius: BorderRadius.circular(10)),
            child: Row(children: [
              const Icon(Icons.visibility_outlined, color: Colors.white38, size: 18),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  'Your role${ApiService.role == null ? '' : ' (${ApiService.role})'} can view connectors but '
                  'only an owner or admin can run one -- it writes results to your Control nodes.',
                  style: const TextStyle(color: Colors.white54, fontSize: 12, height: 1.4),
                ),
              ),
            ]),
          ),

        if (_connectorIds.isEmpty)
          const Padding(
            padding: EdgeInsets.all(4),
            child: Text('No connectors registered.', style: TextStyle(color: Colors.white38, fontSize: 13)),
          )
        else
          ..._connectorIds.map((id) {
            final spec = connectorSpecFor(id);
            return _ConnectorCard(
              spec: spec,
              checks: _checksByConnector[id] ?? const [],
              expanded: _expandedId == id,
              canRun: _canRun,
              running: _running.contains(id),
              saving: _saving.contains(id),
              deleting: _deleting.contains(id),
              savedKeys: _savedKeys[id] ?? const [],
              result: _lastResult[id],
              error: _lastError[id],
              controllers: _controllersFor(spec),
              onToggle: () => setState(() => _expandedId = _expandedId == id ? null : id),
              onRun: () => _run(spec),
              onSave: () => _save(spec),
              onClearSaved: () => _clearSaved(spec),
            );
          }),
      ]),
    );
  }
}

class _ConnectorCard extends StatelessWidget {
  final ConnectorSpec spec;
  final List<String> checks;
  final bool expanded;
  final bool canRun;
  final bool running;
  final bool saving;
  final bool deleting;
  final List<String> savedKeys;
  final Map<String, dynamic>? result;
  final String? error;
  final Map<String, TextEditingController> controllers;
  final VoidCallback onToggle;
  final VoidCallback onRun;
  final VoidCallback onSave;
  final VoidCallback onClearSaved;

  const _ConnectorCard({
    required this.spec,
    required this.checks,
    required this.expanded,
    required this.canRun,
    required this.running,
    required this.saving,
    required this.deleting,
    required this.savedKeys,
    required this.result,
    required this.error,
    required this.controllers,
    required this.onToggle,
    required this.onRun,
    required this.onSave,
    required this.onClearSaved,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(
        color: kSurface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.white.withOpacity(0.06)),
      ),
      child: Column(children: [
        InkWell(
          onTap: onToggle,
          borderRadius: BorderRadius.circular(12),
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Row(children: [
              Container(
                width: 36, height: 36,
                decoration: BoxDecoration(color: kAccent.withOpacity(0.12), borderRadius: BorderRadius.circular(8)),
                child: const Icon(Icons.link_outlined, color: kAccent, size: 18),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Row(children: [
                    Text(spec.name, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 14)),
                    if (!spec.liveVerified) ...[
                      const SizedBox(width: 8),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                        decoration: BoxDecoration(color: kOrange.withOpacity(0.15), borderRadius: BorderRadius.circular(4)),
                        child: const Text('pending live instance',
                            style: TextStyle(color: kOrange, fontSize: 9, fontWeight: FontWeight.w600)),
                      ),
                    ],
                    if (savedKeys.isNotEmpty) ...[
                      const SizedBox(width: 8),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                        decoration: BoxDecoration(color: kGreen.withOpacity(0.15), borderRadius: BorderRadius.circular(4)),
                        child: Row(mainAxisSize: MainAxisSize.min, children: [
                          const Icon(Icons.check_circle, color: kGreen, size: 10),
                          const SizedBox(width: 3),
                          Text('${savedKeys.length} saved',
                              style: const TextStyle(color: kGreen, fontSize: 9, fontWeight: FontWeight.w600)),
                        ]),
                      ),
                    ],
                  ]),
                  const SizedBox(height: 2),
                  Text('${spec.authPattern} · ${checks.length} check${checks.length == 1 ? '' : 's'}',
                      style: const TextStyle(color: Colors.white54, fontSize: 11)),
                ]),
              ),
              Icon(expanded ? Icons.expand_less : Icons.expand_more, color: Colors.white38, size: 20),
            ]),
          ),
        ),
        if (expanded) ...[
          const Divider(height: 1, color: Colors.white10),
          Padding(
            padding: const EdgeInsets.all(16),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Wrap(
                spacing: 6, runSpacing: 6,
                children: checks.map((c) => Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(color: kSurface2.withOpacity(0.6), borderRadius: BorderRadius.circular(6)),
                  child: Text(humanizeCheckId(c), style: const TextStyle(color: Colors.white60, fontSize: 11)),
                )).toList(),
              ),
              if (spec.fields.isNotEmpty) ...[
                const SizedBox(height: 16),
                ...spec.fields.map((f) {
                  final isSaved = savedKeys.contains(f.key);
                  return Padding(
                    padding: const EdgeInsets.only(bottom: 10),
                    child: TextField(
                      controller: controllers[f.key],
                      obscureText: f.secret,
                      enabled: canRun && !running && !saving && !deleting,
                      style: const TextStyle(color: Colors.white, fontSize: 13),
                      decoration: InputDecoration(
                        labelText: f.label,
                        hintText: isSaved ? 'Saved -- leave blank to keep it' : f.hint,
                        suffixIcon: isSaved
                            ? const Padding(
                                padding: EdgeInsets.only(right: 4),
                                child: Icon(Icons.check_circle, color: kGreen, size: 16),
                              )
                            : null,
                        labelStyle: const TextStyle(color: Colors.white38, fontSize: 12),
                        hintStyle: TextStyle(color: isSaved ? kGreen.withOpacity(0.6) : Colors.white24, fontSize: 12),
                        filled: true,
                        fillColor: kSurface2.withOpacity(0.4),
                        border: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: BorderSide.none),
                        isDense: true,
                        contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                      ),
                    ),
                  );
                }),
              ] else if (canRun) ...[
                const SizedBox(height: 16),
                const Text('No credentials needed -- this adapter has nothing to configure.',
                    style: TextStyle(color: Colors.white38, fontSize: 11)),
              ],
              const SizedBox(height: 12),
              Wrap(spacing: 10, runSpacing: 10, crossAxisAlignment: WrapCrossAlignment.center, children: [
                ElevatedButton.icon(
                  onPressed: canRun && !running && !saving && !deleting ? onRun : null,
                  icon: running
                      ? const SizedBox(
                          width: 14, height: 14,
                          child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                        )
                      : const Icon(Icons.play_arrow, size: 16),
                  label: Text(running ? 'Running…' : 'Run connector'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: kAccent,
                    foregroundColor: Colors.white,
                    disabledBackgroundColor: kSurface2,
                  ),
                ),
                if (spec.fields.isNotEmpty) ...[
                  OutlinedButton.icon(
                    onPressed: canRun && !running && !saving && !deleting ? onSave : null,
                    icon: saving
                        ? const SizedBox(
                            width: 14, height: 14,
                            child: CircularProgressIndicator(strokeWidth: 2, color: kAccent),
                          )
                        : const Icon(Icons.save_outlined, size: 16),
                    label: Text(saving ? 'Saving…' : 'Save credentials'),
                    style: OutlinedButton.styleFrom(
                      foregroundColor: kAccent,
                      side: const BorderSide(color: kAccent),
                    ),
                  ),
                  if (savedKeys.isNotEmpty)
                    TextButton.icon(
                      onPressed: canRun && !running && !saving && !deleting ? onClearSaved : null,
                      icon: deleting
                          ? const SizedBox(
                              width: 14, height: 14,
                              child: CircularProgressIndicator(strokeWidth: 2, color: kRed),
                            )
                          : const Icon(Icons.delete_outline, size: 16, color: kRed),
                      label: Text(deleting ? 'Clearing…' : 'Clear saved',
                          style: const TextStyle(color: kRed)),
                    ),
                ],
              ]),
              if (error != null) ...[
                const SizedBox(height: 12),
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: kRed.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: kRed.withOpacity(0.3)),
                  ),
                  child: Text(error!, style: const TextStyle(color: kRed, fontSize: 12)),
                ),
              ],
              if (result != null) ...[
                const SizedBox(height: 12),
                _ResultSummary(result: result!),
              ],
            ]),
          ),
        ],
      ]),
    );
  }
}

class _ResultSummary extends StatelessWidget {
  final Map<String, dynamic> result;
  const _ResultSummary({required this.result});

  Color _statusColor(String status) {
    switch (status) {
      case 'PASS': return kGreen;
      case 'FAIL': return kRed;
      case 'WARNING': return kOrange;
      case 'ERROR': return kRed;
      default: return Colors.white38; // SKIPPED / unknown
    }
  }

  IconData _statusIcon(String status) {
    switch (status) {
      case 'PASS': return Icons.check_circle_outline;
      case 'FAIL': return Icons.cancel_outlined;
      case 'WARNING': return Icons.warning_amber_outlined;
      case 'ERROR': return Icons.error_outline;
      default: return Icons.remove_circle_outline;
    }
  }

  @override
  Widget build(BuildContext context) {
    final results = (result['results'] as List? ?? []).cast<Map<String, dynamic>>();
    final errors = (result['errors'] as List? ?? []).cast<Map<String, dynamic>>();
    final checksRun = result['checks_run'] ?? results.length;
    final checksFailed = result['checks_failed'] ?? errors.length;

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(color: kSurface2.withOpacity(0.4), borderRadius: BorderRadius.circular(8)),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text('$checksRun ran · $checksFailed failed',
            style: const TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.w600)),
        const SizedBox(height: 8),
        ...results.map((r) {
          final status = (r['status'] as String?) ?? '';
          final checkId = (r['check_id'] as String?) ?? '';
          final detail = (r['detail'] as String?) ?? '';
          return Padding(
            padding: const EdgeInsets.only(bottom: 6),
            child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Icon(_statusIcon(status), color: _statusColor(status), size: 14),
              const SizedBox(width: 8),
              Expanded(
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(humanizeCheckId(checkId),
                      style: const TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.w500)),
                  if (detail.isNotEmpty)
                    Text(detail, style: const TextStyle(color: Colors.white54, fontSize: 11)),
                ]),
              ),
            ]),
          );
        }),
        ...errors.map((e) {
          final checkId = (e['check_id'] as String?) ?? '';
          final errorType = (e['error_type'] as String?) ?? '';
          final message = (e['message'] as String?) ?? '';
          return Padding(
            padding: const EdgeInsets.only(bottom: 6),
            child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
              const Icon(Icons.error_outline, color: kRed, size: 14),
              const SizedBox(width: 8),
              Expanded(
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(checkId.isEmpty ? 'Connector error' : humanizeCheckId(checkId),
                      style: const TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.w500)),
                  Text('$errorType: $message', style: const TextStyle(color: kRed, fontSize: 11)),
                ]),
              ),
            ]),
          );
        }),
      ]),
    );
  }
}
