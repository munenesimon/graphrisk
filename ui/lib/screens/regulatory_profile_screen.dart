import 'package:flutter/material.dart';
import '../constants/colors.dart';
import '../constants/frameworks.dart';
import '../models/dashboard.dart';
import '../services/api_service.dart';
import '../widgets/motion.dart';

/// Lets an organisation declare which regulations it's legally subject to
/// (plus any qualifiers, e.g. "we're a payment service provider"). This is
/// deliberately explicit -- see organisation.py's module docstring: with
/// nothing set here, Blast Radius and Vulnerability Impact report no
/// regulatory obligations at all, rather than guessing.
class RegulatoryProfileScreen extends StatefulWidget {
  const RegulatoryProfileScreen({super.key});
  @override
  State<RegulatoryProfileScreen> createState() => _RegulatoryProfileScreenState();
}

class _RegulatoryProfileScreenState extends State<RegulatoryProfileScreen> {
  List<dynamic>? _allFrameworks; // raw framework rows from GET /frameworks/
  RegulatoryProfile? _profile;
  bool _loading = true;
  bool _saving = false;
  String? _error;
  String? _saveMessage;

  final Set<String> _selectedFrameworkIds = {};
  final Set<String> _selectedQualifiers = {};

  bool get _canEdit => ApiService.role == 'owner' || ApiService.role == 'admin';

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() { _loading = true; _error = null; });
    try {
      final frameworks = await ApiService.getFrameworks();
      final profile = await ApiService.getRegulatoryProfile();
      if (!mounted) return;
      setState(() {
        _allFrameworks = frameworks;
        _profile = profile;
        _selectedFrameworkIds
          ..clear()
          ..addAll(profile.frameworks.map((f) => f.id));
        _selectedQualifiers
          ..clear()
          ..addAll(profile.qualifiers);
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      if (e is AuthException) return;
      setState(() { _error = e.toString().replaceFirst('Exception: ', ''); _loading = false; });
    }
  }

  Future<void> _save() async {
    setState(() { _saving = true; _error = null; _saveMessage = null; });
    try {
      final updated = await ApiService.setRegulatoryProfile(
        _selectedFrameworkIds.toList(),
        _selectedQualifiers.toList(),
      );
      if (!mounted) return;
      setState(() {
        _profile = updated;
        _saving = false;
        _saveMessage = 'Saved. Blast Radius and Vulnerability Impact will reflect this immediately.';
      });
    } catch (e) {
      if (!mounted) return;
      if (e is AuthException) return;
      setState(() { _error = e.toString().replaceFirst('Exception: ', ''); _saving = false; });
    }
  }

  List<dynamic> get _regulationRows => (_allFrameworks ?? [])
      .where((f) => !kStandardFrameworkNames.contains(f['name']?.toString() ?? ''))
      .toList();

  List<dynamic> get _standardRows => (_allFrameworks ?? [])
      .where((f) => kStandardFrameworkNames.contains(f['name']?.toString() ?? ''))
      .toList();

  @override
  Widget build(BuildContext context) {
    if (_loading) return const PageSkeleton();

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const Text('Risk Appetite & Regulations',
            style: TextStyle(color: Colors.white, fontSize: 22, fontWeight: FontWeight.w700, letterSpacing: -0.3)),
        const SizedBox(height: 4),
        const Text(
          "How much risk your organisation accepts, which decides whether each risk's controls are "
          "adequate -- and which regulations you are subject to, which decides the notification "
          "clocks in Blast Radius and Vulnerability Impact. With no regulations set, GraphRisk "
          "reports none, rather than guessing.",
          style: TextStyle(color: Colors.white54, fontSize: 13, height: 1.5),
        ),
        const SizedBox(height: 24),

        _RiskAppetiteCard(canEdit: _canEdit && !ApiService.readOnly),
        const SizedBox(height: 16),

        if (!_canEdit) _RoleNotice(role: ApiService.role),

        if (_error != null) _MessageBanner(message: _error!, color: kRed, icon: Icons.error_outline),
        if (_saveMessage != null) _MessageBanner(message: _saveMessage!, color: kGreen, icon: Icons.check_circle_outline),

        _SectionCard(
          title: 'Regulations you may be subject to',
          subtitle: '${_selectedFrameworkIds.length} selected',
          color: kPurple,
          icon: Icons.gavel_outlined,
          child: _regulationRows.isEmpty
              ? const Padding(
                  padding: EdgeInsets.all(4),
                  child: Text('No regulatory frameworks are loaded in the graph yet.',
                      style: TextStyle(color: Colors.white38, fontSize: 12)),
                )
              : Column(
                  children: _regulationRows.map((f) {
                    final id = f['id']?.toString() ?? '';
                    final name = f['name']?.toString() ?? '';
                    final version = f['version']?.toString() ?? '';
                    final checked = _selectedFrameworkIds.contains(id);
                    return _CheckRow(
                      checked: checked,
                      enabled: _canEdit,
                      title: frameworkDisplayName(name),
                      subtitle: version.isEmpty ? null : 'v$version',
                      description: frameworkDescription(name),
                      onChanged: (v) => setState(() {
                        if (v) { _selectedFrameworkIds.add(id); } else { _selectedFrameworkIds.remove(id); }
                      }),
                    );
                  }).toList(),
                ),
        ),

        const SizedBox(height: 20),

        _SectionCard(
          title: 'Qualifiers',
          subtitle: 'Narrow specific duties',
          color: kOrange,
          icon: Icons.tune,
          child: (_profile?.availableQualifiers.isEmpty ?? true)
              ? const Padding(
                  padding: EdgeInsets.all(4),
                  child: Text('No qualifiers are defined server-side.',
                      style: TextStyle(color: Colors.white38, fontSize: 12)),
                )
              : Column(
                  children: _profile!.availableQualifiers.entries.map((e) {
                    final checked = _selectedQualifiers.contains(e.key);
                    return _CheckRow(
                      checked: checked,
                      enabled: _canEdit,
                      title: e.key.replaceAll('_', ' '),
                      description: e.value,
                      onChanged: (v) => setState(() {
                        if (v) { _selectedQualifiers.add(e.key); } else { _selectedQualifiers.remove(e.key); }
                      }),
                    );
                  }).toList(),
                ),
        ),

        const SizedBox(height: 20),

        _SectionCard(
          title: 'Standards (always evaluated)',
          subtitle: 'Not part of your regulatory profile',
          color: kAccent,
          icon: Icons.verified_outlined,
          child: _standardRows.isEmpty
              ? const Padding(
                  padding: EdgeInsets.all(4),
                  child: Text('No standard frameworks are loaded in the graph yet.',
                      style: TextStyle(color: Colors.white38, fontSize: 12)),
                )
              : Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: _standardRows.map((f) {
                    final name = f['name']?.toString() ?? '';
                    final version = f['version']?.toString() ?? '';
                    return Padding(
                      padding: const EdgeInsets.symmetric(vertical: 6),
                      child: Row(children: [
                        const Icon(Icons.circle, size: 6, color: Colors.white38),
                        const SizedBox(width: 10),
                        Expanded(
                          child: Text('${frameworkDisplayName(name)}${version.isEmpty ? '' : ' (v$version)'}',
                              style: const TextStyle(color: Colors.white70, fontSize: 13)),
                        ),
                      ]),
                    );
                  }).toList(),
                ),
        ),

        const SizedBox(height: 28),

        if (_canEdit)
          SizedBox(
            width: 200,
            height: 46,
            child: ElevatedButton.icon(
              onPressed: _saving ? null : _save,
              icon: _saving
                  ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                  : const Icon(Icons.save_outlined, size: 18),
              label: Text(_saving ? 'Saving...' : 'Save profile'),
              style: ElevatedButton.styleFrom(
                backgroundColor: kAccent,
                foregroundColor: Colors.white,
                disabledBackgroundColor: kAccent.withOpacity(0.5),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
              ),
            ),
          ),
      ]),
    );
  }
}

class _RoleNotice extends StatelessWidget {
  final String? role;
  const _RoleNotice({this.role});

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(14),
      margin: const EdgeInsets.only(bottom: 20),
      decoration: BoxDecoration(
        color: kSurface2.withOpacity(0.5),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Row(children: [
        const Icon(Icons.lock_outline, color: Colors.white38, size: 18),
        const SizedBox(width: 10),
        Expanded(
          child: Text(
            'Your role${role == null ? '' : ' ($role)'} can view this profile but only an owner or '
            'admin can change it.',
            style: const TextStyle(color: Colors.white54, fontSize: 12, height: 1.4),
          ),
        ),
      ]),
    );
  }
}

class _MessageBanner extends StatelessWidget {
  final String message;
  final Color color;
  final IconData icon;
  const _MessageBanner({required this.message, required this.color, required this.icon});

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(14),
      margin: const EdgeInsets.only(bottom: 20),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withOpacity(0.3)),
      ),
      child: Row(children: [
        Icon(icon, color: color, size: 18),
        const SizedBox(width: 10),
        Expanded(child: Text(message, style: TextStyle(color: color, fontSize: 12, height: 1.4))),
      ]),
    );
  }
}

class _SectionCard extends StatelessWidget {
  final String title;
  final String subtitle;
  final Color color;
  final IconData icon;
  final Widget child;
  const _SectionCard({
    required this.title, required this.subtitle, required this.color,
    required this.icon, required this.child,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      decoration: BoxDecoration(
        color: kSurface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withOpacity(0.25)),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            Container(
              width: 32, height: 32,
              decoration: BoxDecoration(color: color.withOpacity(0.12), borderRadius: BorderRadius.circular(8)),
              child: Icon(icon, color: color, size: 17),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(title, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600, fontSize: 13)),
                Text(subtitle, style: TextStyle(color: color.withOpacity(0.8), fontSize: 11)),
              ]),
            ),
          ]),
          const SizedBox(height: 14),
          child,
        ]),
      ),
    );
  }
}

class _CheckRow extends StatelessWidget {
  final bool checked;
  final bool enabled;
  final String title;
  final String? subtitle;
  final String description;
  final ValueChanged<bool> onChanged;
  const _CheckRow({
    required this.checked, required this.enabled, required this.title,
    this.subtitle, required this.description, required this.onChanged,
  });

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: enabled ? () => onChanged(!checked) : null,
      borderRadius: BorderRadius.circular(8),
      child: Container(
        margin: const EdgeInsets.only(bottom: 6),
        padding: const EdgeInsets.all(10),
        decoration: BoxDecoration(
          color: checked ? kAccent.withOpacity(0.08) : Colors.transparent,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: checked ? kAccent.withOpacity(0.35) : kSurface2),
        ),
        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Checkbox(
            value: checked,
            onChanged: enabled ? (v) => onChanged(v ?? false) : null,
            activeColor: kAccent,
            side: const BorderSide(color: Colors.white38),
          ),
          const SizedBox(width: 4),
          Expanded(
            child: Padding(
              padding: const EdgeInsets.only(top: 12),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Row(children: [
                  Expanded(
                    child: Text(title, style: const TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.w600)),
                  ),
                  if (subtitle != null)
                    Text(subtitle!, style: const TextStyle(color: Colors.white38, fontSize: 11)),
                ]),
                const SizedBox(height: 4),
                Text(description, style: const TextStyle(color: Colors.white54, fontSize: 12, height: 1.4)),
              ]),
            ),
          ),
        ]),
      ),
    );
  }
}


// ── Risk appetite ────────────────────────────────────────────────────────────
// Self-contained: loads and saves on its own, so it never interferes with
// the regulations form below.
class _RiskAppetiteCard extends StatefulWidget {
  final bool canEdit;
  const _RiskAppetiteCard({required this.canEdit});

  @override
  State<_RiskAppetiteCard> createState() => _RiskAppetiteCardState();
}

class _RiskAppetiteCardState extends State<_RiskAppetiteCard> {
  double? _value;
  double? _saved;
  bool _isDefault = true;
  double _max = 25;
  bool _saving = false;
  String? _message;
  bool _messageIsError = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final data = await ApiService.getRiskAppetite();
      if (!mounted) return;
      setState(() {
        _value = (data['risk_appetite'] as num?)?.toDouble() ?? 4;
        _saved = _value;
        _isDefault = data['is_default'] == true;
        _max = (data['max'] as num?)?.toDouble() ?? 25;
      });
    } catch (e) {
      if (!mounted || e is AuthException) return;
      setState(() { _message = e.toString().replaceFirst('Exception: ', ''); _messageIsError = true; });
    }
  }

  Future<void> _save() async {
    final v = _value;
    if (v == null) return;
    setState(() { _saving = true; _message = null; });
    try {
      final data = await ApiService.setRiskAppetite(v);
      if (!mounted) return;
      setState(() {
        _saved = (data['risk_appetite'] as num?)?.toDouble() ?? v;
        _value = _saved;
        _isDefault = false;
        _saving = false;
        _message = 'Saved. Every risk is now judged against an appetite of ${_fmt(_saved!)}.';
        _messageIsError = false;
      });
    } catch (e) {
      if (!mounted || e is AuthException) return;
      setState(() { _saving = false; _message = e.toString().replaceFirst('Exception: ', ''); _messageIsError = true; });
    }
  }

  static String _fmt(double v) => v == v.roundToDouble() ? v.toStringAsFixed(0) : v.toStringAsFixed(1);

  static (String, Color) _band(double v) {
    if (v <= 4) return ('Low', kGreen);
    if (v <= 9) return ('Moderate', kAccent);
    if (v <= 16) return ('High', kOrange);
    return ('Very high', kRed);
  }

  @override
  Widget build(BuildContext context) {
    final v = _value;
    final (band, bandColor) = _band(v ?? 4);
    return _SectionCard(
      title: 'Risk appetite',
      subtitle: v == null
          ? 'Loading...'
          : 'Accept residual risk up to ${_fmt(v)} of 25 · $band${_isDefault ? ' (default)' : ''}',
      color: bandColor,
      icon: Icons.tune,
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const Text(
          'The highest risk score (likelihood × impact after controls, 0-25) you are willing to '
          'accept. Each risk is then judged against it: Adequate, Relies on one control (fine '
          'today, but one control failing would push it over), or Not adequate, with what '
          'would close the gap.',
          style: TextStyle(color: Colors.white54, fontSize: 12, height: 1.5),
        ),
        if (v != null) ...[
          const SizedBox(height: 8),
          Row(children: [
            Expanded(
              child: Slider(
                value: v.clamp(0, _max).toDouble(),
                min: 0,
                max: _max,
                divisions: (_max * 2).round(),
                activeColor: bandColor,
                label: _fmt(v),
                onChanged: widget.canEdit ? (x) => setState(() { _value = x; _message = null; }) : null,
              ),
            ),
            SizedBox(
              width: 44,
              child: Text(_fmt(v), textAlign: TextAlign.right,
                  style: TextStyle(color: bandColor, fontSize: 18, fontWeight: FontWeight.bold)),
            ),
          ]),
          const Text('0-4 low · 5-9 moderate · 10-16 high · 17-25 very high',
              style: TextStyle(color: Colors.white38, fontSize: 11)),
        ],
        if (_message != null) ...[
          const SizedBox(height: 10),
          Text(_message!, style: TextStyle(color: _messageIsError ? kRed : kGreen, fontSize: 12)),
        ],
        if (widget.canEdit && v != null) ...[
          const SizedBox(height: 12),
          ElevatedButton(
            onPressed: _saving || v == _saved ? null : _save,
            style: ElevatedButton.styleFrom(
              backgroundColor: kAccent,
              foregroundColor: Colors.white,
              disabledBackgroundColor: kAccent.withOpacity(0.3),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
            ),
            child: Text(_saving ? 'Saving...' : 'Save appetite'),
          ),
        ] else if (!widget.canEdit) ...[
          const SizedBox(height: 8),
          const Text('Only an owner or admin can change this.',
              style: TextStyle(color: Colors.white38, fontSize: 11)),
        ],
      ]),
    );
  }
}
