import 'package:flutter/material.dart';
import '../constants/colors.dart';
import '../constants/frameworks.dart';
import '../services/api_service.dart';
import '../widgets/adherence.dart';
import '../widgets/motion.dart';

/// Every requirement in one framework with its evidence: the controls
/// linked to it and how well they're working, or what the organisation has
/// recorded itself. Requirements no connector can measure (a policy, a
/// plan, training) can be marked in place or not applicable here --
/// always shown as self-declared, never as measured.
class FrameworkDetailScreen extends StatefulWidget {
  final String frameworkId;
  final String frameworkName;
  const FrameworkDetailScreen({super.key, required this.frameworkId, required this.frameworkName});

  @override
  State<FrameworkDetailScreen> createState() => _FrameworkDetailScreenState();
}

class _FrameworkDetailScreenState extends State<FrameworkDetailScreen> {
  Map<String, dynamic>? _data;
  bool _loading = true;
  String? _error;
  RequirementStatus? _filter; // null = all

  @override
  void initState() { super.initState(); _load(); }

  // The router can reuse this screen for a different framework (going
  // straight from one framework's page to another's). Start again for the
  // new one, so the old framework's requirements never show under the new
  // name.
  @override
  void didUpdateWidget(covariant FrameworkDetailScreen oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.frameworkId != widget.frameworkId) {
      setState(() { _data = null; _filter = null; });
      _load();
    }
  }

  Future<void> _load() async {
    final requestedId = widget.frameworkId;
    if (_data == null) setState(() { _loading = true; _error = null; });
    try {
      final data = await ApiService.getFrameworkRequirements(requestedId);
      // Drop a reply for a framework we've since navigated away from.
      if (!mounted || requestedId != widget.frameworkId) return;
      setState(() { _data = data; _loading = false; _error = null; });
    } catch (e) {
      if (!mounted || requestedId != widget.frameworkId) return;
      if (e is AuthException) return;
      setState(() { _error = e.toString().replaceFirst('Exception: ', ''); _loading = false; });
    }
  }

  bool get _canAttest => (_data?['can_attest'] == true) && !ApiService.readOnly;

  Future<void> _attest(Map<String, dynamic> req, String status) async {
    final existing = req['attestation'] as Map<String, dynamic>?;
    final result = await showDialog<_AttestationInput>(
      context: context,
      builder: (_) => _AttestationDialog(
        requirement: req,
        status: status,
        note: existing?['note']?.toString(),
        evidenceUrl: existing?['evidence_url']?.toString(),
      ),
    );
    if (result == null) return;
    try {
      await ApiService.setAttestation(widget.frameworkId, req['id'].toString(), status,
          note: result.note, evidenceUrl: result.evidenceUrl);
      await _load();
    } catch (e) {
      if (e is AuthException || !mounted) return;
      _toast(e.toString().replaceFirst('Exception: ', ''));
    }
  }

  Future<void> _removeAttestation(Map<String, dynamic> req) async {
    try {
      await ApiService.deleteAttestation(widget.frameworkId, req['id'].toString());
      await _load();
    } catch (e) {
      if (e is AuthException || !mounted) return;
      _toast(e.toString().replaceFirst('Exception: ', ''));
    }
  }

  void _toast(String message) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message)));
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
    final data = _data!;
    final reqs = (data['requirements'] as List? ?? []).cast<Map<String, dynamic>>();
    final pct = (data['adherence_pct'] as num?)?.toDouble();
    final evidenced = (data['evidenced'] as num?)?.toInt() ?? 0;
    final applicable = (data['applicable'] as num?)?.toInt() ?? 0;
    final applies = data['applies'] == true;
    final thin = evidenceIsThin(data);
    final notice = kFrameworkNotices[data['framework']?.toString() ?? ''];
    final shown = _filter == null ? reqs : reqs.where((r) => r['status'] == _filter!.key).toList();

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
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Row(children: [
                Expanded(
                  child: Text(
                    applies ? 'One of your obligations' : 'Not in your regulatory profile -- shown for reference',
                    style: TextStyle(color: applies ? kAccent : Colors.white54, fontSize: 12,
                        fontWeight: FontWeight.w600),
                  ),
                ),
                Text(pct == null ? '—' : '${pct.toStringAsFixed(1)}% met',
                    style: TextStyle(color: thin ? Colors.white54 : adherenceColor(pct),
                        fontWeight: FontWeight.bold, fontSize: 20)),
              ]),
              const SizedBox(height: 6),
              Text('Evidence for $evidenced of $applicable requirements · ${adherenceBreakdown(data)}',
                  style: const TextStyle(color: Colors.white70, fontSize: 13)),
              if (thin && applicable > 0) ...[
                const SizedBox(height: 2),
                const Text(kThinEvidenceNote,
                    style: TextStyle(color: Colors.white38, fontSize: 12, fontStyle: FontStyle.italic)),
              ],
              const SizedBox(height: 10),
              AdherenceBar(framework: data, height: 10),
              const SizedBox(height: 10),
              const Text(
                '"No evidence yet" means no connector measures this requirement and nothing has been '
                'recorded for it -- not that it has failed. Policies, plans and training can be '
                'recorded below; they show as self-declared.',
                style: TextStyle(color: Colors.white38, fontSize: 11),
              ),
            ]),
          ),
          if (notice != null) ...[
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: kAccent.withOpacity(0.08), borderRadius: BorderRadius.circular(10),
                border: Border.all(color: kAccent.withOpacity(0.25)),
              ),
              child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                const Icon(Icons.info_outline, color: kAccent, size: 18),
                const SizedBox(width: 10),
                Expanded(child: Text(notice, style: const TextStyle(color: Colors.white70, fontSize: 12))),
              ]),
            ),
          ],
          const SizedBox(height: 20),

          Wrap(spacing: 8, runSpacing: 8, children: [
            _FilterChip(label: 'All (${reqs.length})', selected: _filter == null,
                onTap: () => setState(() => _filter = null)),
            for (final s in RequirementStatus.all)
              if ((data[s.key] as num? ?? 0) > 0)
                _FilterChip(
                  label: '${s.label} (${data[s.key]})',
                  selected: _filter == s,
                  color: s == RequirementStatus.noEvidence ? Colors.white70 : s.color,
                  onTap: () => setState(() => _filter = s),
                ),
          ]),
          const SizedBox(height: 20),

          if (shown.isEmpty)
            const Padding(
              padding: EdgeInsets.all(4),
              child: Text('No requirements match this filter.', style: TextStyle(color: Colors.white38, fontSize: 13)),
            )
          else
            ...shown.map((r) => _RequirementRow(
                  requirement: r,
                  canAttest: _canAttest,
                  onAttest: (status) => _attest(r, status),
                  onRemove: () => _removeAttestation(r),
                )),
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

class _RequirementRow extends StatelessWidget {
  final Map<String, dynamic> requirement;
  final bool canAttest;
  final void Function(String status) onAttest;
  final VoidCallback onRemove;
  const _RequirementRow({required this.requirement, required this.canAttest,
      required this.onAttest, required this.onRemove});

  String _evidenceLine(RequirementStatus s, List<Map<String, dynamic>> controls, Map<String, dynamic>? att) {
    if (controls.isNotEmpty) {
      final parts = controls.map((c) {
        final health = ((c['health'] as num?)?.toDouble() ?? 0) * 100;
        final via = c['via'] == 'crosswalk' ? ', via crosswalk' : '';
        return '${c['title']} (${health.round()}% health$via)';
      });
      return 'Measured: ${parts.join(', ')}';
    }
    if (s == RequirementStatus.attested) return 'Recorded as in place (self-declared)';
    if (s == RequirementStatus.notApplicable) return 'Recorded as not applicable';
    return 'No connector measures this, and nothing has been recorded';
  }

  @override
  Widget build(BuildContext context) {
    final s = RequirementStatus.of(requirement['status']?.toString());
    final controls = (requirement['controls'] as List? ?? []).cast<Map<String, dynamic>>();
    final att = requirement['attestation'] as Map<String, dynamic>?;
    final note = att?['note']?.toString();
    final link = att?['evidence_url']?.toString();
    final measured = controls.isNotEmpty;

    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: kSurface,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: s.color.withOpacity(0.25)),
      ),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Icon(s.icon, color: s.color, size: 20),
        const SizedBox(width: 12),
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Wrap(spacing: 8, runSpacing: 4, crossAxisAlignment: WrapCrossAlignment.center, children: [
              Text(requirement['control_reference']?.toString() ?? '',
                  style: const TextStyle(color: Colors.white54, fontSize: 11, fontWeight: FontWeight.bold)),
              _Pill(text: s.label, color: s.color),
              if ((requirement['domain'] ?? '').toString().isNotEmpty)
                _Pill(text: requirement['domain'].toString(), color: Colors.white54),
            ]),
            const SizedBox(height: 4),
            Text(requirement['title']?.toString() ?? '',
                style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600, fontSize: 13)),
            if ((requirement['summary'] ?? '').toString().isNotEmpty) ...[
              const SizedBox(height: 4),
              Text(requirement['summary'].toString(),
                  style: const TextStyle(color: Colors.white38, fontSize: 12), maxLines: 2, overflow: TextOverflow.ellipsis),
            ],
            const SizedBox(height: 6),
            Text(_evidenceLine(s, controls, att),
                style: TextStyle(color: s == RequirementStatus.noEvidence ? Colors.white54 : s.color,
                    fontSize: 11, fontWeight: FontWeight.w600)),
            if (note != null && note.isNotEmpty) ...[
              const SizedBox(height: 4),
              Text('Note: $note', style: const TextStyle(color: Colors.white54, fontSize: 11)),
            ],
            if (link != null && link.isNotEmpty) ...[
              const SizedBox(height: 2),
              SelectableText('Evidence: $link', style: const TextStyle(color: kAccent, fontSize: 11)),
            ],
            if (canAttest) ...[
              const SizedBox(height: 8),
              Wrap(spacing: 8, children: [
                // A measured requirement is judged by its controls; it can
                // still be ruled out as not applicable.
                if (!measured && s != RequirementStatus.attested)
                  _ActionButton(label: 'Mark as in place', onTap: () => onAttest('in_place')),
                if (s == RequirementStatus.attested)
                  _ActionButton(label: 'Edit record', onTap: () => onAttest('in_place')),
                if (s != RequirementStatus.notApplicable)
                  _ActionButton(label: 'Not applicable', onTap: () => onAttest('not_applicable')),
                if (att != null)
                  _ActionButton(label: 'Remove record', onTap: onRemove, color: kRed),
              ]),
            ],
          ]),
        ),
      ]),
    );
  }
}

class _Pill extends StatelessWidget {
  final String text;
  final Color color;
  const _Pill({required this.text, required this.color});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(color: color.withOpacity(0.12), borderRadius: BorderRadius.circular(10)),
      child: Text(text, style: TextStyle(color: color, fontSize: 10, fontWeight: FontWeight.w600)),
    );
  }
}

class _ActionButton extends StatelessWidget {
  final String label;
  final VoidCallback onTap;
  final Color color;
  const _ActionButton({required this.label, required this.onTap, this.color = kAccent});

  @override
  Widget build(BuildContext context) {
    return TextButton(
      onPressed: onTap,
      style: TextButton.styleFrom(
        foregroundColor: color,
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
        minimumSize: const Size(0, 30),
        textStyle: const TextStyle(fontSize: 12, fontWeight: FontWeight.w600),
      ),
      child: Text(label),
    );
  }
}

class _AttestationInput {
  final String? note;
  final String? evidenceUrl;
  const _AttestationInput(this.note, this.evidenceUrl);
}

class _AttestationDialog extends StatefulWidget {
  final Map<String, dynamic> requirement;
  final String status;
  final String? note;
  final String? evidenceUrl;
  const _AttestationDialog({required this.requirement, required this.status, this.note, this.evidenceUrl});

  @override
  State<_AttestationDialog> createState() => _AttestationDialogState();
}

class _AttestationDialogState extends State<_AttestationDialog> {
  late final TextEditingController _note = TextEditingController(text: widget.note ?? '');
  late final TextEditingController _link = TextEditingController(text: widget.evidenceUrl ?? '');
  String? _linkError;

  @override
  void dispose() { _note.dispose(); _link.dispose(); super.dispose(); }

  void _save() {
    final link = _link.text.trim();
    if (link.isNotEmpty && !(link.startsWith('https://') || link.startsWith('http://'))) {
      setState(() => _linkError = 'Use a full link starting with https://');
      return;
    }
    Navigator.of(context).pop(_AttestationInput(_note.text, link));
  }

  @override
  Widget build(BuildContext context) {
    final inPlace = widget.status == 'in_place';
    final ref = widget.requirement['control_reference']?.toString() ?? '';
    final title = widget.requirement['title']?.toString() ?? '';
    return AlertDialog(
      backgroundColor: kSurface,
      title: Text(inPlace ? 'Record as in place' : 'Record as not applicable',
          style: const TextStyle(color: Colors.white, fontSize: 17)),
      content: SizedBox(
        width: 460,
        child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('$ref  $title', style: const TextStyle(color: Colors.white70, fontSize: 13)),
          const SizedBox(height: 12),
          Text(
            inPlace
                ? 'This is shown as self-declared, separately from what connectors measure. '
                    'Say what is in place and, ideally, link to the document.'
                : 'This requirement will be left out of the totals. Say why it does not apply.',
            style: const TextStyle(color: Colors.white54, fontSize: 12),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _note,
            maxLines: 3,
            maxLength: 2000,
            style: const TextStyle(color: Colors.white, fontSize: 13),
            decoration: InputDecoration(
              labelText: inPlace ? 'What is in place' : 'Why it does not apply',
              labelStyle: const TextStyle(color: Colors.white54),
              border: const OutlineInputBorder(),
            ),
          ),
          if (inPlace) ...[
            const SizedBox(height: 8),
            TextField(
              controller: _link,
              style: const TextStyle(color: Colors.white, fontSize: 13),
              decoration: InputDecoration(
                labelText: 'Evidence link (optional)',
                hintText: 'https://...',
                errorText: _linkError,
                labelStyle: const TextStyle(color: Colors.white54),
                border: const OutlineInputBorder(),
              ),
            ),
          ],
        ]),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.of(context).pop(), child: const Text('Cancel')),
        FilledButton(onPressed: _save, child: const Text('Save')),
      ],
    );
  }
}
