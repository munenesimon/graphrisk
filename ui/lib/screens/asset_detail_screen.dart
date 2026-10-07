import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:url_launcher/url_launcher.dart';
import '../constants/colors.dart';
import '../models/asset_profile.dart';
import '../services/api_service.dart';

/// One asset, in as much detail as its connectors can provide.
///
/// Nothing here knows about any particular vendor: the API returns the
/// universal device profile (identity, health, OS, hardware, network,
/// software, vulnerabilities, configuration, protection, ownership, cloud,
/// activity), already merged across every connector that reports on this
/// device. Each section shows which connector it came from, sections no
/// connector filled are left out, and anything a connector reported that
/// isn't part of the schema appears under "Other details".
class AssetDetailScreen extends StatefulWidget {
  final String assetId;
  final String assetName;
  const AssetDetailScreen({super.key, required this.assetId, required this.assetName});

  @override
  State<AssetDetailScreen> createState() => _AssetDetailScreenState();
}

class _AssetDetailScreenState extends State<AssetDetailScreen> {
  AssetProfile? _profile;
  String? _error;
  bool _loading = true;
  bool _showAllVulns = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() { _loading = true; _error = null; });
    try {
      final p = await ApiService.getAssetProfile(widget.assetId);
      if (!mounted) return;
      setState(() { _profile = p; _loading = false; });
    } catch (e) {
      if (!mounted) return;
      if (e is AuthException) return;
      setState(() { _error = e.toString().replaceFirst('Exception: ', ''); _loading = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        TextButton.icon(
          onPressed: () => context.go('/assets'),
          icon: const Icon(Icons.arrow_back, size: 16, color: Colors.white54),
          label: const Text('Assets', style: TextStyle(color: Colors.white54)),
        ),
        const SizedBox(height: 8),
        if (_loading)
          const Padding(
            padding: EdgeInsets.all(40),
            child: Center(child: CircularProgressIndicator(color: kAccent)),
          )
        else if (_error != null)
          Text('Error: $_error', style: const TextStyle(color: kRed))
        else
          ..._content(_profile!),
      ]),
    );
  }

  List<Widget> _content(AssetProfile p) {
    final a = p.asset;
    final name = a['name']?.toString() ?? widget.assetName;
    final health = p.sections['health']?.fields ?? const <String, dynamic>{};
    final status = health['status']?.toString();
    final lastSeen = health['last_seen']?.toString();
    final allSources = <String>{
      for (final s in p.sections.values) ...s.sources.map((x) => x.name),
    }.toList()
      ..sort();

    final widgets = <Widget>[
      // ── Header ──
      Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(name,
                style: const TextStyle(color: Colors.white, fontSize: 22, fontWeight: FontWeight.w700)),
            const SizedBox(height: 4),
            Text(
              [a['asset_type'], a['criticality'], a['environment']]
                  .where((s) => s != null && s.toString().isNotEmpty)
                  .join(' · '),
              style: const TextStyle(color: Colors.white54, fontSize: 13),
            ),
            if (lastSeen != null) ...[
              const SizedBox(height: 4),
              Text('Last seen ${_fmtTime(lastSeen)}',
                  style: const TextStyle(color: Colors.white38, fontSize: 12)),
            ],
          ]),
        ),
        if (status != null && status.isNotEmpty) _StatusBadge(status: status),
      ]),
      const SizedBox(height: 10),
      Wrap(spacing: 6, runSpacing: 6, children: [
        if (allSources.isEmpty)
          const _Chip(text: 'No connector reports on this asset yet', color: Colors.white38)
        else
          for (final s in allSources) _Chip(text: 'From $s', color: kAccent),
        if (a['holds_personal_data'] == true) const _Chip(text: 'Holds personal data', color: kOrange),
      ]),
      if (p.alsoKnownAs.isNotEmpty) ...[
        const SizedBox(height: 12),
        _Note(
          icon: Icons.merge_type,
          text: 'Also reported as ${p.alsoKnownAs.join('; ')}. '
              'These records were merged because they share a hardware identifier.',
        ),
      ],
      if (p.possibleDuplicates.isNotEmpty) ...[
        const SizedBox(height: 12),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: kOrange.withOpacity(0.08),
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: kOrange.withOpacity(0.3)),
          ),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            const Text('Possibly the same device',
                style: TextStyle(color: kOrange, fontSize: 12, fontWeight: FontWeight.w700)),
            const SizedBox(height: 4),
            const Text(
              'These assets share a hostname but no serial number, MAC address or cloud instance id, '
              'so they were not merged automatically.',
              style: TextStyle(color: Colors.white54, fontSize: 12, height: 1.4),
            ),
            const SizedBox(height: 6),
            Wrap(spacing: 8, runSpacing: 6, children: [
              for (final d in p.possibleDuplicates)
                ActionChip(
                  backgroundColor: kSurface2,
                  label: Text(d['name']?.toString() ?? 'Asset',
                      style: const TextStyle(color: Colors.white, fontSize: 12)),
                  onPressed: () => context.go(
                      '/assets/${d['id']}?name=${Uri.encodeQueryComponent(d['name']?.toString() ?? '')}'),
                ),
            ]),
          ]),
        ),
      ],
      if (p.hiddenFields.isNotEmpty) ...[
        const SizedBox(height: 12),
        _Note(
          icon: Icons.lock_outline,
          text: 'Some details (${p.hiddenFields.map(_label).join(', ')}) are visible to owners and admins only.',
        ),
      ],
      const SizedBox(height: 20),
    ];

    // ── Fix first ──
    if (p.fixFirst.isNotEmpty) {
      widgets.add(_Card(
        title: 'Fix first',
        subtitle: 'Vulnerable software on this device, most urgent first',
        icon: Icons.build_circle_outlined,
        color: kRed,
        child: Column(children: [for (final pkg in p.fixFirst) _PackageRow(pkg: pkg)]),
      ));
    }

    // ── Profile sections, in a fixed order ──
    for (final key in _sectionOrder) {
      final section = p.sections[key];
      if (section == null) continue;
      final rows = _fieldRows(key, section);
      if (rows.isEmpty) continue;
      widgets.add(_Card(
        title: _sectionTitles[key] ?? key,
        subtitle: _sourceLine(section),
        icon: _sectionIcons[key] ?? Icons.info_outline,
        color: kAccent,
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: rows),
      ));
    }

    // ── Linked vulnerabilities ──
    if (p.vulnerabilities.isNotEmpty) {
      final shown = _showAllVulns ? p.vulnerabilities : p.vulnerabilities.take(8).toList();
      widgets.add(_Card(
        title: 'Linked vulnerabilities',
        subtitle: '${p.vulnerabilityTotal} CVE${p.vulnerabilityTotal == 1 ? '' : 's'} linked to this asset',
        icon: Icons.bug_report_outlined,
        color: kOrange,
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          for (final v in shown) _CveRow(cve: v),
          if (p.vulnerabilities.length > 8)
            TextButton(
              onPressed: () => setState(() => _showAllVulns = !_showAllVulns),
              child: Text(_showAllVulns ? 'Show fewer' : 'Show all ${p.vulnerabilities.length}'),
            ),
          if (p.vulnerabilityTotal > p.vulnerabilities.length)
            Text('Showing the ${p.vulnerabilities.length} most urgent.',
                style: const TextStyle(color: Colors.white38, fontSize: 11)),
        ]),
      ));
    }

    // ── Risks ──
    if (p.risks.isNotEmpty) {
      widgets.add(_Card(
        title: 'Risks',
        subtitle: 'Risks this asset is linked to, and the controls covering them',
        icon: Icons.warning_amber_rounded,
        color: kRed,
        child: Column(children: [for (final r in p.risks) _RiskRow(risk: r)]),
      ));
    }

    // ── What else a connector could add ──
    final missing = <String, List<String>>{};
    for (final key in _sectionOrder) {
      if (key == 'extra' || p.sections.containsKey(key)) continue;
      final providers = p.capabilities[key] ?? const <String>[];
      if (providers.isNotEmpty) missing[key] = providers;
    }
    if (missing.isNotEmpty) {
      widgets.add(_Card(
        title: 'Not reported yet',
        subtitle: 'Details a connector could add for this asset',
        icon: Icons.add_link,
        color: Colors.white38,
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          for (final e in missing.entries)
            Padding(
              padding: const EdgeInsets.only(bottom: 4),
              child: Text('${_sectionTitles[e.key] ?? e.key}: from ${e.value.join(', ')}',
                  style: const TextStyle(color: Colors.white54, fontSize: 12)),
            ),
        ]),
      ));
    }

    return widgets;
  }

  String _sourceLine(ProfileSection s) {
    if (s.sources.isEmpty) return '';
    return s.sources
        .map((x) => x.collectedAt == null ? 'From ${x.name}' : 'From ${x.name} · ${_fmtTime(x.collectedAt!)}')
        .join('   ');
  }

  List<Widget> _fieldRows(String section, ProfileSection s) {
    final rows = <Widget>[];
    for (final entry in s.fields.entries) {
      final field = entry.key;
      final value = entry.value;
      // Shown in the "Fix first" card instead.
      if (section == 'software' && field == 'vulnerable_packages') continue;
      if (section == 'configuration' && field == 'benchmarks' && value is List) {
        for (final b in value) {
          if (b is Map) rows.add(_BenchmarkTile(benchmark: b.cast<String, dynamic>()));
        }
        continue;
      }
      if (section == 'network' && field == 'listening_ports' && value is List) {
        rows.add(_FieldRow(
          label: 'Listening ports',
          value: value.whereType<Map>().map((p) {
            final proto = p['protocol'] == null ? '' : '/${p['protocol']}';
            final proc = p['process'] == null ? '' : ' (${p['process']})';
            return '${p['port']}$proto$proc';
          }).join(', '),
        ));
        continue;
      }
      final label = section == 'extra' ? field : _label('$section.$field');
      rows.add(_FieldRow(label: label, value: _fmtValue(field, value)));
    }
    return rows;
  }
}

// ── Labels and formatting ────────────────────────────────────────────────────

const _sectionOrder = <String>[
  'identity', 'health', 'os', 'hardware', 'network', 'software',
  'vulnerabilities', 'configuration', 'protection', 'ownership', 'cloud',
  'activity', 'extra',
];

const _sectionTitles = <String, String>{
  'identity': 'Identity',
  'health': 'Health',
  'os': 'Operating system',
  'hardware': 'Hardware',
  'network': 'Network',
  'software': 'Software',
  'vulnerabilities': 'Vulnerability scan',
  'configuration': 'Configuration',
  'protection': 'Endpoint protection',
  'ownership': 'Ownership',
  'cloud': 'Cloud',
  'activity': 'Activity',
  'extra': 'Other details',
};

const _sectionIcons = <String, IconData>{
  'identity': Icons.badge_outlined,
  'health': Icons.monitor_heart_outlined,
  'os': Icons.computer,
  'hardware': Icons.memory,
  'network': Icons.lan_outlined,
  'software': Icons.apps,
  'vulnerabilities': Icons.bug_report_outlined,
  'configuration': Icons.rule,
  'protection': Icons.shield_outlined,
  'ownership': Icons.person_outline,
  'cloud': Icons.cloud_outlined,
  'activity': Icons.timeline,
  'extra': Icons.more_horiz,
};

const _fieldLabels = <String, String>{
  'identity.hostname': 'Hostname',
  'identity.device_type': 'Device type',
  'identity.manufacturer': 'Manufacturer',
  'identity.model': 'Model',
  'identity.serial_number': 'Serial number',
  'identity.agent_id': 'Agent ID',
  'identity.cloud_instance_id': 'Cloud instance ID',
  'identity.groups': 'Groups',
  'health.status': 'Status',
  'health.last_seen': 'Last seen',
  'health.enrolled_at': 'Enrolled',
  'health.agent_version': 'Agent version',
  'os.name': 'Name',
  'os.version': 'Version',
  'os.platform': 'Platform',
  'os.architecture': 'Architecture',
  'os.kernel': 'Kernel / release',
  'os.build': 'Build',
  'hardware.cpu': 'CPU',
  'hardware.cpu_cores': 'CPU cores',
  'hardware.memory_total_mb': 'Memory',
  'hardware.memory_used_percent': 'Memory in use',
  'network.ip_addresses': 'IP addresses',
  'network.mac_addresses': 'MAC addresses',
  'network.public_ip': 'Public IP',
  'software.installed_count': 'Installed packages',
  'software.hotfixes_count': 'Updates installed',
  'software.recent_hotfixes': 'Recent updates',
  'vulnerabilities.counts_by_severity': 'Findings by severity',
  'vulnerabilities.total': 'Total findings',
  'vulnerabilities.scanner': 'Scanner',
  'protection.status': 'Status',
  'protection.product': 'Product',
  'protection.policy': 'Policy',
  'protection.last_detection': 'Last detection',
  'protection.detections_count': 'Detections',
  'ownership.assigned_user': 'Assigned user',
  'ownership.owner_email': 'Owner email',
  'ownership.department': 'Department',
  'ownership.managed': 'Managed',
  'ownership.compliant': 'Compliant',
  'cloud.provider': 'Provider',
  'cloud.region': 'Region',
  'cloud.account': 'Account',
  'cloud.instance_type': 'Instance type',
  'cloud.security_groups': 'Security groups',
  'cloud.public_exposure': 'Publicly exposed',
  'cloud.tags': 'Tags',
  'activity.alerts_by_level': 'Alerts by level',
  'activity.recent_alerts': 'Recent alerts',
  'activity.window': 'Period',
};

String _label(String key) {
  final known = _fieldLabels[key];
  if (known != null) return known;
  final field = key.contains('.') ? key.split('.').last : key;
  final words = field.replaceAll('_', ' ');
  return words.isEmpty ? key : words[0].toUpperCase() + words.substring(1);
}

String _fmtValue(String field, dynamic v) {
  if (v == null) return '—';
  if (v is bool) return v ? 'Yes' : 'No';
  if (field == 'memory_total_mb' && v is num) {
    return v >= 1024 ? '${(v / 1024).toStringAsFixed(1)} GB' : '$v MB';
  }
  if (field == 'memory_used_percent' && v is num) return '$v%';
  if (field.endsWith('_at') || field == 'last_seen' || field == 'last_detection') {
    return _fmtTime(v.toString());
  }
  if (v is List) {
    return v.map((e) => e is Map ? e.values.join(' ') : e.toString()).join(', ');
  }
  if (v is Map) return v.entries.map((e) => '${e.key}: ${e.value}').join(' · ');
  return v.toString();
}

String _two(int n) => n.toString().padLeft(2, '0');

/// "2026-10-05 13:49 (12 min ago)" in the viewer's local time; the raw
/// string if it isn't a timestamp.
String _fmtTime(String raw) {
  final t = DateTime.tryParse(raw);
  if (t == null) return raw;
  final local = t.toLocal();
  final abs = '${local.year}-${_two(local.month)}-${_two(local.day)} ${_two(local.hour)}:${_two(local.minute)}';
  final diff = DateTime.now().difference(local);
  String ago;
  if (diff.isNegative || diff.inMinutes < 1) {
    ago = 'just now';
  } else if (diff.inMinutes < 60) {
    ago = '${diff.inMinutes} min ago';
  } else if (diff.inHours < 48) {
    ago = '${diff.inHours} h ago';
  } else {
    ago = '${diff.inDays} days ago';
  }
  return '$abs ($ago)';
}

Color _severityColor(String? s) {
  switch (s) {
    case 'Critical':
      return kRed;
    case 'High':
      return kOrange;
    case 'Medium':
      return kAccent;
    default:
      return Colors.white54;
  }
}

Future<void> _openNvd(String cveId) async {
  final uri = Uri.parse('https://nvd.nist.gov/vuln/detail/$cveId');
  if (await canLaunchUrl(uri)) {
    await launchUrl(uri, mode: LaunchMode.externalApplication);
  }
}

// ── Building blocks ──────────────────────────────────────────────────────────

class _Card extends StatelessWidget {
  final String title;
  final String subtitle;
  final IconData icon;
  final Color color;
  final Widget child;
  const _Card({required this.title, required this.subtitle, required this.icon, required this.color, required this.child});

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      margin: const EdgeInsets.only(bottom: 14),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: kSurface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.white.withOpacity(0.06)),
      ),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(children: [
          Icon(icon, color: color, size: 18),
          const SizedBox(width: 8),
          Text(title, style: const TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.w700)),
        ]),
        if (subtitle.isNotEmpty) ...[
          const SizedBox(height: 2),
          Padding(
            padding: const EdgeInsets.only(left: 26),
            child: Text(subtitle, style: const TextStyle(color: Colors.white38, fontSize: 11)),
          ),
        ],
        const SizedBox(height: 12),
        child,
      ]),
    );
  }
}

class _FieldRow extends StatelessWidget {
  final String label;
  final String value;
  const _FieldRow({required this.label, required this.value});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        SizedBox(
          width: 160,
          child: Text(label, style: const TextStyle(color: Colors.white54, fontSize: 12)),
        ),
        Expanded(
          child: SelectableText(value, style: const TextStyle(color: Colors.white, fontSize: 12)),
        ),
      ]),
    );
  }
}

class _Chip extends StatelessWidget {
  final String text;
  final Color color;
  const _Chip({required this.text, required this.color});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: color.withOpacity(0.12),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withOpacity(0.35)),
      ),
      child: Text(text, style: TextStyle(color: color, fontSize: 11, fontWeight: FontWeight.w600)),
    );
  }
}

class _Note extends StatelessWidget {
  final IconData icon;
  final String text;
  const _Note({required this.icon, required this.text});

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(color: kSurface2.withOpacity(0.5), borderRadius: BorderRadius.circular(10)),
      child: Row(children: [
        Icon(icon, color: Colors.white38, size: 16),
        const SizedBox(width: 8),
        Expanded(child: Text(text, style: const TextStyle(color: Colors.white54, fontSize: 12, height: 1.4))),
      ]),
    );
  }
}

class _StatusBadge extends StatelessWidget {
  final String status;
  const _StatusBadge({required this.status});

  @override
  Widget build(BuildContext context) {
    final s = status.toLowerCase();
    final Color color = (s == 'online' || s == 'active' || s == 'running')
        ? kGreen
        : ((s == 'offline' || s == 'disconnected' || s == 'stopped') ? kRed : Colors.white54);
    return _Chip(text: status[0].toUpperCase() + status.substring(1), color: color);
  }
}

class _PackageRow extends StatelessWidget {
  final VulnerablePackage pkg;
  const _PackageRow({required this.pkg});

  @override
  Widget build(BuildContext context) {
    final version = pkg.version ?? '';
    final title = version.isEmpty ? pkg.name : '${pkg.name} $version';
    final Color accent = pkg.ransomware ? kRed : Colors.white24;
    return Container(
      width: double.infinity,
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: (pkg.ransomware ? kRed : kSurface2).withOpacity(0.12),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: accent.withOpacity(0.4)),
      ),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(children: [
          Expanded(
            child: Text(title,
                style: const TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.w700)),
          ),
          if (pkg.ransomware) const _Chip(text: 'Used in ransomware', color: kRed),
        ]),
        const SizedBox(height: 4),
        Text(
          '${pkg.cveCount} CVE${pkg.cveCount == 1 ? '' : 's'}'
          '${pkg.maxSeverity == null ? '' : ' · worst: ${pkg.maxSeverity}'}'
          ' · Update or remove ${pkg.name} to clear ${pkg.cveCount == 1 ? 'it' : 'them'}.',
          style: const TextStyle(color: Colors.white60, fontSize: 12),
        ),
        const SizedBox(height: 6),
        for (final c in pkg.cves) _CveRow(cve: c),
      ]),
    );
  }
}

class _CveRow extends StatelessWidget {
  final Map<String, dynamic> cve;
  const _CveRow({required this.cve});

  @override
  Widget build(BuildContext context) {
    final id = cve['cve_id']?.toString() ?? '';
    final severity = cve['severity']?.toString();
    final cvss = cve['cvss_score'] is num ? (cve['cvss_score'] as num).toDouble() : 0.0;
    final ransomware = cve['ransomware'] == true;
    final parts = <String>[
      if (severity != null) severity,
      if (cvss > 0) 'CVSS ${cvss.toStringAsFixed(1)}',
    ];
    return InkWell(
      onTap: id.isEmpty ? null : () => _openNvd(id),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 3),
        child: Row(children: [
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
            decoration: BoxDecoration(color: kSurface2, borderRadius: BorderRadius.circular(4)),
            child: Text(id,
                style: const TextStyle(
                    color: Colors.white, fontSize: 11, fontFamily: 'monospace', fontWeight: FontWeight.bold)),
          ),
          const SizedBox(width: 8),
          Text(parts.join(' · '),
              style: TextStyle(color: _severityColor(severity), fontSize: 11, fontWeight: FontWeight.w600)),
          if (ransomware) ...[
            const SizedBox(width: 8),
            const Text('Known ransomware use',
                style: TextStyle(color: kRed, fontSize: 10, fontWeight: FontWeight.w700)),
          ],
          const Spacer(),
          const Icon(Icons.open_in_new, color: Colors.white24, size: 13),
        ]),
      ),
    );
  }
}

class _BenchmarkTile extends StatelessWidget {
  final Map<String, dynamic> benchmark;
  const _BenchmarkTile({required this.benchmark});

  @override
  Widget build(BuildContext context) {
    final score = benchmark['score'] is num ? (benchmark['score'] as num).toDouble() : null;
    final failed = ((benchmark['failed_checks'] as List?) ?? const []).whereType<Map>().toList();
    final Color color = score == null ? Colors.white54 : (score >= 80 ? kGreen : (score >= 50 ? kOrange : kRed));
    final summary = <String>[
      if (benchmark['passed'] != null) '${benchmark['passed']} passed',
      if (benchmark['failed'] != null) '${benchmark['failed']} failed',
      if (benchmark['scanned_at'] != null) 'scanned ${_fmtTime(benchmark['scanned_at'].toString())}',
    ];
    return Container(
      width: double.infinity,
      margin: const EdgeInsets.only(bottom: 10),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(children: [
          Expanded(
            child: Text(benchmark['name']?.toString() ?? 'Benchmark',
                style: const TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.w600)),
          ),
          if (score != null)
            Text('${score.toStringAsFixed(0)}%', style: TextStyle(color: color, fontWeight: FontWeight.w700)),
        ]),
        const SizedBox(height: 2),
        Text(summary.join(' · '), style: const TextStyle(color: Colors.white38, fontSize: 11)),
        if (score != null) ...[
          const SizedBox(height: 6),
          ClipRRect(
            borderRadius: BorderRadius.circular(4),
            child: LinearProgressIndicator(
              value: (score / 100).clamp(0.0, 1.0).toDouble(),
              minHeight: 5,
              backgroundColor: kSurface2,
              valueColor: AlwaysStoppedAnimation<Color>(color),
            ),
          ),
        ],
        if (failed.isNotEmpty) ...[
          const SizedBox(height: 8),
          const Text('TOP FAILED CHECKS',
              style: TextStyle(color: Colors.white38, fontSize: 10, fontWeight: FontWeight.w700, letterSpacing: 0.8)),
          const SizedBox(height: 4),
          for (final c in failed)
            Theme(
              data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
              child: ExpansionTile(
                tilePadding: EdgeInsets.zero,
                childrenPadding: const EdgeInsets.only(bottom: 8),
                dense: true,
                title: Text(c['title']?.toString() ?? '',
                    style: const TextStyle(color: Colors.white70, fontSize: 12)),
                children: [
                  Align(
                    alignment: Alignment.centerLeft,
                    child: Text(
                      c['remediation'] == null ? 'No remediation text provided.' : 'Fix: ${c['remediation']}',
                      style: const TextStyle(color: Colors.white54, fontSize: 11, height: 1.4),
                    ),
                  ),
                ],
              ),
            ),
        ],
      ]),
    );
  }
}

class _RiskRow extends StatelessWidget {
  final Map<String, dynamic> risk;
  const _RiskRow({required this.risk});

  String _controlsLine(List<Map> controls) {
    if (controls.isEmpty) return 'No control is linked to this risk yet.';
    final parts = controls.map((c) {
      final eff = c['effectiveness'] is num ? ' (${((c['effectiveness'] as num) * 100).round()}%)' : '';
      return '${c['title']}$eff';
    });
    return 'Covered by ${parts.join(', ')}';
  }

  @override
  Widget build(BuildContext context) {
    final controls = ((risk['controls'] as List?) ?? const []).whereType<Map>().toList();
    final drivers = ((risk['driver_cves'] as List?) ?? const []).map((e) => e.toString()).toList();
    final score = risk['risk_score'];
    return Container(
      width: double.infinity,
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: kRed.withOpacity(0.06),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: kRed.withOpacity(0.2)),
      ),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(children: [
          Expanded(
            child: Text(risk['title']?.toString() ?? '',
                style: const TextStyle(color: kRed, fontSize: 13, fontWeight: FontWeight.w600)),
          ),
          if (score is num)
            Text('Score ${score.toStringAsFixed(1)}', style: const TextStyle(color: Colors.white54, fontSize: 11)),
        ]),
        if (drivers.isNotEmpty) ...[
          const SizedBox(height: 4),
          Text('Caused by ${drivers.join(', ')}', style: const TextStyle(color: Colors.white60, fontSize: 12)),
        ],
        const SizedBox(height: 4),
        Text(_controlsLine(controls), style: const TextStyle(color: Colors.white54, fontSize: 12)),
      ]),
    );
  }
}
