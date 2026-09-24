import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';
import '../constants/colors.dart';
import '../constants/frameworks.dart';
import '../models/dashboard.dart';
import '../services/api_service.dart';
import '../widgets/regulatory_obligations_card.dart';

class BlastRadiusScreen extends StatefulWidget {
  /// Lets the caller (MainShell) offer a jump to the Regulatory Profile
  /// screen when the Regulatory Obligations layer has nothing to show
  /// because no profile is set.
  final VoidCallback? onManageProfile;
  const BlastRadiusScreen({super.key, this.onManageProfile});
  @override
  State<BlastRadiusScreen> createState() => _BlastRadiusScreenState();
}

class _BlastRadiusScreenState extends State<BlastRadiusScreen>
    with TickerProviderStateMixin {
  final _ctrl = TextEditingController();
  BlastRadius? _result;
  bool _loading = false;
  String? _error;
  // "all": every framework this control supports, grouped. "applicable":
  // standards plus only the regulations in the tenant's regulatory profile.
  String _scope = 'all';

  // One AnimationController per cascade layer
  late final List<AnimationController> _layerControllers;
  late final List<Animation<double>> _layerFades;
  late final List<Animation<Offset>> _layerSlides;

  // Pulse animation for the trigger node
  late final AnimationController _pulseCtrl;
  late final Animation<double> _pulseAnim;

  // Current MFA control id in the demo tenant post-reseed (matches the
  // README's live example) -- the old id here 404'd after seed_demo.py
  // started generating fresh UUIDs on each reseed.
  static const _defaultId = '2b813abc-d89a-4186-b11e-b20a4216e15b';
  static const _layerCount = 6; // risks, assets, frameworks, framework controls, crosswalk requirements, regulatory obligations
  static const _layerDelay = 180; // ms between each layer unfolding

  @override
  void initState() {
    super.initState();

    _pulseCtrl = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1200),
    );
    _pulseAnim = Tween<double>(begin: 1.0, end: 1.06).animate(
      CurvedAnimation(parent: _pulseCtrl, curve: Curves.easeInOut),
    );

    _layerControllers = List.generate(
      _layerCount,
      (_) => AnimationController(
        vsync: this,
        duration: const Duration(milliseconds: 420),
      ),
    );

    _layerFades = _layerControllers
        .map((c) => CurvedAnimation(parent: c, curve: Curves.easeOut))
        .toList();

    _layerSlides = _layerControllers
        .map((c) => Tween<Offset>(
              begin: const Offset(0, 0.18),
              end: Offset.zero,
            ).animate(CurvedAnimation(parent: c, curve: Curves.easeOut)))
        .toList();

    _ctrl.text = _defaultId;
    _run(_defaultId);
  }

  @override
  void dispose() {
    _pulseCtrl.dispose();
    for (final c in _layerControllers) {
      c.dispose();
    }
    _ctrl.dispose();
    super.dispose();
  }

  Future<void> _run(String id) async {
    if (id.isEmpty) return;

    // Reset animations
    _pulseCtrl.stop();
    for (final c in _layerControllers) {
      c.reset();
    }

    setState(() {
      _loading = true;
      _error = null;
      _result = null;
    });

    try {
      final r = await ApiService.getBlastRadiusControl(id, scope: _scope);
      if (!mounted) return;
      setState(() {
        _result = r;
        _loading = false;
      });

      // Pulse the trigger node briefly
      _pulseCtrl.repeat(reverse: true);
      await Future.delayed(const Duration(milliseconds: 600));
      _pulseCtrl.stop();
      _pulseCtrl.animateTo(1.0);

      // Unfold each cascade layer sequentially
      for (int i = 0; i < _layerCount; i++) {
        await Future.delayed(Duration(milliseconds: i == 0 ? 200 : _layerDelay));
        if (mounted) _layerControllers[i].forward();
      }
    } catch (e) {
      if (!mounted) return;
      // A session-expiry redirect is already in flight -- see the same
      // comment in dashboard_screen.dart's _load().
      if (e is AuthException) return;
      setState(() {
        _error = e.toString().replaceFirst('Exception: ', '');
        _loading = false;
      });
    }
  }

  void _setScope(String scope) {
    if (scope == _scope) return;
    setState(() => _scope = scope);
    // Re-run against whatever control id is already showing, if any, so
    // the toggle updates the current view instead of requiring "Run" again.
    final id = _ctrl.text.trim();
    if (id.isNotEmpty && (_result != null || _error != null)) _run(id);
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const Text('Blast Radius',
            style: TextStyle(
                color: Colors.white,
                fontSize: 22,
                fontWeight: FontWeight.w700,
                letterSpacing: -0.3)),
        const SizedBox(height: 4),
        const Text(
            'A single control change cascades through your risk graph automatically.',
            style: TextStyle(color: Colors.white54, fontSize: 13)),
        const SizedBox(height: 24),

        // ── Query bar ────────────────────────────────────────────────────────
        Row(children: [
          Expanded(
            child: TextField(
              controller: _ctrl,
              style: const TextStyle(
                  color: Colors.white, fontSize: 13, fontFamily: 'monospace'),
              decoration: InputDecoration(
                hintText: 'Control UUID...',
                hintStyle: const TextStyle(color: Colors.white38),
                filled: true,
                fillColor: kSurface,
                prefixIcon: const Icon(Icons.shield_outlined,
                    color: Colors.white38, size: 18),
                border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(8),
                    borderSide:
                        BorderSide(color: kAccent.withOpacity(0.3))),
                enabledBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(8),
                    borderSide:
                        BorderSide(color: kAccent.withOpacity(0.3))),
                focusedBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(8),
                    borderSide: const BorderSide(color: kAccent)),
                contentPadding:
                    const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
              ),
            ),
          ),
          const SizedBox(width: 12),
          ElevatedButton.icon(
            onPressed: _loading ? null : () => _run(_ctrl.text.trim()),
            icon: _loading
                ? const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(
                        strokeWidth: 2, color: Colors.white))
                : const Icon(Icons.bolt, size: 18),
            label: Text(_loading ? 'Running...' : 'Run'),
            style: ElevatedButton.styleFrom(
              backgroundColor: kAccent,
              foregroundColor: Colors.white,
              disabledBackgroundColor: kAccent.withOpacity(0.5),
              padding:
                  const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(8)),
            ),
          ),
        ]),

        const SizedBox(height: 12),

        // ── Scope toggle ─────────────────────────────────────────────────────
        Row(children: [
          const Text('Frameworks:', style: TextStyle(color: Colors.white38, fontSize: 12)),
          const SizedBox(width: 10),
          _ScopeChip(label: 'All', selected: _scope == 'all', onTap: () => _setScope('all')),
          const SizedBox(width: 8),
          _ScopeChip(label: 'Only mine', selected: _scope == 'applicable', onTap: () => _setScope('applicable')),
        ]),

        const SizedBox(height: 28),

        // ── Error state ──────────────────────────────────────────────────────
        if (_error != null) _ErrorCard(message: _error!),

        // ── Cascade visualization ────────────────────────────────────────────
        if (_result != null) ...[
          // Trigger node
          _TriggerNode(result: _result!, pulseAnim: _pulseAnim),

          const SizedBox(height: 8),

          // Cascade connector
          _CascadeConnector(),

          // Layer 0: Risks
          _CascadeLayer(
            fade: _layerFades[0],
            slide: _layerSlides[0],
            child: _ExpandableSection(
              title: 'Exposed Risks',
              subtitle: '${_result!.riskCount} risk${_result!.riskCount == 1 ? '' : 's'} activated',
              color: kRed,
              icon: Icons.warning_amber_rounded,
              items: _result!.exposedRisks
                  .map((r) => _RiskItem(name: r, result: _result!))
                  .toList(),
            ),
          ),

          _CascadeConnector(),

          // Layer 1: Assets
          _CascadeLayer(
            fade: _layerFades[1],
            slide: _layerSlides[1],
            child: _ExpandableSection(
              title: 'Affected Assets',
              subtitle: '${_result!.assetCount} asset${_result!.assetCount == 1 ? '' : 's'} exposed',
              color: kOrange,
              icon: Icons.devices_outlined,
              items: _result!.affectedAssets
                  .map((a) => _AssetItem(name: a))
                  .toList(),
            ),
          ),

          _CascadeConnector(),

          // Layer 2: Compliance gaps -- grouped into your regulations,
          // voluntary standards, and (scope=all only) regulations you
          // aren't subject to.
          _CascadeLayer(
            fade: _layerFades[2],
            slide: _layerSlides[2],
            child: _ExpandableSection(
              title: 'Compliance Gaps',
              subtitle: '${_result!.frameworkCount} framework${_result!.frameworkCount == 1 ? '' : 's'} affected'
                  '${_scope == 'all' ? '' : ' (only yours)'}',
              color: kPurple,
              icon: Icons.policy_outlined,
              items: [
                ..._result!.frameworkGroups.yourRegulations
                    .map((f) => _FrameworkItem(name: f, badge: 'Your regulation', badgeColor: kOrange)),
                ..._result!.frameworkGroups.standards
                    .map((f) => _FrameworkItem(name: f, badge: 'Standard', badgeColor: kAccent)),
                ..._result!.frameworkGroups.otherRegulations
                    .map((f) => _FrameworkItem(name: f, badge: 'Not in your profile', badgeColor: Colors.white38, subdued: true)),
              ],
            ),
          ),

          _CascadeConnector(),

          // Layer 3: Framework controls
          _CascadeLayer(
            fade: _layerFades[3],
            slide: _layerSlides[3],
            child: _ExpandableSection(
              title: 'Framework Controls',
              subtitle: '${_result!.frameworkControls.length} specific requirement${_result!.frameworkControls.length == 1 ? '' : 's'}',
              color: kAccent,
              icon: Icons.list_alt_outlined,
              items: _result!.frameworkControls
                  .map((fc) => _FrameworkControlItem(ref: fc))
                  .toList(),
            ),
          ),

          _CascadeConnector(),

          // Layer 4: Regulatory requirements reached via GraphRisk's
          // curated crosswalk (e.g. this control also satisfies Kenya DPA
          // s.43(3) because it MAPS_TO the NIST control it directly satisfies).
          _CascadeLayer(
            fade: _layerFades[4],
            slide: _layerSlides[4],
            child: _ExpandableSection(
              title: 'Regulatory Requirements (Crosswalk)',
              subtitle: '${_result!.mappedFrameworkControls.length} requirement${_result!.mappedFrameworkControls.length == 1 ? '' : 's'} via curated mapping',
              color: kOrange,
              icon: Icons.alt_route,
              items: _result!.mappedFrameworkControls
                  .map((m) => _MappedRequirementItem(raw: m))
                  .toList(),
            ),
          ),

          _CascadeConnector(),

          // Layer 5: Regulatory notification clocks
          _CascadeLayer(
            fade: _layerFades[5],
            slide: _layerSlides[5],
            child: RegulatoryObligationsSection(
              obligations: _result!.regulatoryObligations,
              onManageProfile: widget.onManageProfile,
            ),
          ),

          const SizedBox(height: 32),

          // Math explainer
          _MathCard(result: _result!),
        ],
      ]),
    );
  }
}

// ── Trigger node ─────────────────────────────────────────────────────────────
class _TriggerNode extends StatelessWidget {
  final BlastRadius result;
  final Animation<double> pulseAnim;
  const _TriggerNode({required this.result, required this.pulseAnim});

  @override
  Widget build(BuildContext context) {
    // Deliberately NOT wrapping the whole card in ScaleTransition (a
    // Transform). Every other card in this screen (_ExpandableSection,
    // via _CascadeLayer) only ever gets Fade/Slide transitions applied to
    // it, never a Transform, and those all render fine at full width with
    // no bleed. Putting an animated Transform directly around this card's
    // own decorated Container was what caused the fill to bleed
    // edge-to-edge across the whole window (a Flutter-web CanvasKit issue
    // with transformed decorated boxes). Matching the pattern that already
    // works: keep the card itself static, and pulse only the small icon.
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: kSurface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: kAccent.withOpacity(0.5), width: 1.5),
      ),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        LayoutBuilder(builder: (ctx, constraints) {
          final icon = ScaleTransition(
            scale: pulseAnim,
            child: Container(
              width: 36,
              height: 36,
              decoration: BoxDecoration(
                  color: kAccent.withOpacity(0.15),
                  borderRadius: BorderRadius.circular(8)),
              child: const Icon(Icons.shield, color: kAccent, size: 20),
            ),
          );
            final titleBlock = Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                const Text('TRIGGER',
                    style: TextStyle(
                        color: kAccent,
                        fontSize: 10,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 1.2)),
                Text(result.controlTitle,
                    overflow: TextOverflow.ellipsis,
                    maxLines: 2,
                    style: const TextStyle(
                        color: Colors.white,
                        fontSize: 15,
                        fontWeight: FontWeight.w600)),
              ],
            );
            final badge = _StatusBadge(status: result.controlStatus);

            // Below ~360px the fixed-width icon + badge leave too little
            // room for the title, so drop the badge to its own line
            // instead of letting the Row overflow horizontally.
            if (constraints.maxWidth < 360) {
              return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Row(children: [
                  icon,
                  const SizedBox(width: 12),
                  Expanded(child: titleBlock),
                ]),
                const SizedBox(height: 10),
                badge,
              ]);
            }

            return Row(children: [
              icon,
              const SizedBox(width: 12),
              Expanded(child: titleBlock),
              const SizedBox(width: 8),
              badge,
            ]);
          }),
          const SizedBox(height: 16),
          // Effectiveness bar
          Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              const Text('Control effectiveness',
                  style: TextStyle(color: Colors.white54, fontSize: 12)),
              const Spacer(),
              Text('${(result.effectivenessScore * 100).toInt()}%',
                  style: const TextStyle(
                      color: kAccent,
                      fontSize: 12,
                      fontWeight: FontWeight.bold)),
            ]),
            const SizedBox(height: 6),
            ClipRRect(
              borderRadius: BorderRadius.circular(4),
              child: LinearProgressIndicator(
                value: result.effectivenessScore,
                minHeight: 6,
                backgroundColor: kSurface2,
                valueColor: AlwaysStoppedAnimation(
                  result.effectivenessScore >= 0.8
                      ? kGreen
                      : result.effectivenessScore >= 0.5
                          ? kOrange
                          : kRed,
                ),
              ),
            ),
          ]),
        ]),
    );
  }
}

// ── Cascade connector ─────────────────────────────────────────────────────────

class _CascadeConnector extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(left: 29),
      child: SizedBox(
        height: 24,
        child: CustomPaint(painter: _ConnectorPainter()),
      ),
    );
  }
}

class _ConnectorPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = kAccent.withOpacity(0.3)
      ..strokeWidth = 1.5
      ..style = PaintingStyle.stroke
      ..strokeCap = StrokeCap.round;
    final path = Path()
      ..moveTo(0, 0)
      ..lineTo(0, size.height);
    canvas.drawPath(path, paint);

    // Arrow head
    final arrowPaint = Paint()
      ..color = kAccent.withOpacity(0.5)
      ..strokeWidth = 1.5
      ..style = PaintingStyle.stroke
      ..strokeCap = StrokeCap.round;
    canvas.drawLine(
        Offset(0, size.height), Offset(-5, size.height - 7), arrowPaint);
    canvas.drawLine(
        Offset(0, size.height), Offset(5, size.height - 7), arrowPaint);
  }

  @override
  bool shouldRepaint(_) => false;
}

// ── Cascade layer wrapper (animated) ─────────────────────────────────────────
class _CascadeLayer extends StatelessWidget {
  final Animation<double> fade;
  final Animation<Offset> slide;
  final Widget child;
  const _CascadeLayer(
      {required this.fade, required this.slide, required this.child});

  @override
  Widget build(BuildContext context) {
    return FadeTransition(
      opacity: fade,
      child: SlideTransition(position: slide, child: child),
    );
  }
}

// ── Expandable section ────────────────────────────────────────────────────────
class _ExpandableSection extends StatefulWidget {
  final String title;
  final String subtitle;
  final Color color;
  final IconData icon;
  final List<Widget> items;
  const _ExpandableSection({
    required this.title,
    required this.subtitle,
    required this.color,
    required this.icon,
    required this.items,
  });

  @override
  State<_ExpandableSection> createState() => _ExpandableSectionState();
}

class _ExpandableSectionState extends State<_ExpandableSection> {
  bool _expanded = true;

  @override
  Widget build(BuildContext context) {
    if (widget.items.isEmpty) return const SizedBox.shrink();
    return Container(
      decoration: BoxDecoration(
        color: kSurface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: widget.color.withOpacity(0.25)),
      ),
      child: Column(children: [
        InkWell(
          onTap: () => setState(() => _expanded = !_expanded),
          borderRadius: BorderRadius.circular(12),
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Row(children: [
              Container(
                width: 32,
                height: 32,
                decoration: BoxDecoration(
                    color: widget.color.withOpacity(0.12),
                    borderRadius: BorderRadius.circular(8)),
                child: Icon(widget.icon, color: widget.color, size: 17),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(widget.title,
                          style: const TextStyle(
                              color: Colors.white,
                              fontWeight: FontWeight.w600,
                              fontSize: 13)),
                      Text(widget.subtitle,
                          style: TextStyle(
                              color: widget.color.withOpacity(0.8),
                              fontSize: 11)),
                    ]),
              ),
              Icon(
                _expanded ? Icons.expand_less : Icons.expand_more,
                color: Colors.white38,
                size: 20,
              ),
            ]),
          ),
        ),
        if (_expanded) ...[
          Divider(height: 1, color: widget.color.withOpacity(0.15)),
          Padding(
            padding: const EdgeInsets.all(12),
            child: Column(
                children: widget.items
                    .map((item) => Padding(
                          padding: const EdgeInsets.only(bottom: 6),
                          child: item,
                        ))
                    .toList()),
          ),
        ],
      ]),
    );
  }
}

// ── Individual item widgets ───────────────────────────────────────────────────
class _RiskItem extends StatefulWidget {
  final String name;
  final BlastRadius result;
  const _RiskItem({required this.name, required this.result});

  @override
  State<_RiskItem> createState() => _RiskItemState();
}

class _RiskItemState extends State<_RiskItem> {
  bool _expanded = false;

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: () => setState(() => _expanded = !_expanded),
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: kRed.withOpacity(0.07),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: kRed.withOpacity(0.2)),
        ),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            const Icon(Icons.warning_amber_rounded, color: kRed, size: 15),
            const SizedBox(width: 8),
            Expanded(
                child: Text(widget.name,
                    style: const TextStyle(
                        color: kRed,
                        fontSize: 13,
                        fontWeight: FontWeight.w500))),
            Icon(_expanded ? Icons.expand_less : Icons.expand_more,
                color: kRed.withOpacity(0.6), size: 16),
          ]),
          if (_expanded) ...[
            const SizedBox(height: 10),
            const Divider(height: 1, color: Colors.white10),
            const SizedBox(height: 10),
            Text(
              'This risk is activated when the "${widget.result.controlTitle}" '
              'control fails to adequately mitigate the conditions that enable it. '
              'With effectiveness at ${(widget.result.effectivenessScore * 100).toInt()}%, '
              'residual risk remains.',
              style:
                  const TextStyle(color: Colors.white60, fontSize: 12, height: 1.5),
            ),
            const SizedBox(height: 8),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
              decoration: BoxDecoration(
                  color: kSurface2, borderRadius: BorderRadius.circular(6)),
              child: Text(
                'risk_score = likelihood × impact × (1 − ${widget.result.effectivenessScore.toStringAsFixed(1)})',
                style: const TextStyle(
                    color: kAccent,
                    fontSize: 11,
                    fontFamily: 'monospace'),
              ),
            ),
          ],
        ]),
      ),
    );
  }
}

class _AssetItem extends StatefulWidget {
  final String name;
  const _AssetItem({required this.name});

  @override
  State<_AssetItem> createState() => _AssetItemState();
}

class _AssetItemState extends State<_AssetItem> {
  bool _expanded = false;

  IconData get _icon {
    final n = widget.name.toLowerCase();
    if (n.contains('gateway') || n.contains('vpn')) return Icons.router_outlined;
    if (n.contains('database') || n.contains('db')) return Icons.storage_outlined;
    if (n.contains('365') || n.contains('email') || n.contains('mail'))
      return Icons.mail_outlined;
    if (n.contains('payroll') || n.contains('hr')) return Icons.people_outlined;
    return Icons.devices_outlined;
  }

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: () => setState(() => _expanded = !_expanded),
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: kOrange.withOpacity(0.07),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: kOrange.withOpacity(0.2)),
        ),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            Icon(_icon, color: kOrange, size: 15),
            const SizedBox(width: 8),
            Expanded(
                child: Text(widget.name,
                    style: const TextStyle(
                        color: kOrange,
                        fontSize: 13,
                        fontWeight: FontWeight.w500))),
            Icon(_expanded ? Icons.expand_less : Icons.expand_more,
                color: kOrange.withOpacity(0.6), size: 16),
          ]),
          if (_expanded) ...[
            const SizedBox(height: 10),
            const Divider(height: 1, color: Colors.white10),
            const SizedBox(height: 10),
            Text(
              '${widget.name} is exposed because one or more risks linked to this '
              'asset are activated by the control gap. Review the asset\'s risk '
              'links and ensure compensating controls are in place.',
              style:
                  const TextStyle(color: Colors.white60, fontSize: 12, height: 1.5),
            ),
          ],
        ]),
      ),
    );
  }
}

class _FrameworkItem extends StatefulWidget {
  final String name;
  /// Optional short label ("Your regulation" / "Standard" / "Not in your
  /// profile") shown next to the framework name -- see the Compliance Gaps
  /// layer's grouped rendering in build().
  final String? badge;
  final Color? badgeColor;
  /// Regulations outside the tenant's profile (scope=all only) render
  /// muted, since they're shown for context, not as something to act on.
  final bool subdued;
  const _FrameworkItem({required this.name, this.badge, this.badgeColor, this.subdued = false});

  @override
  State<_FrameworkItem> createState() => _FrameworkItemState();
}

class _FrameworkItemState extends State<_FrameworkItem> {
  bool _expanded = false;

  @override
  Widget build(BuildContext context) {
    final color = widget.subdued ? Colors.white38 : kPurple;
    return GestureDetector(
      onTap: () => setState(() => _expanded = !_expanded),
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: color.withOpacity(0.07),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: color.withOpacity(0.2)),
        ),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            Icon(Icons.policy_outlined, color: color, size: 15),
            const SizedBox(width: 8),
            Expanded(
                child: Text(frameworkDisplayName(widget.name),
                    style: TextStyle(
                        color: widget.subdued ? Colors.white54 : kPurple,
                        fontSize: 13,
                        fontWeight: FontWeight.w500))),
            if (widget.badge != null) ...[
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                decoration: BoxDecoration(
                    color: (widget.badgeColor ?? Colors.white38).withOpacity(0.15),
                    borderRadius: BorderRadius.circular(4)),
                child: Text(widget.badge!,
                    style: TextStyle(
                        color: widget.badgeColor ?? Colors.white54,
                        fontSize: 10,
                        fontWeight: FontWeight.w600)),
              ),
              const SizedBox(width: 8),
            ],
            Icon(_expanded ? Icons.expand_less : Icons.expand_more,
                color: color.withOpacity(0.6), size: 16),
          ]),
          if (_expanded) ...[
            const SizedBox(height: 10),
            const Divider(height: 1, color: Colors.white10),
            const SizedBox(height: 10),
            Text(frameworkDescription(widget.name),
                style: const TextStyle(
                    color: Colors.white60, fontSize: 12, height: 1.5)),
          ],
        ]),
      ),
    );
  }
}

/// One requirement reached via GraphRisk's curated crosswalk (e.g. "this
/// control satisfies a NIST control that MAPS_TO Kenya DPA s.43(3)"),
/// rather than a direct SATISFIES link. Raw strings look like
/// "KENYA_DPA DPA-43.1" -- see BLAST_RADIUS_CONTROL's mapped_framework_controls.
class _MappedRequirementItem extends StatefulWidget {
  final String raw;
  const _MappedRequirementItem({required this.raw});

  @override
  State<_MappedRequirementItem> createState() => _MappedRequirementItemState();
}

class _MappedRequirementItemState extends State<_MappedRequirementItem> {
  bool _expanded = false;

  String get _frameworkSlug {
    final i = widget.raw.indexOf(' ');
    return i == -1 ? widget.raw : widget.raw.substring(0, i);
  }

  String get _ref {
    final i = widget.raw.indexOf(' ');
    return i == -1 ? '' : widget.raw.substring(i + 1);
  }

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: () => setState(() => _expanded = !_expanded),
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: kOrange.withOpacity(0.07),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: kOrange.withOpacity(0.2)),
        ),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
              decoration: BoxDecoration(
                  color: kOrange.withOpacity(0.15), borderRadius: BorderRadius.circular(4)),
              child: Text(_ref.isEmpty ? widget.raw : _ref,
                  style: const TextStyle(
                      color: kOrange, fontSize: 11, fontFamily: 'monospace', fontWeight: FontWeight.bold)),
            ),
            const SizedBox(width: 8),
            Expanded(
                child: Text(frameworkDisplayName(_frameworkSlug),
                    style: const TextStyle(color: kOrange, fontSize: 13, fontWeight: FontWeight.w500))),
            Icon(_expanded ? Icons.expand_less : Icons.expand_more,
                color: kOrange.withOpacity(0.6), size: 16),
          ]),
          if (_expanded) ...[
            const SizedBox(height: 10),
            const Divider(height: 1, color: Colors.white10),
            const SizedBox(height: 10),
            const Text(
              'Reached via a GraphRisk-curated crosswalk mapping, not an official or '
              'government-issued mapping -- verify before treating it as compliant.',
              style: TextStyle(color: Colors.white60, fontSize: 12, height: 1.5),
            ),
          ],
        ]),
      ),
    );
  }
}

class _FrameworkControlItem extends StatefulWidget {
  final String ref;
  const _FrameworkControlItem({required this.ref});

  @override
  State<_FrameworkControlItem> createState() => _FrameworkControlItemState();
}

class _FrameworkControlItemState extends State<_FrameworkControlItem> {
  bool _expanded = false;

  String get _description {
    const descriptions = {
      'IA-2':  'Identification and Authentication — Uniquely identify and authenticate organizational users.',
      'IA-5':  'Authenticator Management — Manage system authenticators including passwords and tokens.',
      'AC-2':  'Account Management — Manage system accounts including establishing, activating, and removing accounts.',
      'PR.AA-03': 'Users, devices, and other assets are authenticated — commensurate with the risk of the transaction.',
    };
    return descriptions[widget.ref] ??
        'This framework control requirement is linked to the failing control. '
        'Review whether compensating controls satisfy this requirement.';
  }

  Future<void> _openNvdLink() async {
    // Framework controls don't have direct NVD links, but NIST controls
    // have searchable references.
    final query = Uri.encodeComponent(widget.ref);
    final uri = Uri.parse('https://csrc.nist.gov/glossary/term/${query.toLowerCase()}');
    if (await canLaunchUrl(uri)) {
      await launchUrl(uri, mode: LaunchMode.externalApplication);
    }
  }

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: () => setState(() => _expanded = !_expanded),
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: kAccent.withOpacity(0.07),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: kAccent.withOpacity(0.2)),
        ),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
              decoration: BoxDecoration(
                  color: kAccent.withOpacity(0.15),
                  borderRadius: BorderRadius.circular(4)),
              child: Text(widget.ref,
                  style: const TextStyle(
                      color: kAccent,
                      fontSize: 11,
                      fontFamily: 'monospace',
                      fontWeight: FontWeight.bold)),
            ),
            const SizedBox(width: 8),
            Expanded(
                child: Text('Framework requirement',
                    style: TextStyle(
                        color: Colors.white.withOpacity(0.5), fontSize: 12))),
            Icon(_expanded ? Icons.expand_less : Icons.expand_more,
                color: kAccent.withOpacity(0.6), size: 16),
          ]),
          if (_expanded) ...[
            const SizedBox(height: 10),
            const Divider(height: 1, color: Colors.white10),
            const SizedBox(height: 10),
            Text(_description,
                style: const TextStyle(
                    color: Colors.white60, fontSize: 12, height: 1.5)),
            const SizedBox(height: 8),
            InkWell(
              onTap: _openNvdLink,
              child: Row(mainAxisSize: MainAxisSize.min, children: [
                const Icon(Icons.open_in_new, color: kAccent, size: 13),
                const SizedBox(width: 4),
                Text('View in NIST glossary',
                    style: TextStyle(
                        color: kAccent.withOpacity(0.8),
                        fontSize: 12,
                        decoration: TextDecoration.underline)),
              ]),
            ),
          ],
        ]),
      ),
    );
  }
}

// ── Math explainer card ───────────────────────────────────────────────────────
class _MathCard extends StatelessWidget {
  final BlastRadius result;
  const _MathCard({required this.result});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: kSurface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.white.withOpacity(0.06)),
      ),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const Text('How risk scores cascade',
            style: TextStyle(
                color: Colors.white70,
                fontSize: 12,
                fontWeight: FontWeight.w600)),
        const SizedBox(height: 10),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
              color: kBackground, borderRadius: BorderRadius.circular(8)),
          child: Text(
            'risk_score = likelihood × impact × (1 − control_effectiveness)\n\n'
            'With "${result.controlTitle}" at ${(result.effectivenessScore * 100).toInt()}% effectiveness,\n'
            'every linked risk score is automatically recalculated.\n'
            'Change the control status → graph updates instantly.',
            style: const TextStyle(
                color: Colors.white54,
                fontSize: 12,
                fontFamily: 'monospace',
                height: 1.6),
          ),
        ),
      ]),
    );
  }
}

// ── Error card ────────────────────────────────────────────────────────────────
class _ErrorCard extends StatelessWidget {
  final String message;
  const _ErrorCard({required this.message});

  bool get _isNotFound => message.toLowerCase().contains('not found') ||
      message.toLowerCase().contains('404');
  bool get _isAuth => message.toLowerCase().contains('401') ||
      message.toLowerCase().contains('unauthorized') ||
      message.toLowerCase().contains('expired');

  String get _title {
    if (_isNotFound) return 'Control not found';
    if (_isAuth) return 'Session expired';
    return 'Something went wrong';
  }

  String get _suggestion {
    if (_isNotFound)
      return 'Check the control UUID and make sure demo data is seeded for this tenant.';
    if (_isAuth)
      return 'Your session has expired. Log out and log back in to continue.';
    return 'Try running the query again. If the problem persists, check the API logs.';
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      margin: const EdgeInsets.only(bottom: 24),
      decoration: BoxDecoration(
        color: kRed.withOpacity(0.08),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: kRed.withOpacity(0.25)),
      ),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const Icon(Icons.error_outline, color: kRed, size: 20),
        const SizedBox(width: 12),
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(_title,
                style: const TextStyle(
                    color: kRed, fontWeight: FontWeight.w600, fontSize: 13)),
            const SizedBox(height: 4),
            Text(_suggestion,
                style: const TextStyle(
                    color: Colors.white54, fontSize: 12, height: 1.5)),
            const SizedBox(height: 8),
            Text('Detail: $message',
                style: const TextStyle(
                    color: Colors.white38,
                    fontSize: 11,
                    fontFamily: 'monospace')),
          ]),
        ),
      ]),
    );
  }
}

// ── Scope chip (All / Only mine) ────────────────────────────────────────────
class _ScopeChip extends StatelessWidget {
  final String label;
  final bool selected;
  final VoidCallback onTap;
  const _ScopeChip({required this.label, required this.selected, required this.onTap});

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(20),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        decoration: BoxDecoration(
          color: selected ? kAccent.withOpacity(0.15) : Colors.transparent,
          borderRadius: BorderRadius.circular(20),
          border: Border.all(color: selected ? kAccent : kSurface2),
        ),
        child: Text(label,
            style: TextStyle(
                color: selected ? kAccent : Colors.white54,
                fontSize: 12,
                fontWeight: selected ? FontWeight.bold : FontWeight.normal)),
      ),
    );
  }
}

// ── Status badge ──────────────────────────────────────────────────────────────
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
        decoration: BoxDecoration(
            color: _color.withOpacity(0.15),
            borderRadius: BorderRadius.circular(20)),
        child: Text(_label,
            style: TextStyle(
                color: _color, fontSize: 11, fontWeight: FontWeight.bold)),
      );
}
