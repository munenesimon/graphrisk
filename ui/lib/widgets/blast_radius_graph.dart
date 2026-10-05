import 'dart:math' as math;
import 'package:flutter/material.dart';
import '../constants/colors.dart';
import '../constants/frameworks.dart';
import '../models/dashboard.dart';

/// A radial "hub and spoke" rendering of a BlastRadius result: the
/// queried control at the center, one ring of category nodes (Exposed
/// Risks, Affected Assets, Compliance Gaps, Framework Controls, Crosswalk
/// Requirements, Regulatory Duties), and -- on tap -- that category's
/// individual items fanned out one ring further.
///
/// This used to draw every category's items at once, which is what read
/// as "jumbled" no matter how the spacing was tuned: six categories'
/// worth of chips is simply a lot of information to show simultaneously,
/// regardless of layout. It's now an accordion instead -- only the hub
/// and the category ring are shown by default, and tapping a category
/// expands just its items, collapsing whichever other category was
/// previously expanded. One category's items at a time is both less
/// visually busy and a more direct answer to "what does tapping this
/// category actually contain" than a permanently-expanded diagram ever
/// was.
///
/// Expanding a category also moves the camera: the view animates in on
/// that category and its items while the rest of the diagram dims and
/// falls away to the edges, and collapsing it (tapping the category again,
/// or the hub) animates back out to the overview. Items themselves never
/// expand in place -- tapping one opens its detail, and closing that
/// returns to the same zoomed view.
///
/// This is deliberately a two-level tree, not a general graph -- the
/// blast-radius API returns each category as a flat list of names, with
/// no edges between items in different categories (which asset triggered
/// which risk isn't part of this response shape). See
/// BlastRadius.fromJson in models/dashboard.dart for the exact shape
/// this widget consumes.
///
/// Built entirely from Flutter's own SDK -- CustomPainter for the edges,
/// InteractiveViewer for pan/zoom -- rather than a third-party graph
/// package, since a new pub dependency can't be verified to compile
/// against this project's Flutter SDK version without a live build.
class BlastRadiusGraph extends StatefulWidget {
  final BlastRadius result;
  /// Builds the detail shown when an individual item is tapped -- the
  /// screen passes the same widget its list view uses for that item, so
  /// both views describe it identically. Given the category label and the
  /// item's index within that category's full list. Returning null (or no
  /// builder at all) falls back to just showing the item's full name.
  final Widget? Function(String category, int index)? itemDetailBuilder;
  const BlastRadiusGraph({super.key, required this.result, this.itemDetailBuilder});

  @override
  State<BlastRadiusGraph> createState() => _BlastRadiusGraphState();
}

class _BlastRadiusGraphState extends State<BlastRadiusGraph>
    with SingleTickerProviderStateMixin {
  // How many leaf items a single category will draw before collapsing
  // the rest into a "+N more" node -- unbounded categories (a control
  // mapped to 40 framework requirements) would otherwise overlap into an
  // unreadable knot. Same spirit as WazuhAdapter's per-run agent cap on
  // the backend: a documented, deliberate limit, not a silent truncation.
  static const int _maxItemsPerCategory = 10;
  static const double _categoryRadius = 210;
  static const double _itemRadius = 420;
  // The arc length (in logical pixels) a single leaf chip needs around
  // it so its label doesn't collide with its neighbors' -- only one
  // category's leaves are ever on screen at once now, so this just
  // decides how wide that one fan opens, not a sector shared with
  // anything else.
  static const double _minArcPerLeaf = 95;

  // Furthest the camera will zoom in on one category -- a category with
  // a single item would otherwise fill the screen with one huge chip.
  static const double _maxFocusScale = 1.5;
  // The canvas is always sized for the expanded ring, even when collapsed:
  // if it grew and shrank with the content, every expand/collapse would
  // shift the canvas origin mid-animation and make the view jump.
  static const double _canvasSize = (_itemRadius + 180) * 2;

  final _transform = TransformationController();
  late final AnimationController _zoomAnim =
      AnimationController(vsync: this, duration: const Duration(milliseconds: 550));
  Animation<Matrix4>? _zoomTween;
  Size? _lastFittedSize;
  // What the camera should frame, in canvas coordinates: the whole
  // diagram when collapsed, or the expanded category plus its items.
  Rect _focusRect = Rect.zero;
  // Set when the focus changed because of a tap, so the next fit animates
  // instead of jumping.
  bool _pendingAnimatedFit = false;

  // Which category (by label) currently has its items expanded -- null
  // means the diagram is fully collapsed to just the hub and the
  // category ring. Only one category is ever expanded at a time.
  String? _expandedLabel;

  @override
  void initState() {
    super.initState();
    _zoomAnim.addListener(() {
      final t = _zoomTween;
      if (t != null) _transform.value = t.value;
    });
  }

  @override
  void dispose() {
    _zoomAnim.dispose();
    _transform.dispose();
    super.dispose();
  }

  @override
  void didUpdateWidget(covariant BlastRadiusGraph oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (!identical(oldWidget.result, widget.result)) {
      // A new control was queried -- start fresh, collapsed, and
      // centered rather than wherever the previous one was left.
      _lastFittedSize = null;
      _expandedLabel = null;
      _pendingAnimatedFit = false;
    }
  }

  void _toggleCategory(String label) {
    setState(() {
      _expandedLabel = (_expandedLabel == label) ? null : label;
      // Zoom in on the newly expanded category (or back out to the
      // overview) once this frame has laid it out.
      _pendingAnimatedFit = true;
    });
  }

  void _collapse() {
    if (_expandedLabel == null) return;
    setState(() {
      _expandedLabel = null;
      _pendingAnimatedFit = true;
    });
  }

  void _openItemDetail(String category, int index, String label) {
    final detail = widget.itemDetailBuilder?.call(category, index);
    if (detail == null) {
      _showDetail(context, label);
      return;
    }
    showDialog<void>(
      context: context,
      builder: (ctx) => Dialog(
        backgroundColor: kSurface,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 560),
          child: Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 8, 16),
            child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
              Row(children: [
                Expanded(
                  child: Text(category,
                      style: const TextStyle(color: Colors.white70, fontSize: 13, fontWeight: FontWeight.w600)),
                ),
                IconButton(
                  tooltip: 'Close',
                  icon: const Icon(Icons.close, color: Colors.white54, size: 18),
                  onPressed: () => Navigator.of(ctx).pop(),
                ),
              ]),
              Flexible(
                child: Padding(
                  padding: const EdgeInsets.only(right: 8),
                  child: SingleChildScrollView(child: detail),
                ),
              ),
            ]),
          ),
        ),
      ),
    );
  }

  /// Frames [_focusRect] in [viewport] -- animated for a tap, instant for
  /// a first layout or a window resize.
  void _fitToView(Size viewport, {bool animate = false}) {
    if (!mounted) return;
    _lastFittedSize = viewport;
    final target = _matrixFor(_focusRect, viewport);
    if (!animate) {
      _zoomAnim.stop();
      _transform.value = target;
      return;
    }
    _animateTo(target);
  }

  void _animateTo(Matrix4 target) {
    _zoomTween = Matrix4Tween(begin: _transform.value.clone(), end: target)
        .animate(CurvedAnimation(parent: _zoomAnim, curve: Curves.easeInOutCubic));
    _zoomAnim.forward(from: 0);
  }

  /// The +/- buttons: zoom about the middle of the view, animated, within
  /// the same 0.25x-2.5x range as before.
  void _zoomBy(double factor, Size viewport) {
    final current = _transform.value.getMaxScaleOnAxis();
    final targetScale = (current * factor).clamp(0.25, 2.5).toDouble();
    final f = targetScale / current;
    if ((f - 1).abs() < 1e-3) return;
    final c = Offset(viewport.width / 2, viewport.height / 2);
    final aboutCenter = Matrix4.identity()
      ..translate(c.dx, c.dy)
      ..scale(f)
      ..translate(-c.dx, -c.dy);
    _animateTo(aboutCenter.multiplied(_transform.value));
  }

  Matrix4 _matrixFor(Rect rect, Size viewport) {
    const pad = 24.0;
    final maxScale = _expandedLabel == null ? 1.0 : _maxFocusScale;
    final scale = math
        .min((viewport.width - 2 * pad) / rect.width, (viewport.height - 2 * pad) / rect.height)
        .clamp(0.25, maxScale)
        .toDouble();
    final c = rect.center;
    return Matrix4.identity()
      ..translate(viewport.width / 2 - c.dx * scale, viewport.height / 2 - c.dy * scale)
      ..scale(scale);
  }

  List<_Category> _buildCategories() {
    final cats = <_Category>[];

    if (widget.result.exposedRisks.isNotEmpty) {
      cats.add(_Category('Exposed Risks', kRed, Icons.warning_amber_rounded, widget.result.exposedRisks));
    }
    if (widget.result.affectedAssets.isNotEmpty) {
      cats.add(_Category('Affected Assets', kOrange, Icons.devices_outlined, widget.result.affectedAssets));
    }
    final complianceItems = [
      ...widget.result.frameworkGroups.yourRegulations,
      ...widget.result.frameworkGroups.standards,
      ...widget.result.frameworkGroups.otherRegulations,
    ];
    if (complianceItems.isNotEmpty) {
      cats.add(_Category('Compliance Gaps', kPurple, Icons.policy_outlined, complianceItems));
    }
    if (widget.result.frameworkControls.isNotEmpty) {
      cats.add(_Category('Framework Controls', kAccent, Icons.list_alt_outlined, widget.result.frameworkControls));
    }
    if (widget.result.mappedFrameworkControls.isNotEmpty) {
      cats.add(_Category('Crosswalk Requirements', kOrange, Icons.alt_route, widget.result.mappedFrameworkControls));
    }
    final obligationItems = widget.result.regulatoryObligations.obligations
        .map((o) => '${o.title} (${o.deadlineHours}h -> ${o.notify})')
        .toList();
    if (obligationItems.isNotEmpty) {
      cats.add(_Category('Regulatory Duties', kGreen, Icons.gavel_outlined, obligationItems));
    }

    return cats;
  }

  int _leafCountFor(_Category cat) {
    final shown = math.min(cat.items.length, _maxItemsPerCategory);
    final hasOverflow = cat.items.length > shown;
    return shown + (hasOverflow ? 1 : 0);
  }

  @override
  Widget build(BuildContext context) {
    final categories = _buildCategories();
    if (categories.isEmpty) {
      return const Padding(
        padding: EdgeInsets.all(24),
        child: Text('Nothing to visualize for this control yet.',
            style: TextStyle(color: Colors.white38, fontSize: 13)),
      );
    }
    // A category that was expanded under a previous result (or that no
    // longer has items) shouldn't silently stay "expanded" against
    // nothing.
    if (_expandedLabel != null && !categories.any((c) => c.label == _expandedLabel)) {
      _expandedLabel = null;
    }

    final nodes = <_PositionedNode>[];
    final edges = <_Edge>[];
    final focusing = _expandedLabel != null;

    const center = Offset.zero;
    nodes.add(_PositionedNode(
      position: center,
      size: 78,
      color: kAccent,
      icon: Icons.shield,
      label: widget.result.controlTitle,
      isCenter: true,
      dimmed: focusing,
      // While zoomed in on a category, the hub is the way back out.
      onTap: focusing ? _collapse : null,
    ));

    final catCount = categories.length;
    // Collapsed: frame the hub and the category ring (labels included).
    Rect focus = Rect.fromCircle(center: center, radius: _categoryRadius + 80);

    for (var ci = 0; ci < catCount; ci++) {
      final cat = categories[ci];
      final isExpanded = cat.label == _expandedLabel;
      final catAngle = (-math.pi / 2) + (2 * math.pi * ci / catCount);
      final catPos = Offset(_categoryRadius * math.cos(catAngle), _categoryRadius * math.sin(catAngle));

      nodes.add(_PositionedNode(
        position: catPos,
        size: 58,
        color: cat.color,
        icon: cat.icon,
        label: '${cat.label} (${cat.items.length})',
        isCenter: false,
        isExpanded: isExpanded,
        dimmed: focusing && !isExpanded,
        onTap: () => _toggleCategory(cat.label),
      ));
      edges.add(_Edge(_circleToCircle(center, 39, catPos, 29),
          color: isExpanded ? cat.color : null, dimmed: focusing && !isExpanded));

      if (!isExpanded) continue;

      // Expanded: frame this category's node box (circle + label) and,
      // below, each of its item chips.
      focus = Rect.fromLTWH(catPos.dx - _kNodeBoxWidth / 2, catPos.dy - 29, _kNodeBoxWidth, 58 + 36);

      final shown = cat.items.take(_maxItemsPerCategory).toList();
      final overflow = cat.items.length - shown.length;
      final leafCount = _leafCountFor(cat);
      // Nothing else is sharing the circle right now, so this fan just
      // needs to be wide enough for its own leaf count -- no sector to
      // divide with sibling categories the way the old always-expanded
      // layout had to.
      final window = leafCount > 1
          ? (_minArcPerLeaf * (leafCount - 1) / _itemRadius).clamp(math.pi / 6, math.pi * 0.9).toDouble()
          : 0.0;

      for (var ii = 0; ii < leafCount; ii++) {
        final t = leafCount == 1 ? 0.5 : ii / (leafCount - 1);
        final itemAngle = catAngle - window / 2 + window * t;
        final itemPos = Offset(_itemRadius * math.cos(itemAngle), _itemRadius * math.sin(itemAngle));
        final isOverflow = overflow > 0 && ii == leafCount - 1;
        // Same readable framework names the list view shows (e.g. "NIST SP
        // 800-53 Rev5" rather than the raw "NIST_800_53" slug).
        final label = isOverflow
            ? '+$overflow more (see List view)'
            : cat.label == 'Compliance Gaps'
                ? frameworkDisplayName(shown[ii])
                : cat.label == 'Crosswalk Requirements'
                    ? readableRequirement(shown[ii])
                    : shown[ii];
        final itemIndex = ii;
        nodes.add(_PositionedNode(
          position: itemPos,
          size: 0,
          color: cat.color,
          icon: null,
          label: label,
          isCenter: false,
          isLeaf: true,
          isOverflow: isOverflow,
          onTap: isOverflow ? null : () => _openItemDetail(cat.label, itemIndex, label),
        ));
        edges.add(_Edge(_circleToRect(catPos, 29, itemPos, 55, 21), color: cat.color));
        focus = focus.expandToInclude(Rect.fromCenter(center: itemPos, width: 110, height: 42));
      }
      focus = focus.inflate(16);
    }

    _focusRect = focus.shift(const Offset(_canvasSize / 2, _canvasSize / 2));

    return LayoutBuilder(builder: (context, constraints) {
      final viewport = Size(constraints.maxWidth, constraints.maxHeight);
      if (_lastFittedSize != viewport || _pendingAnimatedFit) {
        // Animate only when the focus changed from a tap on an
        // already-laid-out view; a first layout or resize just snaps.
        final animate = _pendingAnimatedFit && _lastFittedSize == viewport;
        _pendingAnimatedFit = false;
        _lastFittedSize = viewport;
        WidgetsBinding.instance.addPostFrameCallback((_) => _fitToView(viewport, animate: animate));
      }
      return Stack(children: [
        InteractiveViewer(
          transformationController: _transform,
          constrained: false,
          minScale: 0.25,
          maxScale: 2.5,
          boundaryMargin: const EdgeInsets.all(400),
          // Mouse-wheel zoom is off: the graph sits inside a scrolling page,
          // and a wheel over it used to zoom the graph instead of scrolling
          // the page. Zoom with the +/- buttons or by tapping a category.
          scaleEnabled: false,
          // A manual pan/zoom mid-animation wins over the animation.
          onInteractionStart: (_) => _zoomAnim.stop(),
          child: SizedBox(
            width: _canvasSize,
            height: _canvasSize,
            child: Stack(children: [
              Positioned.fill(
                child: CustomPaint(
                  painter: _EdgePainter(edges, center: const Offset(_canvasSize / 2, _canvasSize / 2)),
                ),
              ),
              for (final n in nodes)
                Positioned(
                  left: _canvasSize / 2 + n.position.dx - (n.isLeaf ? 55 : _kNodeBoxWidth / 2),
                  top: _canvasSize / 2 + n.position.dy - (n.isLeaf ? 21 : n.size / 2),
                  child: AnimatedOpacity(
                    opacity: n.dimmed ? (n.isCenter ? 0.45 : 0.3) : 1.0,
                    duration: const Duration(milliseconds: 350),
                    child: n.isLeaf
                        // Items fade in as the camera arrives, rather than
                        // popping in before it gets there.
                        ? TweenAnimationBuilder<double>(
                            key: ValueKey('leaf:${_expandedLabel}:${n.label}'),
                            tween: Tween(begin: 0, end: 1),
                            duration: const Duration(milliseconds: 400),
                            curve: Curves.easeOut,
                            builder: (_, v, child) => Opacity(opacity: v, child: child),
                            child: _LeafChip(node: n),
                          )
                        : _CircleNode(node: n),
                  ),
                ),
            ]),
          ),
        ),
        Positioned(
          top: 8, right: 8,
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            _ViewButton(
              icon: Icons.center_focus_strong,
              tooltip: _expandedLabel == null ? 'Recenter the diagram' : 'Recenter on this category',
              onTap: () => _fitToView(viewport, animate: true),
            ),
            const SizedBox(height: 6),
            _ViewButton(icon: Icons.add, tooltip: 'Zoom in', onTap: () => _zoomBy(1.25, viewport)),
            const SizedBox(height: 6),
            _ViewButton(icon: Icons.remove, tooltip: 'Zoom out', onTap: () => _zoomBy(0.8, viewport)),
          ]),
        ),
          Positioned(
            bottom: 8, left: 8,
            child: IgnorePointer(
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                decoration: BoxDecoration(
                  color: kSurface2.withOpacity(0.8),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(
                    _expandedLabel == null
                        ? 'Tap a category to zoom in on its items'
                        : 'Tap an item for details · tap the category or the center to zoom out',
                    style: const TextStyle(color: Colors.white54, fontSize: 11)),
              ),
            ),
          ),
      ]);
    });
  }
}

/// Width of a circle node's whole box (circle + label underneath). The
/// label is what sets it -- it's wider than any circle -- and the circle
/// is centered horizontally inside it, so positioning must center this
/// box on the node's point, not a box the size of the circle. Getting
/// that wrong shifted every circle sideways off the end of its spokes.
const double _kNodeBoxWidth = 130;

/// A spoke between two circles, trimmed to start and end at each circle's
/// edge rather than its center (same look as a standard hub-and-spoke
/// diagram, and no line running underneath the node).
List<Offset> _circleToCircle(Offset a, double ra, Offset b, double rb) {
  final d = b - a;
  final len = d.distance;
  if (len <= ra + rb) return [a, b];
  final u = d / len;
  return [a + u * (ra + 2), b - u * (rb + 2)];
}

/// A spoke from a circle to a rectangular chip (half-width/half-height
/// given), ending where it meets the chip's border.
List<Offset> _circleToRect(Offset a, double ra, Offset b, double halfW, double halfH) {
  final d = b - a;
  final len = d.distance;
  if (len == 0) return [a, b];
  final u = d / len;
  final tx = u.dx.abs() < 1e-6 ? double.infinity : halfW / u.dx.abs();
  final ty = u.dy.abs() < 1e-6 ? double.infinity : halfH / u.dy.abs();
  return [a + u * (ra + 2), b - u * math.min(tx, ty)];
}

class _Category {
  final String label;
  final Color color;
  final IconData icon;
  final List<String> items;
  _Category(this.label, this.color, this.icon, this.items);
}

class _PositionedNode {
  final Offset position;
  final double size;
  final Color color;
  final IconData? icon;
  final String label;
  final bool isCenter;
  final bool isLeaf;
  final bool isOverflow;
  final bool isExpanded;
  /// Shown faded because another category has the focus.
  final bool dimmed;
  final VoidCallback? onTap;
  _PositionedNode({
    required this.position,
    required this.size,
    required this.color,
    this.icon,
    required this.label,
    this.isCenter = false,
    this.isLeaf = false,
    this.isOverflow = false,
    this.isExpanded = false,
    this.dimmed = false,
    this.onTap,
  });
}

/// One spoke: its two trimmed endpoints, plus how to draw it -- tinted
/// with the category's color when it belongs to the focused category,
/// faded when another category has the focus.
class _Edge {
  final Offset a;
  final Offset b;
  final Color? color;
  final bool dimmed;
  _Edge(List<Offset> ends, {this.color, this.dimmed = false})
      : a = ends[0],
        b = ends[1];
}

class _EdgePainter extends CustomPainter {
  final List<_Edge> edges;
  final Offset center;
  _EdgePainter(this.edges, {required this.center});

  @override
  void paint(Canvas canvas, Size size) {
    for (final e in edges) {
      final paint = Paint()
        ..color = e.color != null
            ? e.color!.withOpacity(0.45)
            : Colors.white.withOpacity(e.dimmed ? 0.05 : 0.12)
        ..strokeWidth = e.color != null ? 1.6 : 1.2
        ..style = PaintingStyle.stroke;
      canvas.drawLine(center + e.a, center + e.b, paint);
    }
  }

  // The canvas no longer changes size on expand/collapse, so nothing else
  // forces a repaint -- compare the edges themselves.
  @override
  bool shouldRepaint(covariant _EdgePainter oldDelegate) => !identical(oldDelegate.edges, edges);
}

void _showDetail(BuildContext context, String text) {
  ScaffoldMessenger.of(context).showSnackBar(
    SnackBar(content: Text(text), duration: const Duration(seconds: 4)),
  );
}

class _CircleNode extends StatelessWidget {
  final _PositionedNode node;
  const _CircleNode({required this.node});

  @override
  Widget build(BuildContext context) {
    // Category nodes toggle their own expansion; the hub (and any node
    // with no override) just announces its full label, since long
    // labels are already truncated below it.
    final onTap = node.onTap ?? () => _showDetail(context, node.label);
    final chevron = node.isCenter
        ? null
        : (node.isExpanded ? Icons.expand_less : Icons.expand_more);

    return GestureDetector(
      onTap: onTap,
      child: SizedBox(width: _kNodeBoxWidth, child: Column(mainAxisSize: MainAxisSize.min, children: [
        Container(
          width: node.size,
          height: node.size,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: Color.alphaBlend(node.color.withOpacity(node.isCenter ? 0.18 : (node.isExpanded ? 0.28 : 0.15)), kBackground),
            border: Border.all(color: node.color, width: node.isCenter ? 2 : (node.isExpanded ? 2.5 : 1.5)),
          ),
          child: Icon(node.icon, color: node.color, size: node.isCenter ? 30 : 22),
        ),
        const SizedBox(height: 4),
        SizedBox(
          width: _kNodeBoxWidth,
          child: Center(
            // Opaque backing so a spoke passing behind a label (e.g. the
            // hub's, on the way to the bottom category) doesn't strike
            // through the text.
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
              decoration: BoxDecoration(
                color: kBackground.withOpacity(0.85),
                borderRadius: BorderRadius.circular(6),
              ),
              child: Row(mainAxisSize: MainAxisSize.min, mainAxisAlignment: MainAxisAlignment.center, children: [
            Flexible(
              child: Text(
                node.label,
                textAlign: TextAlign.center,
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  color: node.isCenter ? Colors.white : (node.isExpanded ? Colors.white : Colors.white70),
                  fontSize: node.isCenter ? 12 : 11,
                  fontWeight: node.isCenter || node.isExpanded ? FontWeight.w700 : FontWeight.w600,
                ),
              ),
            ),
            if (chevron != null) Icon(chevron, color: node.color, size: 14),
              ]),
            ),
          ),
        ),
      ])),
    );
  }
}

class _LeafChip extends StatelessWidget {
  final _PositionedNode node;
  const _LeafChip({required this.node});

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: node.onTap ?? () => _showDetail(context, node.label),
      child: Container(
        width: 110,
        height: 42,
        alignment: Alignment.center,
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
        decoration: BoxDecoration(
          color: node.isOverflow ? Color.alphaBlend(kSurface2.withOpacity(0.6), kBackground) : Color.alphaBlend(node.color.withOpacity(0.1), kBackground),
          borderRadius: BorderRadius.circular(6),
          border: Border.all(color: node.isOverflow ? Colors.white24 : node.color.withOpacity(0.5)),
        ),
        child: Text(
          node.label,
          textAlign: TextAlign.center,
          maxLines: 2,
          overflow: TextOverflow.ellipsis,
          style: TextStyle(
            color: node.isOverflow ? Colors.white54 : Colors.white,
            fontSize: 10,
            fontStyle: node.isOverflow ? FontStyle.italic : FontStyle.normal,
          ),
        ),
      ),
    );
  }
}

class _ViewButton extends StatelessWidget {
  final IconData icon;
  final String tooltip;
  final VoidCallback onTap;
  const _ViewButton({required this.icon, required this.tooltip, required this.onTap});

  @override
  Widget build(BuildContext context) {
    return Tooltip(
      message: tooltip,
      child: Material(
        color: kSurface2.withOpacity(0.8),
        borderRadius: BorderRadius.circular(8),
        child: InkWell(
          borderRadius: BorderRadius.circular(8),
          onTap: onTap,
          child: Padding(
            padding: const EdgeInsets.all(8),
            child: Icon(icon, color: Colors.white70, size: 18),
          ),
        ),
      ),
    );
  }
}
