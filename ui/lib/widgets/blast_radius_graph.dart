import 'dart:math' as math;
import 'package:flutter/material.dart';
import '../constants/colors.dart';
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
  const BlastRadiusGraph({super.key, required this.result});

  @override
  State<BlastRadiusGraph> createState() => _BlastRadiusGraphState();
}

class _BlastRadiusGraphState extends State<BlastRadiusGraph> {
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

  final _transform = TransformationController();
  Size? _lastFittedSize;
  double _canvasSize = 1100;
  double _contentHalfExtent = 470;

  // Which category (by label) currently has its items expanded -- null
  // means the diagram is fully collapsed to just the hub and the
  // category ring. Only one category is ever expanded at a time.
  String? _expandedLabel;

  @override
  void dispose() {
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
    }
  }

  void _toggleCategory(String label) {
    setState(() {
      _expandedLabel = (_expandedLabel == label) ? null : label;
      // The diagram's content bounds change when a category opens or
      // closes -- re-fit on the next frame instead of leaving the view
      // scaled/centered for whatever was on screen before.
      _lastFittedSize = null;
    });
  }

  void _fitToView(Size viewport) {
    if (!mounted) return;
    _lastFittedSize = viewport;
    final center = _canvasSize / 2;
    final scale = (math.min(viewport.width, viewport.height) / (2 * _contentHalfExtent))
        .clamp(0.25, 1.0)
        .toDouble();
    _transform.value = Matrix4.identity()
      ..translate(viewport.width / 2 - center * scale, viewport.height / 2 - center * scale)
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
    final edges = <List<Offset>>[];

    const center = Offset.zero;
    nodes.add(_PositionedNode(
      position: center,
      size: 78,
      color: kAccent,
      icon: Icons.shield,
      label: widget.result.controlTitle,
      isCenter: true,
    ));

    final catCount = categories.length;
    double maxRadiusUsed = _categoryRadius;

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
        onTap: () => _toggleCategory(cat.label),
      ));
      edges.add(_circleToCircle(center, 39, catPos, 29));

      if (!isExpanded) continue;

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
      if (_itemRadius > maxRadiusUsed) maxRadiusUsed = _itemRadius;

      for (var ii = 0; ii < leafCount; ii++) {
        final t = leafCount == 1 ? 0.5 : ii / (leafCount - 1);
        final itemAngle = catAngle - window / 2 + window * t;
        final itemPos = Offset(_itemRadius * math.cos(itemAngle), _itemRadius * math.sin(itemAngle));
        final isOverflow = overflow > 0 && ii == leafCount - 1;
        nodes.add(_PositionedNode(
          position: itemPos,
          size: 0,
          color: cat.color,
          icon: null,
          label: isOverflow ? '+$overflow more (see List view)' : shown[ii],
          isCenter: false,
          isLeaf: true,
          isOverflow: isOverflow,
        ));
        edges.add(_circleToRect(catPos, 29, itemPos, 55, 21));
      }
    }

    _canvasSize = (maxRadiusUsed + 180) * 2;
    _contentHalfExtent = maxRadiusUsed + 80;

    return LayoutBuilder(builder: (context, constraints) {
      final viewport = Size(constraints.maxWidth, constraints.maxHeight);
      if (_lastFittedSize != viewport) {
        WidgetsBinding.instance.addPostFrameCallback((_) => _fitToView(viewport));
      }
      return Stack(children: [
        InteractiveViewer(
          transformationController: _transform,
          constrained: false,
          minScale: 0.25,
          maxScale: 2.5,
          boundaryMargin: const EdgeInsets.all(400),
          child: SizedBox(
            width: _canvasSize,
            height: _canvasSize,
            child: Stack(children: [
              Positioned.fill(
                child: CustomPaint(
                  painter: _EdgePainter(edges, center: Offset(_canvasSize / 2, _canvasSize / 2)),
                ),
              ),
              for (final n in nodes)
                Positioned(
                  left: _canvasSize / 2 + n.position.dx - (n.isLeaf ? 55 : _kNodeBoxWidth / 2),
                  top: _canvasSize / 2 + n.position.dy - (n.isLeaf ? 21 : n.size / 2),
                  child: n.isLeaf ? _LeafChip(node: n) : _CircleNode(node: n),
                ),
            ]),
          ),
        ),
        Positioned(
          top: 8, right: 8,
          child: Tooltip(
            message: 'Recenter the diagram',
            child: Material(
              color: kSurface2.withOpacity(0.8),
              borderRadius: BorderRadius.circular(8),
              child: InkWell(
                borderRadius: BorderRadius.circular(8),
                onTap: () => _fitToView(viewport),
                child: const Padding(
                  padding: EdgeInsets.all(8),
                  child: Icon(Icons.center_focus_strong, color: Colors.white70, size: 18),
                ),
              ),
            ),
          ),
        ),
        if (_expandedLabel == null)
          Positioned(
            bottom: 8, left: 8,
            child: IgnorePointer(
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                decoration: BoxDecoration(
                  color: kSurface2.withOpacity(0.8),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: const Text('Tap a category to see its items',
                    style: TextStyle(color: Colors.white54, fontSize: 11)),
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
    this.onTap,
  });
}

class _EdgePainter extends CustomPainter {
  final List<List<Offset>> edges;
  final Offset center;
  _EdgePainter(this.edges, {required this.center});

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = Colors.white.withOpacity(0.12)
      ..strokeWidth = 1.2
      ..style = PaintingStyle.stroke;
    for (final e in edges) {
      canvas.drawLine(center + e[0], center + e[1], paint);
    }
  }

  @override
  bool shouldRepaint(covariant _EdgePainter oldDelegate) => false;
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
      onTap: () => _showDetail(context, node.label),
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
