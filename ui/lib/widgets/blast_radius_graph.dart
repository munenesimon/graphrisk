import 'dart:math' as math;
import 'package:flutter/material.dart';
import '../constants/colors.dart';
import '../models/dashboard.dart';

/// A radial "hub and spoke" rendering of a BlastRadius result: the
/// queried control at the center, one ring of category nodes (Exposed
/// Risks, Affected Assets, Compliance Gaps, Framework Controls, Crosswalk
/// Requirements, Regulatory Duties), and each category's individual items
/// fanned out one ring further out.
///
/// This is deliberately a two-level tree, not a general graph -- the
/// blast-radius API returns each category as a flat list of names, with
/// no edges between items in different categories (which asset triggered
/// which risk isn't part of this response shape), so drawing anything
/// beyond a categorized hub-and-spoke would mean inventing connections
/// the data doesn't actually contain. See BlastRadius.fromJson in
/// models/dashboard.dart for the exact shape this widget consumes.
///
/// Built entirely from Flutter's own SDK -- CustomPainter for the edges,
/// InteractiveViewer for pan/zoom -- rather than a third-party graph
/// package, since a new pub dependency can't be verified to compile
/// against this project's Flutter SDK version without a live build.
///
/// Stateful (not the StatelessWidget this started as) purely to own the
/// InteractiveViewer's TransformationController: left unset,
/// InteractiveViewer(constrained: false) shows the unscaled top-left
/// corner of the canvas rather than the centered hub -- on a result with
/// several categories that crops most of the diagram out of view on
/// load. _fitToView() computes a transform that centers the hub and
/// scales the full diagram to fit the available box, applied on first
/// layout and again whenever a new result comes in or the box is
/// resized; the button in the top-right corner re-applies it on demand.
///
/// Layout: categories don't split the circle evenly any more. Each
/// category is given an angular sector sized by how many leaf chips it
/// has to show (a 1-item category and a 10-item category used to get the
/// exact same slice, which is what made a busy category's chips overlap
/// each other and spill into its neighbor's slice -- reads as the whole
/// diagram being "jumbled" even though the underlying tree is simple).
/// Within its sector, a crowded category is also pushed further out from
/// the hub (see _itemRadiusFor) so there's enough arc length between
/// adjacent chip centers for their labels not to collide. Both the
/// canvas size and the fit-to-view math scale with however far out that
/// pushes the busiest category, instead of assuming a fixed radius.
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
  // The arc length (in logical pixels) a single leaf chip needs around
  // it so its label doesn't collide with its neighbors' -- this is what
  // decides how far out a crowded category's ring has to sit, rather
  // than every category sharing one fixed item radius regardless of how
  // many chips it's fanning out.
  static const double _minArcPerLeaf = 95;
  static const double _itemRadiusMin = 300;
  static const double _itemRadiusMax = 620;

  final _transform = TransformationController();
  Size? _lastFittedSize;
  // Recomputed on every build from the actual content -- see build().
  double _canvasSize = 1200;
  double _contentHalfExtent = 490;

  @override
  void dispose() {
    _transform.dispose();
    super.dispose();
  }

  @override
  void didUpdateWidget(covariant BlastRadiusGraph oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (!identical(oldWidget.result, widget.result)) {
      // A new control was queried -- start the new diagram centered
      // rather than wherever the previous one happened to be panned to.
      // The build() below re-fits as soon as it sees this mismatch.
      _lastFittedSize = null;
    }
  }

  void _fitToView(Size viewport) {
    if (!mounted) return;
    _lastFittedSize = viewport;
    final center = _canvasSize / 2;
    final scale = (math.min(viewport.width, viewport.height) / (2 * _contentHalfExtent))
        .clamp(0.2, 1.0)
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

    // Weight each category's sector by its own leaf count (plus a flat
    // baseline so a 1-item category still gets a usable sliver instead
    // of being squeezed to almost nothing next to a 10-item one).
    final leafCounts = categories.map(_leafCountFor).toList();
    final weights = leafCounts.map((n) => n + 3).toList();
    final totalWeight = weights.fold<int>(0, (a, b) => a + b);

    double maxRadiusUsed = _categoryRadius;
    double cursor = -math.pi / 2;
    for (var ci = 0; ci < categories.length; ci++) {
      final cat = categories[ci];
      final leafCount = leafCounts[ci];
      final sector = 2 * math.pi * weights[ci] / totalWeight;
      final catAngle = cursor + sector / 2;
      cursor += sector;

      final catPos = Offset(_categoryRadius * math.cos(catAngle), _categoryRadius * math.sin(catAngle));
      nodes.add(_PositionedNode(
        position: catPos,
        size: 58,
        color: cat.color,
        icon: cat.icon,
        label: '${cat.label} (${cat.items.length})',
        isCenter: false,
      ));
      edges.add([center, catPos]);

      final shown = cat.items.take(_maxItemsPerCategory).toList();
      final overflow = cat.items.length - shown.length;
      final window = sector * 0.86;
      // A category with only one or two chips doesn't need to be pushed
      // far out -- it's a crowded category (several chips sharing a
      // sector) that needs the extra radius so the arc between
      // neighboring chip centers stays wide enough for their labels.
      final itemRadius = leafCount > 1
          ? (_minArcPerLeaf * (leafCount - 1) / window).clamp(_itemRadiusMin, _itemRadiusMax).toDouble()
          : _itemRadiusMin;
      if (itemRadius > maxRadiusUsed) maxRadiusUsed = itemRadius;

      for (var ii = 0; ii < leafCount; ii++) {
        final t = leafCount == 1 ? 0.5 : ii / (leafCount - 1);
        final itemAngle = catAngle - window / 2 + window * t;
        final itemPos = Offset(itemRadius * math.cos(itemAngle), itemRadius * math.sin(itemAngle));
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
        edges.add([catPos, itemPos]);
      }
    }

    // The canvas and the fit-to-view math both track however far out the
    // busiest category actually landed, rather than a fixed guess --
    // a result with one sparse category stays tight and legible instead
    // of floating in a canvas sized for a much busier one.
    _canvasSize = (maxRadiusUsed + 200) * 2;
    _contentHalfExtent = maxRadiusUsed + 90;

    return LayoutBuilder(builder: (context, constraints) {
      final viewport = Size(constraints.maxWidth, constraints.maxHeight);
      if (_lastFittedSize != viewport) {
        WidgetsBinding.instance.addPostFrameCallback((_) => _fitToView(viewport));
      }
      return Stack(children: [
        InteractiveViewer(
          transformationController: _transform,
          constrained: false,
          minScale: 0.2,
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
                  left: _canvasSize / 2 + n.position.dx - (n.isLeaf ? 55 : n.size / 2),
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
      ]);
    });
  }
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
  _PositionedNode({
    required this.position,
    required this.size,
    required this.color,
    this.icon,
    required this.label,
    this.isCenter = false,
    this.isLeaf = false,
    this.isOverflow = false,
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
    return GestureDetector(
      onTap: () => _showDetail(context, node.label),
      child: Column(mainAxisSize: MainAxisSize.min, children: [
        Container(
          width: node.size,
          height: node.size,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: node.color.withOpacity(node.isCenter ? 0.18 : 0.15),
            border: Border.all(color: node.color, width: node.isCenter ? 2 : 1.5),
          ),
          child: Icon(node.icon, color: node.color, size: node.isCenter ? 30 : 22),
        ),
        const SizedBox(height: 4),
        SizedBox(
          width: 130,
          child: Text(
            node.label,
            textAlign: TextAlign.center,
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              color: node.isCenter ? Colors.white : Colors.white70,
              fontSize: node.isCenter ? 12 : 11,
              fontWeight: node.isCenter ? FontWeight.w700 : FontWeight.w600,
            ),
          ),
        ),
      ]),
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
          color: node.isOverflow ? kSurface2.withOpacity(0.6) : node.color.withOpacity(0.1),
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
