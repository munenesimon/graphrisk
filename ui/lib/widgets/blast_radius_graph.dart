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
/// corner of the fixed _canvasSize canvas rather than the centered hub --
/// on a result with several categories that crops most of the diagram
/// out of view on load, which is what read as the diagram looking
/// scattered and parts of it being unreachable (a mouse-wheel/trackpad
/// scroll over the box pans the diagram, per InteractiveViewer's own
/// default handling of PointerScrollEvent, rather than scrolling the
/// page underneath it -- expected once the diagram itself starts
/// centered and legible, but confusing when it starts off-center).
/// _fitToView() computes a transform that centers the hub and scales the
/// full diagram to fit the available box, applied on first layout and
/// again whenever a new result comes in or the box is resized; the
/// button in the top-right corner re-applies it on demand as an explicit
/// "reset view" escape hatch instead of relying on the user rediscovering
/// the right drag.
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
  static const double _canvasSize = 1200;
  static const double _categoryRadius = 190;
  static const double _itemRadius = 430;
  // A heuristic half-extent for the content that actually needs to fit
  // on screen (item chips extend roughly itemRadius plus half a chip's
  // width/height beyond center) -- not an exact bounding box, which
  // would need an extra post-layout measurement pass just to save a
  // little padding.
  static const double _contentHalfExtent = _itemRadius + 60;

  final _transform = TransformationController();
  Size? _lastFittedSize;

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
    const center = _canvasSize / 2;
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

    final catCount = categories.length;
    for (var ci = 0; ci < catCount; ci++) {
      final cat = categories[ci];
      final catAngle = (-math.pi / 2) + (2 * math.pi * ci / catCount);
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
      final leafCount = shown.length + (overflow > 0 ? 1 : 0);
      // Fan this category's items across a slice of the full circle,
      // capped below the slice's natural width so neighboring categories'
      // fans don't visually run into each other.
      final window = (2 * math.pi / catCount) * 0.85;
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
        edges.add([catPos, itemPos]);
      }
    }

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
                  painter: _EdgePainter(edges, center: const Offset(_canvasSize / 2, _canvasSize / 2)),
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
