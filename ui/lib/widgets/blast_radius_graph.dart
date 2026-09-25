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
class BlastRadiusGraph extends StatelessWidget {
  final BlastRadius result;
  const BlastRadiusGraph({super.key, required this.result});

  // How many leaf items a single category will draw before collapsing
  // the rest into a "+N more" node -- unbounded categories (a control
  // mapped to 40 framework requirements) would otherwise overlap into an
  // unreadable knot. Same spirit as WazuhAdapter's per-run agent cap on
  // the backend: a documented, deliberate limit, not a silent truncation.
  static const int _maxItemsPerCategory = 10;
  static const double _canvasSize = 1200;
  static const double _categoryRadius = 190;
  static const double _itemRadius = 430;

  List<_Category> _buildCategories() {
    final cats = <_Category>[];

    if (result.exposedRisks.isNotEmpty) {
      cats.add(_Category('Exposed Risks', kRed, Icons.warning_amber_rounded, result.exposedRisks));
    }
    if (result.affectedAssets.isNotEmpty) {
      cats.add(_Category('Affected Assets', kOrange, Icons.devices_outlined, result.affectedAssets));
    }
    final complianceItems = [
      ...result.frameworkGroups.yourRegulations,
      ...result.frameworkGroups.standards,
      ...result.frameworkGroups.otherRegulations,
    ];
    if (complianceItems.isNotEmpty) {
      cats.add(_Category('Compliance Gaps', kPurple, Icons.policy_outlined, complianceItems));
    }
    if (result.frameworkControls.isNotEmpty) {
      cats.add(_Category('Framework Controls', kAccent, Icons.list_alt_outlined, result.frameworkControls));
    }
    if (result.mappedFrameworkControls.isNotEmpty) {
      cats.add(_Category('Crosswalk Requirements', kOrange, Icons.alt_route, result.mappedFrameworkControls));
    }
    final obligationItems = result.regulatoryObligations.obligations
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
      label: result.controlTitle,
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

    return InteractiveViewer(
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
    );
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
