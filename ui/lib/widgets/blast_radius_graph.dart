import 'dart:async';
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
  static const double _canvasSize = 1300;
  static const double _categoryRadius = 210;
  static const double _itemRadius = 460;

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
      // Distinct from Affected Assets' orange -- two categories sharing a
      // color made the old layout harder to scan at a glance.
      cats.add(_Category('Crosswalk Requirements', kTeal, Icons.alt_route, result.mappedFrameworkControls));
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
    final edges = <_Edge>[];

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
      // A straight spoke reads cleanly here -- it's literally a radius of
      // the category ring, so a curve would look like an arbitrary bend.
      edges.add(_Edge(center, catPos, cat.color, curved: false));

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
        // A gentle bow rather than a straight line makes the branch read
        // as a "connector" instead of a spike, and keeps a fan of leaves
        // from looking like a sunburst of dead-straight rays.
        edges.add(_Edge(catPos, itemPos, cat.color, curved: true));
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
              painter: _EdgePainter(
                edges,
                center: const Offset(_canvasSize / 2, _canvasSize / 2),
                categoryRadius: _categoryRadius,
                itemRadius: _itemRadius,
              ),
            ),
          ),
          for (final n in nodes)
            Positioned(
              left: _canvasSize / 2 + n.position.dx - (n.isLeaf ? 58 : n.size / 2),
              top: _canvasSize / 2 + n.position.dy - (n.isLeaf ? 22 : n.size / 2),
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

class _Edge {
  final Offset start;
  final Offset end;
  final Color color;
  final bool curved;
  _Edge(this.start, this.end, this.color, {required this.curved});
}

class _EdgePainter extends CustomPainter {
  final List<_Edge> edges;
  final Offset center;
  final double categoryRadius;
  final double itemRadius;
  _EdgePainter(this.edges, {required this.center, required this.categoryRadius, required this.itemRadius});

  @override
  void paint(Canvas canvas, Size size) {
    // Faint concentric rings give the layout a sense of structure/depth
    // (like radar range rings) instead of nodes floating in empty space.
    final guidePaint = Paint()
      ..color = Colors.white.withOpacity(0.045)
      ..strokeWidth = 1
      ..style = PaintingStyle.stroke;
    canvas.drawCircle(center, categoryRadius, guidePaint);
    canvas.drawCircle(center, itemRadius, guidePaint);

    for (final e in edges) {
      final start = center + e.start;
      final end = center + e.end;
      final paint = Paint()
        ..color = e.color.withOpacity(e.curved ? 0.22 : 0.38)
        ..strokeWidth = e.curved ? 1.1 : 1.4
        ..style = PaintingStyle.stroke;

      if (!e.curved) {
        canvas.drawLine(start, end, paint);
        continue;
      }

      final mid = Offset((start.dx + end.dx) / 2, (start.dy + end.dy) / 2);
      final dx = end.dx - start.dx;
      final dy = end.dy - start.dy;
      final len = math.sqrt(dx * dx + dy * dy);
      var control = mid;
      if (len > 0) {
        // Perpendicular offset, always bowed the same rotational way, so
        // every branch across the whole graph curves consistently rather
        // than some bulging left and others right at random.
        final nx = -dy / len;
        final ny = dx / len;
        final bend = len * 0.16;
        control = Offset(mid.dx + nx * bend, mid.dy + ny * bend);
      }
      final path = Path()
        ..moveTo(start.dx, start.dy)
        ..quadraticBezierTo(control.dx, control.dy, end.dx, end.dy);
      canvas.drawPath(path, paint);
    }
  }

  @override
  bool shouldRepaint(covariant _EdgePainter oldDelegate) => false;
}

/// Shows a small floating card near the tapped point instead of a
/// Material SnackBar pinned to the bottom of the screen -- a proper
/// pop-out/tooltip feel that stays anchored to what was actually tapped,
/// works the same however far down the (very tall) graph canvas that tap
/// happened, and doesn't collide with anything else docked at the bottom
/// of the page.
void _showNodePopover(BuildContext context, Offset globalPosition, _PositionedNode node) {
  final overlayState = Overlay.of(context);
  final screenSize = MediaQuery.of(context).size;
  const cardWidth = 260.0;

  final maxLeft = math.max(12.0, screenSize.width - cardWidth - 12);
  final left = (globalPosition.dx - cardWidth / 2).clamp(12.0, maxLeft);
  // Prefer popping the card above the tap (keeps it clear of anything
  // docked at the bottom); flip below only when there isn't room above.
  final showBelow = globalPosition.dy < 160;

  late OverlayEntry entry;
  var removed = false;
  void dismiss() {
    if (!removed) {
      removed = true;
      entry.remove();
    }
  }

  entry = OverlayEntry(builder: (_) {
    return Stack(children: [
      Positioned.fill(
        child: GestureDetector(
          behavior: HitTestBehavior.translucent,
          onTap: dismiss,
        ),
      ),
      Positioned(
        left: left,
        top: showBelow ? globalPosition.dy + 20 : null,
        bottom: showBelow ? null : screenSize.height - globalPosition.dy + 20,
        width: cardWidth,
        child: _NodePopoverCard(
          label: node.label,
          color: node.color,
          icon: node.icon,
          onDismiss: dismiss,
        ),
      ),
    ]);
  });
  overlayState.insert(entry);
}

class _NodePopoverCard extends StatefulWidget {
  final String label;
  final Color color;
  final IconData? icon;
  final VoidCallback onDismiss;
  const _NodePopoverCard({required this.label, required this.color, required this.onDismiss, this.icon});

  @override
  State<_NodePopoverCard> createState() => _NodePopoverCardState();
}

class _NodePopoverCardState extends State<_NodePopoverCard> with SingleTickerProviderStateMixin {
  late final AnimationController _ctrl;
  Timer? _autoDismiss;

  @override
  void initState() {
    super.initState();
    _ctrl = AnimationController(vsync: this, duration: const Duration(milliseconds: 170))..forward();
    _autoDismiss = Timer(const Duration(seconds: 6), widget.onDismiss);
  }

  @override
  void dispose() {
    _autoDismiss?.cancel();
    _ctrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ScaleTransition(
      scale: CurvedAnimation(parent: _ctrl, curve: Curves.easeOutBack),
      alignment: Alignment.topCenter,
      child: FadeTransition(
        opacity: CurvedAnimation(parent: _ctrl, curve: Curves.easeOut),
        child: Material(
          color: Colors.transparent,
          child: Container(
            padding: const EdgeInsets.fromLTRB(14, 12, 10, 12),
            decoration: BoxDecoration(
              color: kSurface,
              borderRadius: BorderRadius.circular(12),
              border: Border(left: BorderSide(color: widget.color, width: 3)),
              boxShadow: [
                BoxShadow(color: Colors.black.withOpacity(0.45), blurRadius: 20, offset: const Offset(0, 8)),
              ],
            ),
            child: Row(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
              if (widget.icon != null) ...[
                Icon(widget.icon, color: widget.color, size: 18),
                const SizedBox(width: 8),
              ],
              Expanded(
                child: Text(
                  widget.label,
                  style: const TextStyle(color: Colors.white, fontSize: 13, height: 1.35, fontWeight: FontWeight.w500),
                ),
              ),
              const SizedBox(width: 6),
              GestureDetector(
                onTap: widget.onDismiss,
                child: const Icon(Icons.close_rounded, color: Colors.white38, size: 16),
              ),
            ]),
          ),
        ),
      ),
    );
  }
}

class _CircleNode extends StatelessWidget {
  final _PositionedNode node;
  const _CircleNode({required this.node});

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTapDown: (details) => _showNodePopover(context, details.globalPosition, node),
      child: Column(mainAxisSize: MainAxisSize.min, children: [
        Container(
          width: node.size,
          height: node.size,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: node.color.withOpacity(node.isCenter ? 0.18 : 0.15),
            border: Border.all(color: node.color, width: node.isCenter ? 2 : 1.5),
            boxShadow: [
              BoxShadow(
                color: node.color.withOpacity(node.isCenter ? 0.35 : 0.2),
                blurRadius: node.isCenter ? 26 : 14,
                spreadRadius: node.isCenter ? 2 : 0,
              ),
            ],
          ),
          child: Icon(node.icon, color: node.color, size: node.isCenter ? 30 : 22),
        ),
        const SizedBox(height: 6),
        Container(
          constraints: const BoxConstraints(maxWidth: 130),
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
          decoration: BoxDecoration(
            color: kBackground.withOpacity(0.55),
            borderRadius: BorderRadius.circular(6),
          ),
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
    final accent = node.isOverflow ? Colors.white24 : node.color;
    return GestureDetector(
      onTapDown: (details) => _showNodePopover(context, details.globalPosition, node),
      child: Container(
        width: 116,
        height: 44,
        alignment: Alignment.center,
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
        decoration: BoxDecoration(
          color: node.isOverflow ? kSurface2.withOpacity(0.55) : kSurface.withOpacity(0.9),
          borderRadius: BorderRadius.circular(10),
          border: Border(left: BorderSide(color: accent, width: 3)),
          boxShadow: [
            BoxShadow(color: Colors.black.withOpacity(0.25), blurRadius: 8, offset: const Offset(0, 3)),
          ],
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
