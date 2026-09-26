// Widget tests for BlastRadiusGraph's structural rendering: which category
// nodes appear, the "+N more" overflow cap, and the empty state. Tap-to-
// popover interaction (_showNodePopover / _NodePopoverCard) lives inside
// an InteractiveViewer over a large fixed-size canvas, whose viewport
// transform makes a simulated tap's hit-testing behavior in a default-size
// test surface unreliable to assert on without a real Flutter test run to
// verify against -- that interaction was instead verified by hand against
// the deployed app (see the Roadmap doc's Blast Radius Graph entries).
// These tests stick to what's safe to assert without running flutter test.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:graphrisk_ui/models/dashboard.dart';
import 'package:graphrisk_ui/widgets/blast_radius_graph.dart';

BlastRadius _blastRadius({
  List<String> exposedRisks = const [],
  List<String> affectedAssets = const [],
  List<String> frameworkControls = const [],
  List<String> mappedFrameworkControls = const [],
  String controlTitle = 'Multi-Factor Authentication',
}) {
  return BlastRadius(
    controlTitle: controlTitle,
    controlStatus: 'implemented',
    effectivenessScore: 0.8,
    exposedRisks: exposedRisks,
    affectedAssets: affectedAssets,
    complianceGaps: const [],
    frameworkControls: frameworkControls,
    riskCount: exposedRisks.length,
    assetCount: affectedAssets.length,
    frameworkCount: frameworkControls.length,
    scope: 'all',
    frameworkGroups: FrameworkGroups(standards: const [], yourRegulations: const [], otherRegulations: const []),
    mappedFrameworkControls: mappedFrameworkControls,
    regulatoryObligations: RegulatoryObligations(note: '', obligations: const []),
  );
}

Widget _wrap(Widget child) => MaterialApp(
      home: Scaffold(body: child),
    );

void main() {
  group('BlastRadiusGraph', () {
    testWidgets('shows a message instead of a graph when there is nothing to visualize', (tester) async {
      await tester.pumpWidget(_wrap(BlastRadiusGraph(result: _blastRadius())));

      expect(find.text('Nothing to visualize for this control yet.'), findsOneWidget);
      expect(find.byType(InteractiveViewer), findsNothing);
    });

    testWidgets('renders the center control title and one node per non-empty category', (tester) async {
      final result = _blastRadius(
        controlTitle: 'Multi-Factor Authentication',
        exposedRisks: ['Credential Stuffing', 'Account Takeover'],
        affectedAssets: ['prod-db-01'],
      );
      await tester.pumpWidget(_wrap(BlastRadiusGraph(result: result)));

      expect(find.byType(InteractiveViewer), findsOneWidget);
      expect(find.text('Multi-Factor Authentication'), findsOneWidget);
      expect(find.text('Exposed Risks (2)'), findsOneWidget);
      expect(find.text('Affected Assets (1)'), findsOneWidget);
      // Categories with nothing to show don't get a node at all.
      expect(find.textContaining('Framework Controls'), findsNothing);
      expect(find.textContaining('Crosswalk Requirements'), findsNothing);
    });

    testWidgets('every leaf item under the 10-item cap is shown individually', (tester) async {
      final items = List.generate(6, (i) => 'Risk $i');
      final result = _blastRadius(exposedRisks: items);
      await tester.pumpWidget(_wrap(BlastRadiusGraph(result: result)));

      for (final item in items) {
        expect(find.text(item), findsOneWidget);
      }
      expect(find.textContaining('more (see List view)'), findsNothing);
    });

    testWidgets('a category over the 10-item cap collapses the rest into a "+N more" node', (tester) async {
      final items = List.generate(13, (i) => 'Requirement $i');
      final result = _blastRadius(mappedFrameworkControls: items);
      await tester.pumpWidget(_wrap(BlastRadiusGraph(result: result)));

      expect(find.text('Crosswalk Requirements (13)'), findsOneWidget);
      for (var i = 0; i < 10; i++) {
        expect(find.text('Requirement $i'), findsOneWidget);
      }
      // 13 items, cap 10 -> 3 collapsed into the overflow node.
      expect(find.text('+3 more (see List view)'), findsOneWidget);
      expect(find.text('Requirement 10'), findsNothing);
    });
  });
}
