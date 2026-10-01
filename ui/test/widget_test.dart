// Smoke test for app startup. The default `flutter create` counter-app
// test this replaced referenced a `MyApp` widget that doesn't exist in
// this codebase (the real root widget is `GraphRiskApp`) -- it would have
// failed to even compile, so it was never actually exercising anything.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:graphrisk_ui/main.dart';

void main() {
  testWidgets('App boots to the login screen when no session exists',
      (WidgetTester tester) async {
    await tester.pumpWidget(const GraphRiskApp());
    await tester.pump();

    // ApiService.isLoggedIn starts false in a fresh test process (main()'s
    // restoreSession() isn't run by pumpWidget), so the router's redirect
    // must land on /login, not the main dashboard shell.
    expect(find.text('GraphRisk'), findsOneWidget);
    expect(find.widgetWithText(ElevatedButton, 'Log in'), findsOneWidget);
    expect(find.text('Dashboard'), findsNothing);
  });
}
