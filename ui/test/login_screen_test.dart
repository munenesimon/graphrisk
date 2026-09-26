// Widget tests for LoginScreen's client-side logic: form validation, the
// login/register mode toggle, and the demo-credentials shortcut. These
// deliberately never reach _submit()'s network call (ApiService.login /
// .register) -- form validation failing is what stops that call before it
// happens, and there's no dependency-injection seam in ApiService today to
// safely mock a successful network round trip in a widget test. Testing
// the real network paths is covered by manual verification against the
// deployed app (see the Roadmap doc), not this suite.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:graphrisk_ui/screens/login_screen.dart';

Widget _wrap(Widget child) => MaterialApp(home: child);

void main() {
  group('LoginScreen', () {
    testWidgets('defaults to log-in mode with no organization field', (tester) async {
      await tester.pumpWidget(_wrap(LoginScreen(onAuthenticated: () {})));

      expect(find.widgetWithText(ElevatedButton, 'Log in'), findsOneWidget);
      expect(find.text('Organization name'), findsNothing);
      expect(find.text('Email'), findsOneWidget);
      expect(find.text('Password'), findsOneWidget);
    });

    testWidgets('switching to create-account mode reveals the organization field', (tester) async {
      await tester.pumpWidget(_wrap(LoginScreen(onAuthenticated: () {})));

      await tester.tap(find.text('Create account'));
      await tester.pump();

      expect(find.text('Organization name'), findsOneWidget);
      expect(find.widgetWithText(ElevatedButton, 'Create account'), findsOneWidget);
    });

    testWidgets('submitting with empty fields shows validation errors and does not crash',
        (tester) async {
      await tester.pumpWidget(_wrap(LoginScreen(onAuthenticated: () {})));

      await tester.tap(find.widgetWithText(ElevatedButton, 'Log in'));
      await tester.pump();

      expect(find.text('Enter a valid email'), findsOneWidget);
      expect(find.text('At least 8 characters'), findsOneWidget);
    });

    testWidgets('an email without @ fails validation', (tester) async {
      await tester.pumpWidget(_wrap(LoginScreen(onAuthenticated: () {})));

      await tester.enterText(find.widgetWithText(TextFormField, 'Email'), 'not-an-email');
      await tester.enterText(find.widgetWithText(TextFormField, 'Password'), 'longenoughpassword');
      await tester.tap(find.widgetWithText(ElevatedButton, 'Log in'));
      await tester.pump();

      expect(find.text('Enter a valid email'), findsOneWidget);
    });

    testWidgets('a short password fails validation', (tester) async {
      await tester.pumpWidget(_wrap(LoginScreen(onAuthenticated: () {})));

      await tester.enterText(find.widgetWithText(TextFormField, 'Email'), 'person@example.com');
      await tester.enterText(find.widgetWithText(TextFormField, 'Password'), 'short');
      await tester.tap(find.widgetWithText(ElevatedButton, 'Log in'));
      await tester.pump();

      expect(find.text('At least 8 characters'), findsOneWidget);
    });

    testWidgets('create-account mode requires an organization name', (tester) async {
      await tester.pumpWidget(_wrap(LoginScreen(onAuthenticated: () {})));

      await tester.tap(find.text('Create account'));
      await tester.pump();
      await tester.enterText(find.widgetWithText(TextFormField, 'Email'), 'person@example.com');
      await tester.enterText(find.widgetWithText(TextFormField, 'Password'), 'longenoughpassword');
      await tester.tap(find.widgetWithText(ElevatedButton, 'Create account'));
      await tester.pump();

      expect(find.text('Enter an organization name'), findsOneWidget);
    });

    testWidgets('the demo-credentials shortcut fills email and password and stays in log-in mode',
        (tester) async {
      await tester.pumpWidget(_wrap(LoginScreen(onAuthenticated: () {})));

      // Switch to register mode first, to prove the shortcut also flips back to log-in.
      await tester.tap(find.text('Create account'));
      await tester.pump();

      // In register mode the card is taller than the default 800x600 test
      // surface, so "Use demo credentials" (below the card) sits below the
      // fold inside the SingleChildScrollView. Scroll it into view first --
      // otherwise the tap lands outside the render view and silently misses,
      // leaving the fields empty.
      final demoLinkFinder = find.text('Use demo credentials');
      await tester.ensureVisible(demoLinkFinder);
      await tester.pumpAndSettle();

      await tester.tap(demoLinkFinder);
      await tester.pump();

      // find.text() only matches Text/RichText widgets, not the live value
      // inside a TextFormField's EditableText -- the "Email"/"Password"
      // labels are findable as text, but a filled-in value never is. Read
      // the controller directly instead.
      final emailField =
          tester.widget<TextFormField>(find.widgetWithText(TextFormField, 'Email'));
      final passwordField =
          tester.widget<TextFormField>(find.widgetWithText(TextFormField, 'Password'));
      expect(emailField.controller!.text, 'demo@graphrisk.dev');
      expect(passwordField.controller!.text, 'demopass123');
      expect(find.text('Organization name'), findsNothing); // back in log-in mode
    });

    testWidgets('shows the session-expired banner when sessionExpired is true', (tester) async {
      await tester.pumpWidget(_wrap(LoginScreen(onAuthenticated: () {}, sessionExpired: true)));
      await tester.pump();

      expect(find.text('Your session expired. Please log in again.'), findsOneWidget);
    });

    testWidgets('does not show the session-expired banner on a normal cold start', (tester) async {
      await tester.pumpWidget(_wrap(LoginScreen(onAuthenticated: () {})));

      expect(find.text('Your session expired. Please log in again.'), findsNothing);
    });
  });
}
