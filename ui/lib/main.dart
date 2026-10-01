import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'constants/colors.dart';
import 'screens/dashboard_screen.dart';
import 'screens/blast_radius_screen.dart';
import 'screens/frameworks_screen.dart';
import 'screens/framework_detail_screen.dart';
import 'screens/vulnerability_screen.dart';
import 'screens/assets_screen.dart';
import 'screens/regulatory_profile_screen.dart';
import 'screens/connectors_screen.dart';
import 'screens/login_screen.dart';
import 'services/api_service.dart';

void main() {
  // Pick up this tab's session (if any) before the first route is
  // resolved, so a reload or a Back/Forward into the app lands on the
  // screen in the URL rather than on the login screen.
  ApiService.restoreSession();
  ApiService.onSessionExpired = _auth.expired;
  runApp(const GraphRiskApp());
}

/// Login state the router listens to. Every screen used to be swapped in
/// and out of a single page by hand (an AuthGate widget plus a tab index),
/// so the browser's history only ever held one entry: Back left the app
/// entirely, and coming back reloaded it with the in-memory session gone
/// -- which read as Back "logging you out." Each screen now has its own
/// URL (/#/dashboard, /#/frameworks/<id>, ...), so Back and Forward move
/// between screens, and the redirect below keeps unauthenticated visits on
/// /login.
class AuthState extends ChangeNotifier {
  bool sessionExpired = false;

  bool get loggedIn => ApiService.isLoggedIn;

  void authenticated() {
    sessionExpired = false;
    notifyListeners();
  }

  void logout() {
    ApiService.logout();
    sessionExpired = false;
    notifyListeners();
  }

  // Fired by ApiService whenever an authenticated call comes back 401
  // (JWT expired) -- it has already cleared the session by this point.
  void expired() {
    sessionExpired = true;
    notifyListeners();
  }
}

final _auth = AuthState();

/// Rail order. DashboardScreen's stat cards navigate by index into this.
const _tabPaths = [
  '/dashboard',
  '/blast-radius',
  '/frameworks',
  '/vulnerabilities',
  '/assets',
  '/regulatory',
  '/connectors',
];

final _router = GoRouter(
  initialLocation: '/dashboard',
  refreshListenable: _auth,
  redirect: (context, state) {
    final atLogin = state.matchedLocation == '/login';
    if (!_auth.loggedIn) return atLogin ? null : '/login';
    if (atLogin) return '/dashboard';
    return null;
  },
  routes: [
    GoRoute(path: '/', redirect: (_, __) => '/dashboard'),
    GoRoute(
      path: '/login',
      builder: (context, state) => LoginScreen(
        // A distinct key per mode, so switching from /login to
        // /login?register=1 builds a fresh form in the right mode.
        key: ValueKey('login-${state.uri.queryParameters['register'] ?? ''}'),
        onAuthenticated: _auth.authenticated,
        sessionExpired: _auth.sessionExpired,
        initialRegisterMode: state.uri.queryParameters['register'] == '1',
      ),
    ),
    ShellRoute(
      builder: (context, state, child) => MainShell(
        location: state.matchedLocation,
        onLogout: _auth.logout,
        child: child,
      ),
      routes: [
        GoRoute(
          path: '/dashboard',
          builder: (context, state) =>
              DashboardScreen(onNavigate: (i) => context.go(_tabPaths[i])),
        ),
        GoRoute(
          path: '/blast-radius',
          builder: (context, state) =>
              BlastRadiusScreen(onManageProfile: () => context.go('/regulatory')),
        ),
        GoRoute(
          path: '/frameworks',
          builder: (context, state) => const FrameworksScreen(),
          routes: [
            GoRoute(
              path: ':id',
              builder: (context, state) => FrameworkDetailScreen(
                frameworkId: state.pathParameters['id']!,
                frameworkName: state.uri.queryParameters['name'] ?? 'Framework',
              ),
            ),
          ],
        ),
        GoRoute(
          path: '/vulnerabilities',
          builder: (context, state) =>
              VulnerabilityScreen(onManageProfile: () => context.go('/regulatory')),
        ),
        GoRoute(path: '/assets', builder: (context, state) => const AssetsScreen()),
        GoRoute(path: '/regulatory', builder: (context, state) => const RegulatoryProfileScreen()),
        GoRoute(path: '/connectors', builder: (context, state) => const ConnectorsScreen()),
      ],
    ),
  ],
);

class GraphRiskApp extends StatelessWidget {
  const GraphRiskApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp.router(
      title: 'GraphRisk Intelligence Platform',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: kBackground,
        colorScheme: const ColorScheme.dark(primary: kAccent, surface: kSurface),
        fontFamily: 'Inter',
      ),
      routerConfig: _router,
    );
  }
}

class MainShell extends StatelessWidget {
  final String location;
  final VoidCallback onLogout;
  final Widget child;
  const MainShell({super.key, required this.location, required this.onLogout, required this.child});

  int get _selectedIndex {
    final i = _tabPaths.indexWhere((p) => location == p || location.startsWith('$p/'));
    return i < 0 ? 0 : i;
  }

  static const _navItems = [
    NavigationRailDestination(icon: Icon(Icons.dashboard_outlined),    selectedIcon: Icon(Icons.dashboard),    label: Text('Dashboard')),
    NavigationRailDestination(icon: Icon(Icons.bolt_outlined),         selectedIcon: Icon(Icons.bolt),         label: Text('Blast Radius')),
    NavigationRailDestination(icon: Icon(Icons.policy_outlined),       selectedIcon: Icon(Icons.policy),       label: Text('Frameworks')),
    NavigationRailDestination(icon: Icon(Icons.bug_report_outlined),   selectedIcon: Icon(Icons.bug_report),   label: Text('Vulnerabilities')),
    NavigationRailDestination(icon: Icon(Icons.devices_other_outlined),selectedIcon: Icon(Icons.devices_other),label: Text('Assets')),
    NavigationRailDestination(icon: Icon(Icons.gavel_outlined),        selectedIcon: Icon(Icons.gavel),        label: Text('Regulatory')),
    NavigationRailDestination(icon: Icon(Icons.link_outlined),         selectedIcon: Icon(Icons.link),         label: Text('Connectors')),
  ];

  @override
  Widget build(BuildContext context) {
    final extended = MediaQuery.of(context).size.width > 900;
    return Scaffold(
      body: Row(children: [
        NavigationRail(
          backgroundColor: kSurface,
          selectedIndex: _selectedIndex,
          onDestinationSelected: (i) => context.go(_tabPaths[i]),
          extended: extended,
          leading: Padding(
            padding: const EdgeInsets.symmetric(vertical: 24, horizontal: 8),
            child: Column(children: [
              Container(width: 36, height: 36,
                decoration: BoxDecoration(color: kAccent, borderRadius: BorderRadius.circular(8)),
                child: const Icon(Icons.hub, color: Colors.white, size: 20)),
              if (extended) ...[
                const SizedBox(height: 8),
                const Text('GraphRisk', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 14)),
                const SizedBox(height: 2),
                Text(
                  ApiService.graphTenantId ?? '',
                  style: const TextStyle(color: Colors.white38, fontSize: 11),
                ),
              ],
            ]),
          ),
          trailing: Expanded(
            child: Align(
              alignment: Alignment.bottomCenter,
              child: Padding(
                padding: const EdgeInsets.only(bottom: 16),
                child: IconButton(
                  onPressed: onLogout,
                  icon: const Icon(Icons.logout, color: Colors.white38, size: 20),
                  tooltip: 'Log out',
                ),
              ),
            ),
          ),
          selectedIconTheme: const IconThemeData(color: kAccent),
          unselectedIconTheme: const IconThemeData(color: Colors.white38),
          selectedLabelTextStyle: const TextStyle(color: kAccent, fontWeight: FontWeight.bold),
          unselectedLabelTextStyle: const TextStyle(color: Colors.white38),
          indicatorColor: kAccent.withOpacity(0.15),
          destinations: _navItems,
        ),
        const VerticalDivider(width: 1, color: Color(0xFF334155)),
        Expanded(
          child: Column(children: [
            if (ApiService.readOnly)
              _ReadOnlyBanner(onRegister: () {
                onLogout();
                context.go('/login?register=1');
              }),
            Expanded(child: child),
          ]),
        ),
      ]),
    );
  }
}

/// Shown across the top of every screen in the shared public demo, which
/// the server keeps read-only (see api/app/auth/read_only.py) -- so a
/// visitor finds out why saving doesn't work before they try, and how to
/// get an account where it does.
class _ReadOnlyBanner extends StatelessWidget {
  final VoidCallback onRegister;
  const _ReadOnlyBanner({required this.onRegister});

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
      color: kAccent.withOpacity(0.12),
      child: Row(children: [
        const Icon(Icons.visibility_outlined, color: kAccent, size: 16),
        const SizedBox(width: 10),
        const Expanded(
          child: Text(
            "You're exploring the shared demo, which is read-only. "
            'Register your own free account to connect your tools and make changes.',
            style: TextStyle(color: Colors.white70, fontSize: 12),
          ),
        ),
        TextButton(
          onPressed: onRegister,
          child: const Text('Register', style: TextStyle(color: kAccent, fontWeight: FontWeight.w600)),
        ),
      ]),
    );
  }
}
