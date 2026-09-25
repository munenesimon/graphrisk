import 'package:flutter/material.dart';
import 'constants/colors.dart';
import 'screens/dashboard_screen.dart';
import 'screens/blast_radius_screen.dart';
import 'screens/frameworks_screen.dart';
import 'screens/vulnerability_screen.dart';
import 'screens/assets_screen.dart';
import 'screens/regulatory_profile_screen.dart';
import 'screens/connectors_screen.dart';
import 'screens/login_screen.dart';
import 'services/api_service.dart';

void main() {
  runApp(const GraphRiskApp());
}

class GraphRiskApp extends StatelessWidget {
  const GraphRiskApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'GraphRisk Intelligence Platform',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: kBackground,
        colorScheme: const ColorScheme.dark(primary: kAccent, surface: kSurface),
        fontFamily: 'Inter',
      ),
      home: const AuthGate(),
    );
  }
}

/// Shows the login screen until a session exists, then shows the app.
/// A simple StatefulWidget swap is enough here -- no routing package
/// needed for a two-state app (logged out / logged in).
class AuthGate extends StatefulWidget {
  const AuthGate({super.key});

  @override
  State<AuthGate> createState() => _AuthGateState();
}

class _AuthGateState extends State<AuthGate> {
  bool _loggedIn = ApiService.isLoggedIn;
  bool _sessionExpired = false;

  @override
  void initState() {
    super.initState();
    ApiService.onSessionExpired = _handleSessionExpired;
  }

  @override
  void dispose() {
    // Only clear the hook if we're still the one holding it, so we don't
    // clobber a handler set by some later AuthGate instance.
    if (identical(ApiService.onSessionExpired, _handleSessionExpired)) {
      ApiService.onSessionExpired = null;
    }
    super.dispose();
  }

  void _handleAuthenticated() => setState(() {
        _loggedIn = true;
        _sessionExpired = false;
      });

  void _handleLogout() {
    ApiService.logout();
    setState(() {
      _loggedIn = false;
      _sessionExpired = false;
    });
  }

  // Fired by ApiService whenever an authenticated call comes back 401
  // (JWT expired). Bounces straight to the login screen with a banner
  // explaining why, rather than leaving whatever screen was open stuck.
  void _handleSessionExpired() {
    if (!mounted) return;
    setState(() {
      _loggedIn = false;
      _sessionExpired = true;
    });
  }

  @override
  Widget build(BuildContext context) {
    if (!_loggedIn) {
      return LoginScreen(
        onAuthenticated: _handleAuthenticated,
        sessionExpired: _sessionExpired,
      );
    }
    return MainShell(onLogout: _handleLogout);
  }
}

class MainShell extends StatefulWidget {
  final VoidCallback onLogout;
  const MainShell({super.key, required this.onLogout});

  @override
  State<MainShell> createState() => _MainShellState();
}

class _MainShellState extends State<MainShell> {
  int _selectedIndex = 0;

  /// Lets child screens (e.g. DashboardScreen's stat card drill-down)
  /// switch tabs without needing a routing package.
  void _navigateTo(int index) => setState(() => _selectedIndex = index);

  // Index of the Regulatory Profile tab -- kept as a named constant since
  // both BlastRadiusScreen and VulnerabilityScreen jump straight to it from
  // their "no regulatory profile set" hints.
  static const _regulatoryProfileIndex = 5;

  List<Widget> get _screens => [
    DashboardScreen(onNavigate: _navigateTo),
    BlastRadiusScreen(onManageProfile: () => _navigateTo(_regulatoryProfileIndex)),
    const FrameworksScreen(),
    VulnerabilityScreen(onManageProfile: () => _navigateTo(_regulatoryProfileIndex)),
    const AssetsScreen(),
    const RegulatoryProfileScreen(),
    const ConnectorsScreen(),
  ];

  final _navItems = const [
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
          onDestinationSelected: (i) => setState(() => _selectedIndex = i),
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
                  onPressed: widget.onLogout,
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
        Expanded(child: _screens[_selectedIndex]),
      ]),
    );
  }
}
