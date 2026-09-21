import 'package:flutter/material.dart';
import 'constants/colors.dart';
import 'screens/dashboard_screen.dart';
import 'screens/blast_radius_screen.dart';
import 'screens/frameworks_screen.dart';
import 'screens/vulnerability_screen.dart';
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

  void _handleAuthenticated() => setState(() => _loggedIn = true);

  void _handleLogout() {
    ApiService.logout();
    setState(() => _loggedIn = false);
  }

  @override
  Widget build(BuildContext context) {
    if (!_loggedIn) {
      return LoginScreen(onAuthenticated: _handleAuthenticated);
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

  final _screens = const [
    DashboardScreen(),
    BlastRadiusScreen(),
    FrameworksScreen(),
    VulnerabilityScreen(),
  ];

  final _navItems = const [
    NavigationRailDestination(icon: Icon(Icons.dashboard_outlined),    selectedIcon: Icon(Icons.dashboard),    label: Text('Dashboard')),
    NavigationRailDestination(icon: Icon(Icons.bolt_outlined),         selectedIcon: Icon(Icons.bolt),         label: Text('Blast Radius')),
    NavigationRailDestination(icon: Icon(Icons.policy_outlined),       selectedIcon: Icon(Icons.policy),       label: Text('Frameworks')),
    NavigationRailDestination(icon: Icon(Icons.bug_report_outlined),   selectedIcon: Icon(Icons.bug_report),   label: Text('Vulnerabilities')),
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
