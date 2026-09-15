
import 'package:flutter/material.dart';
import 'constants/colors.dart';
import 'screens/dashboard_screen.dart';
import 'screens/blast_radius_screen.dart';
import 'screens/frameworks_screen.dart';
import 'screens/vulnerability_screen.dart';

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
      home: const MainShell(),
    );
  }
}

class MainShell extends StatefulWidget {
  const MainShell({super.key});

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
    return Scaffold(
      body: Row(children: [
        NavigationRail(
          backgroundColor: kSurface,
          selectedIndex: _selectedIndex,
          onDestinationSelected: (i) => setState(() => _selectedIndex = i),
          extended: MediaQuery.of(context).size.width > 900,
          leading: Padding(
            padding: const EdgeInsets.symmetric(vertical: 24, horizontal: 8),
            child: Column(children: [
              Container(width: 36, height: 36,
                decoration: BoxDecoration(color: kAccent, borderRadius: BorderRadius.circular(8)),
                child: const Icon(Icons.hub, color: Colors.white, size: 20)),
              if (MediaQuery.of(context).size.width > 900) ...[
                const SizedBox(height: 8),
                const Text('GraphRisk', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 14)),
              ],
            ]),
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
