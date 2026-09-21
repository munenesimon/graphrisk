import 'dart:convert';
import 'package:http/http.dart' as http;
import '../models/dashboard.dart';

/// Thrown when a request fails because there is no valid session.
/// Screens can catch this specifically to redirect to the login screen.
class AuthException implements Exception {
  final String message;
  AuthException(this.message);
  @override
  String toString() => message;
}

class ApiService {
  static final _client = http.Client();
  static const _base   = 'http://localhost:8000/api/v1';

  // The API key gates "is this a legitimate GraphRisk client at all" --
  // it is not a secret in the sense of protecting tenant data (JWT does
  // that), so embedding it in the built app is an acceptable trade-off
  // for a demo deployment. Swap this for a build-time --dart-define in a
  // production build if the key ever needs to differ per environment.
  static const _apiKey = 'XzdinqqrWCGAB_fFUQwBuRCyTy9L6N5APD7mMNSE4eA';

  // In-memory session state. Simple and sufficient for a demo: the token
  // is cleared on app restart, which just means the user logs in again --
  // no stale-session bugs to worry about. Swap for flutter_secure_storage
  // if "stay logged in across restarts" becomes a real requirement.
  static String? _token;
  static String? _tenantName;
  static String? _graphTenantId;
  static String? _role;

  static bool get isLoggedIn => _token != null;
  static String? get tenantName => _tenantName;
  static String? get graphTenantId => _graphTenantId;
  static String? get role => _role;

  static void logout() {
    _token = null;
    _tenantName = null;
    _graphTenantId = null;
    _role = null;
  }

  static Map<String, String> get _authHeaders => {
    'X-API-Key': _apiKey,
    'Content-Type': 'application/json',
    if (_token != null) 'Authorization': 'Bearer $_token',
  };

  static Future<Map<String, dynamic>> _get(String path) async {
    final uri = Uri.parse(_base + path);
    final res = await _client.get(uri, headers: _authHeaders);
    if (res.statusCode == 200) {
      return json.decode(res.body) as Map<String, dynamic>;
    }
    if (res.statusCode == 401) {
      logout();
      throw AuthException('Session expired. Please log in again.');
    }
    throw Exception('API error ${res.statusCode}: $path');
  }

  static Future<Map<String, dynamic>> _post(String path, Map<String, dynamic> body) async {
    final uri = Uri.parse(_base + path);
    final res = await _client.post(uri, headers: _authHeaders, body: json.encode(body));
    if (res.statusCode == 200 || res.statusCode == 201) {
      return json.decode(res.body) as Map<String, dynamic>;
    }
    if (res.statusCode == 401) {
      final detail = _extractDetail(res.body);
      throw AuthException(detail ?? 'Invalid email or password.');
    }
    final detail = _extractDetail(res.body);
    throw Exception(detail ?? 'API error ${res.statusCode}: $path');
  }

  static String? _extractDetail(String body) {
    try {
      final decoded = json.decode(body);
      if (decoded is Map && decoded['detail'] is String) return decoded['detail'] as String;
    } catch (_) {}
    return null;
  }

  // ── Auth ────────────────────────────────────────────────────────────────
  static Future<void> login(String email, String password) async {
    final data = await _post('/auth/login', {'email': email, 'password': password});
    _applySession(data);
  }

  static Future<void> register(String email, String password, String tenantName) async {
    final data = await _post('/auth/register', {
      'email': email,
      'password': password,
      'tenant_name': tenantName,
    });
    _applySession(data);
  }

  static void _applySession(Map<String, dynamic> data) {
    _token         = data['access_token'] as String;
    _graphTenantId = data['graph_tenant_id'] as String;
    _role          = data['role'] as String;
    _tenantName    = _graphTenantId; // display name; refine later if the API returns the friendly tenant name too
  }

  // ── Dashboard / Graph (all tenant-scoped calls now carry NO query
  //    parameter -- the server derives the tenant entirely from the JWT) ──
  static Future<DashboardSummary> getDashboardSummary() async {
    final data = await _get('/dashboard/summary');
    return DashboardSummary.fromJson(data);
  }

  static Future<GraphStats> getGraphStats() async {
    final data = await _get('/dashboard/graph-stats');
    return GraphStats.fromJson(data);
  }

  static Future<BlastRadius> getBlastRadiusControl(String controlId) async {
    final data = await _get('/graph/blast-radius/control/$controlId');
    return BlastRadius.fromJson(data);
  }

  static Future<Map<String, dynamic>> getBlastRadiusTechnique(String techniqueId) async {
    return await _get('/graph/blast-radius/technique/$techniqueId');
  }

  static Future<List<dynamic>> getAssets() async {
    final data = await _get('/assets/');
    return data['assets'] as List? ?? [];
  }

  static Future<List<dynamic>> getRisks() async {
    final data = await _get('/risks/');
    return data['risks'] as List? ?? [];
  }

  static Future<List<dynamic>> getControls() async {
    final data = await _get('/controls/');
    return data['controls'] as List? ?? [];
  }

  static Future<List<dynamic>> getFrameworks() async {
    final data = await _get('/frameworks/');
    return data['frameworks'] as List? ?? [];
  }

  static Future<Map<String, dynamic>> getVulnerabilityIntel() async {
    return await _get('/dashboard/vulnerability-intel');
  }

  static Future<Map<String, dynamic>> getFrameworkCoverage() async {
    return await _get('/dashboard/framework-coverage');
  }
}
