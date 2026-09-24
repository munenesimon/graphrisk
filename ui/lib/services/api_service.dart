import 'dart:convert';
import 'package:flutter/foundation.dart' show VoidCallback;
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

  // Defaults to local dev so `flutter run` needs no extra flags. The
  // Firebase production build MUST override this with
  // --dart-define=GRAPHRISK_API_BASE_URL=https://graphrisk.onrender.com/api/v1
  // -- without it, the deployed site would call localhost:8000 for every
  // request, which doesn't exist for anyone but the developer.
  static const _base = String.fromEnvironment(
    'GRAPHRISK_API_BASE_URL',
    defaultValue: 'http://localhost:8000/api/v1',
  );

  // The API key gates "is this a legitimate GraphRisk client at all" --
  // it is not a secret in the sense of protecting tenant data (JWT does
  // that), so embedding it in the built app is an acceptable trade-off
  // for a demo deployment. Swap this for a build-time --dart-define in a
  // production build if the key ever needs to differ per environment.
  static const _apiKey = String.fromEnvironment('GRAPHRISK_API_KEY', defaultValue: '');

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

  // Registered by the app shell (main.dart's AuthGate) so that any
  // authenticated request hitting a 401 -- most commonly the JWT
  // expiring after access_token_expire_minutes (60 min by default) --
  // bounces the user straight back to the login screen instead of
  // leaving them stuck on a screen that quietly stopped working. This is
  // NOT silent token refresh (there's no refresh-token endpoint on the
  // backend yet); it just makes the expiry loud and recoverable instead
  // of a dead end.
  static VoidCallback? onSessionExpired;

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
      onSessionExpired?.call();
      throw AuthException('Session expired. Please log in again.');
    }
    // Extract the server's `detail` where there is one (e.g. vulnerability-impact's
    // "CVE-... is not in GraphRisk's vulnerability data") instead of a bare status code.
    final detail = _extractDetail(res.body);
    throw Exception(detail ?? 'API error ${res.statusCode}: $path');
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

  static Future<Map<String, dynamic>> _put(String path, Map<String, dynamic> body) async {
    final uri = Uri.parse(_base + path);
    final res = await _client.put(uri, headers: _authHeaders, body: json.encode(body));
    if (res.statusCode == 200 || res.statusCode == 201) {
      return json.decode(res.body) as Map<String, dynamic>;
    }
    if (res.statusCode == 401) {
      logout();
      onSessionExpired?.call();
      throw AuthException('Session expired. Please log in again.');
    }
    final detail = _extractDetail(res.body);
    throw Exception(detail ?? 'API error ${res.statusCode}: $path');
  }

  static Future<Map<String, dynamic>> _patch(String path, Map<String, dynamic> body) async {
    final uri = Uri.parse(_base + path);
    final res = await _client.patch(uri, headers: _authHeaders, body: json.encode(body));
    if (res.statusCode == 200 || res.statusCode == 201) {
      return json.decode(res.body) as Map<String, dynamic>;
    }
    if (res.statusCode == 401) {
      logout();
      onSessionExpired?.call();
      throw AuthException('Session expired. Please log in again.');
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

  // `scope`: "all" (every framework this control supports, grouped) or
  // "applicable" (standards plus only the regulations in the tenant's
  // regulatory profile) -- mirrors blast_radius.py's `scope` query param.
  static Future<BlastRadius> getBlastRadiusControl(String controlId, {String scope = 'all'}) async {
    final data = await _get('/graph/blast-radius/control/$controlId?scope=$scope');
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

  // ── Assets (typed) ─────────────────────────────────────────────────────
  static Future<List<Asset>> getAssetsFull() async {
    final data = await _get('/assets/');
    final list = data['assets'] as List? ?? [];
    return list.map((a) => Asset.fromJson(a as Map<String, dynamic>)).toList();
  }

  static Future<void> setAssetDataClassification(String assetId, bool holdsPersonalData) async {
    await _patch('/assets/$assetId/data-classification', {
      'holds_personal_data': holdsPersonalData,
    });
  }

  // ── Regulatory profile ──────────────────────────────────────────────────
  // Which frameworks this tenant is legally subject to -- decides which
  // notification clocks show up in blast-radius and vulnerability-impact.
  static Future<RegulatoryProfile> getRegulatoryProfile() async {
    final data = await _get('/organisation/regulatory-profile');
    return RegulatoryProfile.fromJson(data);
  }

  // Replaces the profile wholesale -- send the full selected list each time.
  static Future<RegulatoryProfile> setRegulatoryProfile(List<String> frameworkIds, List<String> qualifiers) async {
    final data = await _put('/organisation/regulatory-profile', {
      'frameworks': frameworkIds,
      'qualifiers': qualifiers,
    });
    return RegulatoryProfile.fromJson(data);
  }

  // ── Vulnerability impact ────────────────────────────────────────────────
  // "This CVE was published today -- what does it mean for us?"
  static Future<VulnerabilityImpact> getVulnerabilityImpact(String cveId) async {
    final data = await _get('/graph/vulnerability-impact/${Uri.encodeComponent(cveId.trim())}');
    return VulnerabilityImpact.fromJson(data);
  }
}
