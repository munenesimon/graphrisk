import 'dart:convert';
import 'package:http/http.dart' as http;
import '../models/dashboard.dart';

class ApiService {
  static final _client = http.Client();
  static const _base   = 'http://localhost:8000/api/v1';
  static const _tenant = 'demo';

  static Future<Map<String, dynamic>> _get(String path) async {
    final uri = Uri.parse(_base + path);
    final res = await _client.get(uri);
    if (res.statusCode == 200) {
      return json.decode(res.body) as Map<String, dynamic>;
    }
    throw Exception('API error ' + res.statusCode.toString() + ': ' + path);
  }

  static Future<DashboardSummary> getDashboardSummary() async {
    final data = await _get('/dashboard/summary?tenant_id=' + _tenant);
    return DashboardSummary.fromJson(data);
  }

  static Future<GraphStats> getGraphStats() async {
    final data = await _get('/dashboard/graph-stats');
    return GraphStats.fromJson(data);
  }

  static Future<BlastRadius> getBlastRadiusControl(String controlId) async {
    final data = await _get('/graph/blast-radius/control/' + controlId + '?tenant_id=' + _tenant);
    return BlastRadius.fromJson(data);
  }

  static Future<Map<String, dynamic>> getBlastRadiusTechnique(String techniqueId) async {
    return await _get('/graph/blast-radius/technique/' + techniqueId);
  }

  static Future<List<dynamic>> getAssets() async {
    final data = await _get('/assets/?tenant_id=' + _tenant);
    return data['assets'] as List? ?? [];
  }

  static Future<List<dynamic>> getRisks() async {
    final data = await _get('/risks/?tenant_id=' + _tenant);
    return data['risks'] as List? ?? [];
  }

  static Future<List<dynamic>> getControls() async {
    final data = await _get('/controls/?tenant_id=' + _tenant);
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
    return await _get('/dashboard/framework-coverage?tenant_id=' + _tenant);
  }
}