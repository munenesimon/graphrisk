/// The asset page's data: GET /assets/{id}/profile. Device detail comes
/// from the universal profile (api/app/connectors/profile.py) -- sections
/// any connector can fill, each field labelled with the connector it came
/// from -- so nothing here is specific to one vendor.
class AssetProfile {
  final Map<String, dynamic> asset;
  final Map<String, ProfileSection> sections;
  final List<String> hiddenFields;
  final bool canViewSensitive;
  /// section -> names of connectors that *could* fill it.
  final Map<String, List<String>> capabilities;
  final List<VulnerablePackage> fixFirst;
  final int vulnerabilityTotal;
  final List<Map<String, dynamic>> vulnerabilities;
  final List<Map<String, dynamic>> risks;
  /// Other names this device was reported under, merged in because they
  /// share a serial number, MAC address or cloud instance id.
  final List<String> alsoKnownAs;
  /// Assets that only share a hostname -- flagged, not merged: {id, name, reason}.
  final List<Map<String, dynamic>> possibleDuplicates;

  AssetProfile({
    required this.asset,
    required this.sections,
    required this.hiddenFields,
    required this.canViewSensitive,
    required this.capabilities,
    required this.fixFirst,
    required this.vulnerabilityTotal,
    required this.vulnerabilities,
    required this.risks,
    this.alsoKnownAs = const [],
    this.possibleDuplicates = const [],
  });

  factory AssetProfile.fromJson(Map<String, dynamic> j) {
    final rawProfile = (j['profile'] as Map?)?.cast<String, dynamic>() ?? {};
    final rawCaps = (j['capabilities'] as Map?)?.cast<String, dynamic>() ?? {};
    final vulns = (j['vulnerabilities'] as Map?)?.cast<String, dynamic>() ?? {};
    return AssetProfile(
      asset: (j['asset'] as Map?)?.cast<String, dynamic>() ?? {},
      sections: rawProfile.map((k, v) =>
          MapEntry(k, ProfileSection.fromJson((v as Map).cast<String, dynamic>()))),
      hiddenFields: ((j['hidden_fields'] as List?) ?? []).map((e) => e.toString()).toList(),
      canViewSensitive: j['can_view_sensitive'] == true,
      capabilities: rawCaps.map((k, v) =>
          MapEntry(k, ((v as List?) ?? []).map((e) => e.toString()).toList())),
      fixFirst: ((j['fix_first'] as List?) ?? [])
          .map((e) => VulnerablePackage.fromJson((e as Map).cast<String, dynamic>()))
          .toList(),
      vulnerabilityTotal: (vulns['total'] as num?)?.toInt() ?? 0,
      vulnerabilities: ((vulns['items'] as List?) ?? [])
          .map((e) => (e as Map).cast<String, dynamic>())
          .toList(),
      risks: ((j['risks'] as List?) ?? []).map((e) => (e as Map).cast<String, dynamic>()).toList(),
      alsoKnownAs: ((j['also_known_as'] as List?) ?? []).map((e) => e.toString()).toList(),
      possibleDuplicates: ((j['possible_duplicates'] as List?) ?? [])
          .map((e) => (e as Map).cast<String, dynamic>())
          .toList(),
    );
  }
}

class ProfileSection {
  final Map<String, dynamic> fields;
  /// field -> connector id it came from.
  final Map<String, String> fieldSources;
  final List<ProfileSource> sources;

  ProfileSection({required this.fields, required this.fieldSources, required this.sources});

  factory ProfileSection.fromJson(Map<String, dynamic> j) => ProfileSection(
        fields: (j['fields'] as Map?)?.cast<String, dynamic>() ?? {},
        fieldSources: ((j['field_sources'] as Map?) ?? {})
            .map((k, v) => MapEntry(k.toString(), v.toString())),
        sources: ((j['sources'] as List?) ?? [])
            .map((e) => ProfileSource.fromJson((e as Map).cast<String, dynamic>()))
            .toList(),
      );
}

class ProfileSource {
  final String source;
  final String name;
  final String? collectedAt;
  ProfileSource({required this.source, required this.name, this.collectedAt});
  factory ProfileSource.fromJson(Map<String, dynamic> j) => ProfileSource(
        source: j['source']?.toString() ?? '',
        name: j['name']?.toString() ?? j['source']?.toString() ?? '',
        collectedAt: j['collected_at']?.toString(),
      );
}

class VulnerablePackage {
  final String name;
  final String? version;
  final int cveCount;
  final String? maxSeverity;
  final bool ransomware;
  final double maxCvss;
  final List<Map<String, dynamic>> cves;

  VulnerablePackage({
    required this.name,
    this.version,
    required this.cveCount,
    this.maxSeverity,
    required this.ransomware,
    required this.maxCvss,
    required this.cves,
  });

  factory VulnerablePackage.fromJson(Map<String, dynamic> j) => VulnerablePackage(
        name: j['name']?.toString() ?? '',
        version: j['version']?.toString(),
        cveCount: (j['cve_count'] as num?)?.toInt() ?? 0,
        maxSeverity: j['max_severity']?.toString(),
        ransomware: j['ransomware'] == true,
        maxCvss: (j['max_cvss'] as num?)?.toDouble() ?? 0.0,
        cves: ((j['cves'] as List?) ?? []).map((e) => (e as Map).cast<String, dynamic>()).toList(),
      );
}
