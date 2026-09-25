
/// Client-side metadata for connector adapters.
///
/// GET /api/v1/connectors/ only returns connector ids and a check_id ->
/// connector_id map (see api/app/api/v1/connectors.py's list_connectors) --
/// it doesn't expose CONNECTOR_NAME, REQUIRED_CONFIG_KEYS, or the auth
/// pattern each vendor uses, since those live on the Python adapter classes
/// in api/app/connectors/adapters/, not in anything JSON-serialised back to
/// a client. Same reasoning as constants/frameworks.dart: that display
/// metadata is hand-kept here, one place, and must be kept in sync by hand
/// whenever an adapter's REQUIRED_CONFIG_KEYS changes or a new adapter is
/// registered in connectors.py / registry.py.
///
/// A connector id GET /connectors/ returns that isn't in [kConnectorSpecs]
/// still renders -- connectorSpecFor() falls back to the raw id with no
/// known fields -- it just can't offer a credentials form until this file
/// is updated to match the new adapter.
library;

class ConnectorField {
  final String key;
  final String label;
  final bool secret;
  final String? hint;
  const ConnectorField(this.key, this.label, {this.secret = false, this.hint});
}

class ConnectorSpec {
  final String id;
  final String name;
  final String authPattern;
  final List<ConnectorField> fields;
  // Matches the README connector table's "Validation" column: false means
  // this adapter has only been offline/structurally verified, not run
  // against a live vendor instance yet (e.g. Wazuh, pending a self-hosted
  // instance). Purely informational -- doesn't gate whether it can be run.
  final bool liveVerified;

  const ConnectorSpec({
    required this.id,
    required this.name,
    required this.authPattern,
    required this.fields,
    this.liveVerified = true,
  });
}

const List<ConnectorSpec> kConnectorSpecs = [
  ConnectorSpec(
    id: 'mock',
    name: 'Mock Connector (Testing)',
    authPattern: 'None',
    fields: [],
  ),
  ConnectorSpec(
    id: 'entra_id',
    name: 'Microsoft Entra ID',
    authPattern: 'OAuth 2.0 client credentials',
    fields: [
      ConnectorField('azure_tenant_id', 'Azure tenant ID'),
      ConnectorField('client_id', 'Client ID'),
      ConnectorField('client_secret', 'Client secret', secret: true),
    ],
  ),
  ConnectorSpec(
    id: 'aws',
    name: 'AWS Security Posture',
    authPattern: 'SDK-managed IAM keys (boto3)',
    fields: [
      ConnectorField('aws_access_key_id', 'Access key ID'),
      ConnectorField('aws_secret_access_key', 'Secret access key', secret: true),
    ],
  ),
  ConnectorSpec(
    id: 'okta',
    name: 'Okta',
    authPattern: 'Static API key header',
    fields: [
      ConnectorField('org_url', 'Org URL', hint: 'https://your-org.okta.com'),
      ConnectorField('api_token', 'API token', secret: true),
    ],
  ),
  ConnectorSpec(
    id: 'wazuh',
    name: 'Wazuh',
    authPattern: 'HTTP Basic → session JWT (self-hosted SIEM/XDR)',
    fields: [
      ConnectorField('api_url', 'Manager API URL', hint: 'https://your-manager:55000'),
      ConnectorField('username', 'Username'),
      ConnectorField('password', 'Password', secret: true),
    ],
    liveVerified: false,
  ),
];

ConnectorSpec connectorSpecFor(String id) => kConnectorSpecs.firstWhere(
      (c) => c.id == id,
      orElse: () => ConnectorSpec(id: id, name: id, authPattern: 'Unknown', fields: const []),
    );

/// Turns a snake_case check_id like "dormant_accounts" into "Dormant accounts".
String humanizeCheckId(String checkId) {
  final s = checkId.replaceAll('_', ' ');
  if (s.isEmpty) return s;
  return s[0].toUpperCase() + s.substring(1);
}
