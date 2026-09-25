
/// Human-readable names and short descriptions for framework slugs, keyed by
/// Framework.name as GraphRisk stores it -- which is NOT always the same as
/// the framework's `id` (e.g. NIST CSF is id "NIST_CSF_2", name "NIST_CSF").
/// Blast-radius responses and the crosswalk's `mapped_framework_controls`
/// strings both use `name`, so this is the single place new frameworks get
/// a display name/description without touching the screens that use them.
const Map<String, String> kFrameworkDisplayNames = {
  'NIST_800_53': 'NIST SP 800-53 Rev5',
  'NIST_CSF': 'NIST CSF 2.0',
  // Verified live against GET /frameworks/ -- these two are the actual
  // Framework.name slugs in the graph, not the "CIS_V8"/"PCI_DSS_4" guess
  // the pre-existing blast-radius switch statement used (which never
  // actually matched either, so it silently fell through to its default
  // case before this file existed).
  'CIS_Controls': 'CIS Controls v8.1',
  'PCI_DSS': 'PCI DSS v4.0.1',
  'KENYA_DPA': 'Kenya Data Protection Act 2019',
  'CBK_CYBER_BANKS': 'CBK Cybersecurity Guidance (Banks, 2017)',
  'CBK_CYBER_PSP': 'CBK Cybersecurity Guideline (PSPs, 2019)',
  'KENYA_CMCA_CII': 'CMCA Critical Information Infrastructure Regs 2024',
};

const Map<String, String> kFrameworkDescriptions = {
  'NIST_800_53': 'NIST SP 800-53 Rev5 — Federal security and privacy controls. '
      'Gaps here affect your compliance posture with US government standards.',
  'NIST_CSF': 'NIST Cybersecurity Framework 2.0 — The industry-standard risk '
      'management framework used by organizations of all sizes.',
  'CIS_Controls': 'CIS Controls v8.1 — Prioritized security best practices. '
      'Control gaps here affect your Implementation Group coverage.',
  'PCI_DSS': 'PCI DSS v4.0.1 — Required for organizations handling payment card data. '
      'Gaps here carry financial and contractual penalties.',
  'KENYA_DPA': "Kenya's Data Protection Act 2019, enforced by the Office of the Data "
      'Protection Commissioner. Gaps here can mean lawful-processing and breach-notice '
      'obligations are unmet.',
  'CBK_CYBER_BANKS': 'Central Bank of Kenya cybersecurity guidance for banks (2017). '
      "Gaps here affect a regulated bank's supervisory standing with the CBK.",
  'CBK_CYBER_PSP': 'Central Bank of Kenya cybersecurity guideline for payment service '
      "providers (2019). Gaps here affect a PSP's licence conditions.",
  'KENYA_CMCA_CII': "Kenya's Critical Information Infrastructure regulations under the "
      'Computer Misuse and Cybercrimes Act (2024). Applies to designated CII operators.',
};

String frameworkDisplayName(String slug) => kFrameworkDisplayNames[slug] ?? slug;

String frameworkDescription(String slug) =>
    kFrameworkDescriptions[slug] ??
    'This framework has requirements linked to the affected control. '
        'Review the specific control references below.';

/// Voluntary standards/benchmarks rather than binding regulations -- kept
/// as `name` values (not `id`s, which aren't guaranteed to match the slug;
/// see the header note above) so the Regulatory Profile screen can offer
/// every OTHER framework returned by GET /frameworks/ as something a tenant
/// might declare itself subject to, without needing the server to expose a
/// `category` field on that endpoint.
const Set<String> kStandardFrameworkNames = {
  'NIST_800_53',
  'NIST_CSF',
  'CIS_Controls',
  'PCI_DSS',
};
