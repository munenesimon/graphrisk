
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
  'ISO_27001': 'ISO/IEC 27001:2022 (readiness)',
  'SOC2_TSC': 'SOC 2 readiness (Trust Services Criteria)',
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
  'ISO_27001': 'ISO/IEC 27001:2022 — the international information security management '
      'standard. Voluntary; GraphRisk shows readiness, not certification.',
  'SOC2_TSC': 'AICPA Trust Services Criteria behind SOC 2 reports — often requested by US '
      'customers. Voluntary; GraphRisk shows readiness only.',
};

String frameworkDisplayName(String slug) => kFrameworkDisplayNames[slug] ?? slug;

/// Compact names for tight spots like graph chips, where the full display
/// name wouldn't fit (the item's detail still shows the full name).
const Map<String, String> kFrameworkShortNames = {
  'NIST_800_53': 'NIST 800-53',
  'NIST_CSF': 'NIST CSF',
  'CIS_Controls': 'CIS v8.1',
  'PCI_DSS': 'PCI DSS',
  'KENYA_DPA': 'Kenya DPA',
  'CBK_CYBER_BANKS': 'CBK Banks',
  'CBK_CYBER_PSP': 'CBK PSPs',
  'KENYA_CMCA_CII': 'CMCA CII',
  'ISO_27001': 'ISO 27001',
  'SOC2_TSC': 'SOC 2',
};

String frameworkShortName(String slug) =>
    kFrameworkShortNames[slug] ?? frameworkDisplayName(slug);

/// "KENYA_DPA DPR-DETECTION" -> "Kenya DPA DPR-DETECTION": a crosswalk
/// requirement string ("<framework name> <reference>") with a readable
/// framework prefix.
String readableRequirement(String raw, {bool short = true}) {
  final i = raw.indexOf(' ');
  if (i <= 0) return raw;
  final slug = raw.substring(0, i);
  final name = short ? frameworkShortName(slug) : frameworkDisplayName(slug);
  return '$name ${raw.substring(i + 1)}';
}

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
  'ISO_27001',
  'SOC2_TSC',
};

/// Notes shown at the top of a framework's requirements page. ISO/IEC 27001
/// is copyrighted: GraphRisk holds only reference numbers and its own
/// summaries, and must never imply certification.
const Map<String, String> kFrameworkNotices = {
  'ISO_27001': 'Readiness view, not certification -- only an accredited certification body can '
      'certify you. GraphRisk shows ISO/IEC 27001:2022 reference numbers with its own short '
      'summaries; use your licensed copy of the standard (from ISO or the Kenya Bureau of '
      'Standards) for the actual requirements. Where it overlaps Kenyan law, the law prevails. '
      'Requirements you mark "Not applicable", with the reason, form your Statement of Applicability.',
  'SOC2_TSC': 'Readiness view only -- SOC 2 is a report that only a CPA firm can issue; GraphRisk '
      'never makes you "SOC 2 certified" or "compliant". GraphRisk shows the AICPA Trust Services '
      'Criteria identifiers with its own short summaries; use the AICPA\'s published criteria for '
      'the actual text. Security (CC) applies to every report; mark the availability, '
      'confidentiality, processing-integrity or privacy criteria outside your report\'s scope '
      '"Not applicable". For privacy, the Kenya Data Protection Act is the binding law.',
};
