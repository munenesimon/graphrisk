"""
GraphRisk -- CPE (Common Platform Enumeration) helper.

NVD's CVE API describes affected products as CPE 2.3 URIs nested inside
cve.configurations[].nodes[].cpeMatch[], e.g.:
    "cpe:2.3:a:sonicwall:sma1000:*:*:*:*:*:*:*:*"
Fields in order: cpe / version / part / vendor / product / version /
update / edition / language / sw_edition / target_sw / target_hw / other.

CISA KEV, by contrast, already gives vendor/product as plain structured
fields (vendorProject/product) -- no CPE parsing needed there. This
module exists only to give NVD-sourced Vulnerability nodes the same kind
of structured vendor/product data KEV nodes get for free, so
vulnerability -> asset correlation can match on real fields instead of
guessing against free-text titles/descriptions.
"""


def extract_cpe_pairs(cve: dict, max_pairs: int = 20) -> tuple[str, str, list[str]]:
    """
    Pull every "vulnerable" CPE match out of an NVD CVE item and return:
      - primary_vendor, primary_product: the first pair found (mirrors the
        v.vendor / v.product fields CISA KEV nodes already carry)
      - cpe_pairs: a deduplicated list of "vendor product" strings
        (lowercased, underscores turned into spaces), one per affected
        product on the CVE -- a single CVE can affect several products
        from the same or different vendors. Used for correlation matching.

    A CPE URI that can't be parsed (missing/malformed criteria) is skipped
    rather than raising -- one bad entry shouldn't drop the whole CVE.
    """
    seen: list[tuple[str, str]] = []

    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                if match.get("vulnerable") is False:
                    continue
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                # cpe : 2.3 : part : vendor : product : version : ...
                if len(parts) < 5 or parts[0] != "cpe":
                    continue
                vendor = parts[3].replace("_", " ").strip().lower()
                product = parts[4].replace("_", " ").strip().lower()
                if not vendor or vendor == "*" or not product or product == "*":
                    continue
                pair = (vendor, product)
                if pair not in seen:
                    seen.append(pair)
                if len(seen) >= max_pairs:
                    break
            if len(seen) >= max_pairs:
                break
        if len(seen) >= max_pairs:
            break

    if not seen:
        return "", "", []

    primary_vendor, primary_product = seen[0]
    cpe_pairs = [f"{v} {p}" for v, p in seen]
    return primary_vendor, primary_product, cpe_pairs
