"""
NVD API 2.0 Integration Module
Fetches live CVE data from the National Vulnerability Database.
API Docs: https://nvd.nist.gov/developers/vulnerabilities
"""

import urllib.request
import urllib.parse
import json
import time

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Optional: set your NVD API key here or via environment variable
# With key: 50 requests per 30 seconds
# Without key: 5 requests per 30 seconds
_last_request_time = 0
_MIN_INTERVAL = 6  # seconds between requests (safe without API key)


def _rate_limit():
    """Enforce rate limiting for NVD API."""
    global _last_request_time
    now = time.time()
    elapsed = now - _last_request_time
    if elapsed < _MIN_INTERVAL:
        time.sleep(_MIN_INTERVAL - elapsed)
    _last_request_time = time.time()


def _nvd_request(params):
    """Make a rate-limited request to the NVD API 2.0."""
    _rate_limit()

    query_string = urllib.parse.urlencode(params)
    url = f"{NVD_API_BASE}?{query_string}"

    req = urllib.request.Request(url)
    req.add_header("User-Agent", "DockSec-Scanner/1.0")

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as e:
        print(f"⚠️  NVD API request failed: {e}")
        return None


def _extract_severity(cve_item):
    """Extract severity and CVSS score from NVD CVE item."""
    metrics = cve_item.get("metrics", {})

    # Try CVSS v3.1 first, then v3.0, then v2
    for key in ["cvssMetricV31", "cvssMetricV30"]:
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            cvss_data = m.get("cvssData", {})
            return {
                "severity": cvss_data.get("baseSeverity", "UNKNOWN").upper(),
                "cvss_score": cvss_data.get("baseScore", 0.0)
            }

    if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        m = metrics["cvssMetricV2"][0]
        score = m.get("cvssData", {}).get("baseScore", 0.0)
        # Map v2 score to severity
        if score >= 9.0:
            sev = "CRITICAL"
        elif score >= 7.0:
            sev = "HIGH"
        elif score >= 4.0:
            sev = "MEDIUM"
        else:
            sev = "LOW"
        return {"severity": sev, "cvss_score": score}

    return {"severity": "UNKNOWN", "cvss_score": 0.0}


def _normalize_cve(vuln):
    """Convert NVD API CVE format to DockSec internal format."""
    cve_item = vuln.get("cve", {})
    cve_id = cve_item.get("id", "UNKNOWN")

    # Get description (English preferred)
    descriptions = cve_item.get("descriptions", [])
    description = "No description available"
    for d in descriptions:
        if d.get("lang") == "en":
            description = d.get("value", description)
            break

    severity_info = _extract_severity(cve_item)

    return {
        "cve_id": cve_id,
        "severity": severity_info["severity"],
        "cvss_score": severity_info["cvss_score"],
        "description": description[:300],  # Truncate long descriptions
        "source": "NVD_LIVE"
    }


def fetch_cves_by_keyword(keyword, max_results=20):
    """
    Search NVD for CVEs matching a keyword (e.g., package name).
    Returns a list of normalized CVE dictionaries.
    """
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": min(max_results, 50),
        "noRejected": ""
    }

    data = _nvd_request(params)
    if not data:
        return []

    vulnerabilities = data.get("vulnerabilities", [])
    results = []

    for vuln in vulnerabilities:
        normalized = _normalize_cve(vuln)
        if normalized["severity"] != "UNKNOWN":
            results.append(normalized)

    return results


def fetch_cve_by_id(cve_id):
    """
    Fetch details for a specific CVE ID (e.g., 'CVE-2023-38545').
    Returns a single normalized CVE dict or None.
    """
    params = {"cveId": cve_id}

    data = _nvd_request(params)
    if not data:
        return None

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return None

    return _normalize_cve(vulnerabilities[0])


def fetch_recent_critical_cves(days=30, max_results=20):
    """
    Fetch recently published CRITICAL severity CVEs.
    Useful for awareness dashboard.
    """
    from datetime import datetime, timedelta

    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
        "cvssV3Severity": "CRITICAL",
        "resultsPerPage": min(max_results, 50),
        "noRejected": ""
    }

    data = _nvd_request(params)
    if not data:
        return []

    vulnerabilities = data.get("vulnerabilities", [])
    return [_normalize_cve(v) for v in vulnerabilities]
