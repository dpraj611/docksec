import json
import os
from packaging.version import parse as parse_version


def load_cve_data():
    data_path = os.path.join("data", "demo_cves.json")
    with open(data_path, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_version(version):
    """
    Normalize distro-specific versions by trimming metadata.
    Example: 8.14.1-2+deb13u2 -> 8.14.1
    Example: 1.29.7-1~trixie  -> 1.29.7
    Example: 1.35+dfsg-3.1    -> 1.35
    """
    for sep in ["-", "+", "~"]:
        if sep in version:
            version = version.split(sep)[0]
    # Remove any remaining non-numeric suffixes
    import re
    match = re.match(r'^([\d]+(?:\.[\d]+)*)', version)
    if match:
        return match.group(1)
    return version


def check_condition(installed_v, operator, vuln_v):
    if operator == "<":
        return installed_v < vuln_v
    if operator == "<=":
        return installed_v <= vuln_v
    if operator == ">":
        return installed_v > vuln_v
    if operator == ">=":
        return installed_v >= vuln_v
    if operator == "=":
        return installed_v == vuln_v
    return False


def is_vulnerable(installed, affected_expression):
    """
    Supports:
    - "< 8.4.0"
    - ">= 7.0.0, < 8.4.0"
    - "< 8.4.0 || >= 9.1.0"
    """
    try:
        installed_v = parse_version(normalize_version(installed))

        # OR conditions
        for or_block in affected_expression.split("||"):
            or_block = or_block.strip()
            and_conditions = [c.strip() for c in or_block.split(",")]

            all_match = True
            for condition in and_conditions:
                parts = condition.strip().split()
                if len(parts) != 2:
                    all_match = False
                    break
                operator, version = parts
                vuln_v = parse_version(version)

                if not check_condition(installed_v, operator, vuln_v):
                    all_match = False
                    break

            if all_match:
                return True

        return False
    except Exception:
        return False


def match_cves(packages):
    cves = load_cve_data()

    # Build O(1) lookup table
    cve_lookup = {}
    for cve in cves:
        for pkg in cve["packages"]:
            pkg = pkg.lower()
            cve_lookup.setdefault(pkg, []).append(cve)

    findings = []

    for pkg in packages:
        pkg_name = pkg["name"].lower()
        pkg_version = pkg["version"]

        if pkg_name not in cve_lookup:
            continue

        for cve in cve_lookup[pkg_name]:
            if is_vulnerable(pkg_version, cve["affected_versions"]):
                findings.append({
                    "package": pkg["name"],
                    "version": pkg_version,
                    "cve_id": cve["cve_id"],
                    "severity": cve["severity"],
                    "description": cve["description"]
                })

    return findings
