import json
import os
from packaging.version import parse as parse_version


def load_cve_data():
    data_path = os.path.join("data", "sample_cves.json")
    with open(data_path, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_version(version):
    """
    Normalize distro-specific versions by trimming metadata.
    Example:
    8.14.1-2+deb13u2 -> 8.14.1
    """
    for sep in ["-", "+"]:
        if sep in version:
            version = version.split(sep)[0]
    return version


def is_vulnerable(installed, affected_expression):
    """
    Check if installed version satisfies vulnerability condition.
    Example affected_expression: "< 8.4.0"
    """
    operator, vuln_version = affected_expression.split()
    installed_v = parse_version(normalize_version(installed))
    vuln_v = parse_version(vuln_version)

    if operator == "<":
        return installed_v < vuln_v
    if operator == "<=":
        return installed_v <= vuln_v
    if operator == ">":
        return installed_v > vuln_v
    if operator == ">=":
        return installed_v >= vuln_v

    return False


def match_cves(packages):
    cves = load_cve_data()
    findings = []

    for pkg in packages:
        for cve in cves:
            if pkg["name"] == cve["package"]:
                if is_vulnerable(pkg["version"], cve["affected_versions"]):
                    findings.append({
                        "package": pkg["name"],
                        "version": pkg["version"],
                        "cve_id": cve["cve_id"],
                        "severity": cve["severity"],
                        "description": cve["description"]
                    })

    return findings
