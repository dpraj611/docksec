import json
import os


def load_cve_data():
    """
    Loads CVE data from local JSON file.
    """
    data_path = os.path.join("data", "sample_cves.json")

    with open(data_path, "r") as f:
        return json.load(f)


def version_less_than(installed, vulnerable):
    """
    Very simple version comparison.
    Only for demo purposes.
    """
    try:
        return installed < vulnerable
    except Exception:
        return False


def match_cves(packages):
    """
    Matches installed packages against CVE database.
    """
    cves = load_cve_data()
    findings = []

    for pkg in packages:
        for cve in cves:
            if pkg["name"] == cve["package"]:
                # Extract vulnerable version threshold
                vuln_version = cve["affected_versions"].replace("<", "").strip()

                if version_less_than(pkg["version"], vuln_version):
                    findings.append({
                        "package": pkg["name"],
                        "version": pkg["version"],
                        "cve_id": cve["cve_id"],
                        "severity": cve["severity"],
                        "description": cve["description"]
                    })

    return findings
