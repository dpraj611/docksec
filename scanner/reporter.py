import json
import os
from datetime import datetime


def generate_reports(image_name, os_type, report_data):
    """
    Generates JSON and Markdown security reports.
    """
    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.utcnow().isoformat()
    base_name = image_name.replace(":", "_")

    json_path = f"reports/{base_name}_report.json"
    md_path = f"reports/{base_name}_report.md"

    # JSON report
    with open(json_path, "w", encoding="utf-8") as jf:

        json.dump({
            "image": image_name,
            "os": os_type,
            "generated_at": timestamp,
            **report_data
        }, jf, indent=2)

    # Markdown report
    with open(md_path, "w", encoding="utf-8") as mf:

        mf.write(f"# DockSec Scan Report\n\n")
        mf.write(f"**Image:** `{image_name}`  \n")
        mf.write(f"**OS:** `{os_type}`  \n")
        mf.write(f"**Generated:** {timestamp}\n\n")

        mf.write("## Risk Summary\n\n")
        for k, v in report_data["summary"].items():
            mf.write(f"- **{k}**: {v}\n")

        mf.write(f"\n**Overall Risk Level:** 🔥 `{report_data['overall_risk']}`\n\n")

        mf.write("## Vulnerability Details\n\n")
        for f in report_data["findings"]:
            mf.write(
                f"- **{f['package']} {f['version']}**  \n"
                f"  - CVE: `{f['cve_id']}`  \n"
                f"  - Severity: `{f['severity']}`  \n"
                f"  - Risk Score: `{f['risk_score']}`  \n"
                f"  - {f['description']}\n\n"
            )

    return json_path, md_path
