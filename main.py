import sys

from scanner.image_loader import check_docker, pull_image
from scanner.os_detector import detect_os
from scanner.package_extractor import extract_packages
from scanner.cve_matcher import match_cves
from scanner.risk_engine import calculate_risk
from scanner.reporter import generate_reports


def main():
    if len(sys.argv) < 2:
        print("❌ Usage: python main.py <docker-image>")
        print("Example: python main.py nginx:latest")
        return

    image_to_scan = sys.argv[1]

    print("🚀 DockSec Scan starting...\n")

    docker_version = check_docker()
    if not docker_version:
        print("❌ Docker not found or not running.")
        return

    print(f"✅ Docker detected: {docker_version}\n")

    if not pull_image(image_to_scan):
        return

    os_type = detect_os(image_to_scan)
    print(f"🧠 Detected OS inside image: {os_type}\n")

    packages = extract_packages(image_to_scan, os_type)
    print(f"📦 Found {len(packages)} installed packages\n")

    findings = match_cves(packages)
    risk_report = calculate_risk(findings)

    json_report, md_report = generate_reports(
        image_to_scan, os_type, risk_report
    )

    print("📄 Reports generated:")
    print(f"  - {json_report}")
    print(f"  - {md_report}")

    print(f"\n🔥 Overall Image Risk: {risk_report['overall_risk']}")

    # CI/CD fail condition
    if risk_report["overall_risk"] == "CRITICAL":
        print("\n❌ CRITICAL vulnerabilities found. Failing scan.")
        sys.exit(1)

    print("\n✅ Scan completed successfully.")


if __name__ == "__main__":
    main()
