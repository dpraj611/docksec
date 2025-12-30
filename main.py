from scanner.image_loader import check_docker, pull_image
from scanner.os_detector import detect_os
from scanner.package_extractor import extract_packages
from scanner.cve_matcher import match_cves


def main():
    print("🚀 DockSec Scan starting...\n")

    docker_version = check_docker()
    if not docker_version:
        print("❌ Docker not found or not running.")
        return

    print(f"✅ Docker detected: {docker_version}\n")

    image_to_scan = "nginx:latest"

    if not pull_image(image_to_scan):
        return

    os_type = detect_os(image_to_scan)
    print(f"🧠 Detected OS inside image: {os_type}\n")

    packages = extract_packages(image_to_scan, os_type)
    print(f"📦 Found {len(packages)} installed packages\n")

    findings = match_cves(packages)

    if not findings:
        print("✅ No known vulnerabilities found.")
    else:
        print("🚨 Vulnerabilities detected:\n")
        for f in findings:
            print(
                f"- {f['package']} {f['version']} | "
                f"{f['cve_id']} | {f['severity']}\n  {f['description']}"
            )


if __name__ == "__main__":
    main()
