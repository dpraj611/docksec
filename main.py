from scanner.image_loader import check_docker, pull_image
from scanner.os_detector import detect_os


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
    print(f"🧠 Detected OS inside image: {os_type}")


if __name__ == "__main__":
    main()
