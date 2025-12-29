from scanner.image_loader import check_docker, list_images, pull_image


def main():
    print("🚀 DockSec Scan starting...\n")

    docker_version = check_docker()
    if not docker_version:
        print("❌ Docker not found or not running.")
        return

    print(f"✅ Docker detected: {docker_version}\n")

    image_to_scan = "nginx:latest"

    if pull_image(image_to_scan):
        images = list_images()
        print("📦 Local Docker images after pull:")
        for img in images:
            print(f"  - {img}")


if __name__ == "__main__":
    main()
