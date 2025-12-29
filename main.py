from scanner.image_loader import check_docker, list_images


def main():
    print("🚀 DockSec Scan starting...\n")

    docker_version = check_docker()
    if not docker_version:
        print("❌ Docker not found or not running.")
        return

    print(f"✅ Docker detected: {docker_version}\n")

    images = list_images()
    if not images:
        print("ℹ️ No local Docker images found.")
    else:
        print("📦 Local Docker images:")
        for img in images:
            print(f"  - {img}")


if __name__ == "__main__":
    main()
