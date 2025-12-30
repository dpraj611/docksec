import subprocess
import re


def check_docker():
    """
    Checks if Docker is installed and the daemon is reachable.
    """
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True
        )
        return "Docker daemon running"
    except Exception:
        return None


def is_valid_image_name(image_name):
    """
    Validates Docker image name format.
    """
    pattern = r"^[a-zA-Z0-9][a-zA-Z0-9._/-]*(?::[a-zA-Z0-9._-]+)?$"
    return bool(re.match(pattern, image_name))


def pull_image(image_name):
    """
    Pulls a Docker image safely.
    """
    if not is_valid_image_name(image_name):
        print(f"❌ Invalid image name: {image_name}")
        return False

    try:
        print(f"⬇️ Pulling image: {image_name}")
        subprocess.run(
            ["docker", "pull", image_name],
            timeout=300,
            check=True
        )
        print("✅ Image pulled successfully.\n")
        return True
    except subprocess.TimeoutExpired:
        print("❌ Docker pull timed out.")
        return False
    except subprocess.CalledProcessError as e:
        print("❌ Failed to pull image.")
        return False


def create_temp_container(image_name):
    """
    Creates a stopped container for inspection.
    """
    try:
        result = subprocess.run(
            ["docker", "create", image_name],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None


def remove_container(container_id):
    subprocess.run(
        ["docker", "rm", "-f", container_id],
        capture_output=True
    )
