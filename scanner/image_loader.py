import subprocess


def check_docker():
    """
    Checks if Docker is installed and running.
    """
    try:
        result = subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None


def list_images():
    """
    Lists locally available Docker images.
    """
    try:
        result = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True,
            text=True,
            check=True
        )
        images = result.stdout.strip().split("\n")
        return images if images != [''] else []
    except subprocess.CalledProcessError:
        return []
