import subprocess


def detect_os(image_name):
    """
    Detect OS inside Docker image by running a temporary container.
    """
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", image_name, "cat", "/etc/os-release"],
            capture_output=True,
            text=True
        )

        content = result.stdout.lower()

        if "alpine" in content:
            return "alpine"
        if "debian" in content or "ubuntu" in content:
            return "debian"

        return "unknown"

    except Exception:
        return "unknown"