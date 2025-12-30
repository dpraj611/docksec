import subprocess


def extract_packages(image_name, os_type):
    """
    Extract installed packages from Docker image.
    Returns a list of dictionaries: [{name, version}]
    """

    packages = []

    try:
        if os_type == "debian":
            result = subprocess.run(
                ["docker", "run", "--rm", image_name, "dpkg", "-l"],
                capture_output=True,
                text=True
            )

            for line in result.stdout.splitlines():
                if line.startswith("ii"):
                    parts = line.split()
                    if len(parts) >= 3:
                        packages.append({
                            "name": parts[1],
                            "version": parts[2]
                        })

        elif os_type == "alpine":
            result = subprocess.run(
                ["docker", "run", "--rm", image_name, "apk", "info", "-v"],
                capture_output=True,
                text=True
            )

            for line in result.stdout.splitlines():
                if "-" in line:
                    name, version = line.rsplit("-", 1)
                    packages.append({
                        "name": name,
                        "version": version
                    })

        return packages

    except Exception:
        return []
