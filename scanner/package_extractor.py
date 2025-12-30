import subprocess
import tarfile
import tempfile
import os


def parse_dpkg_status(content):
    """
    Parse /var/lib/dpkg/status
    """
    packages = []
    current = {}

    for line in content.splitlines():
        if not line.strip():
            if "Package" in current and "Version" in current:
                packages.append({
                    "name": current["Package"],
                    "version": current["Version"]
                })
            current = {}
            continue

        if ":" in line:
            key, value = line.split(":", 1)
            current[key.strip()] = value.strip()

    return packages


def parse_apk_installed(content):
    """
    Parse /lib/apk/db/installed
    """
    packages = []
    current = {}

    for line in content.splitlines():
        if not line.strip():
            if "P" in current and "V" in current:
                packages.append({
                    "name": current["P"],
                    "version": current["V"]
                })
            current = {}
            continue

        if ":" in line:
            key, value = line.split(":", 1)
            current[key.strip()] = value.strip()

    return packages


def extract_packages(image_name, os_type):
    """
    Safely extract installed packages WITHOUT running the container.
    Uses:
      docker create
      docker export
    """

    container_id = None
    tmp_tar_path = None

    try:
        # 1️⃣ Create stopped container (NO execution)
        container_id = subprocess.run(
            ["docker", "create", image_name],
            capture_output=True,
            text=True,
            check=True
        ).stdout.strip()

        # 2️⃣ Create temp file correctly (Windows-safe)
        fd, tmp_tar_path = tempfile.mkstemp(suffix=".tar")
        os.close(fd)  # CRITICAL: close before docker writes

        # 3️⃣ Export filesystem
        subprocess.run(
            ["docker", "export", container_id, "-o", tmp_tar_path],
            check=True
        )

        packages = []

        # 4️⃣ Read package database files
        with tarfile.open(tmp_tar_path, "r") as tar:
            if os_type == "debian":
                try:
                    status_file = tar.extractfile("var/lib/dpkg/status")
                    if status_file:
                        content = status_file.read().decode("utf-8", errors="ignore")
                        packages = parse_dpkg_status(content)
                except KeyError:
                    pass

            elif os_type == "alpine":
                try:
                    installed_file = tar.extractfile("lib/apk/db/installed")
                    if installed_file:
                        content = installed_file.read().decode("utf-8", errors="ignore")
                        packages = parse_apk_installed(content)
                except KeyError:
                    pass

        return packages

    except Exception as e:
        print(f"❌ Failed to extract packages safely: {e}")
        return []

    finally:
        # 5️⃣ Cleanup ALWAYS
        if container_id:
            subprocess.run(
                ["docker", "rm", "-f", container_id],
                capture_output=True
            )

        if tmp_tar_path and os.path.exists(tmp_tar_path):
            try:
                os.unlink(tmp_tar_path)
            except Exception:
                pass
