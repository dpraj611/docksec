import subprocess
import tempfile
import os


# /etc/os-release is often a symlink. On Windows docker cp can't follow it.
# We try the real path first, then the symlink.
OS_RELEASE_PATHS = [
    "/usr/lib/os-release",   # real file (Debian/Ubuntu/nginx)
    "/etc/os-release",       # symlink target or real file (Alpine)
]


def detect_os(image_name):
    """
    Detect OS inside Docker image using filesystem-only inspection.
    Uses docker create + docker cp to read os-release without running anything.
    Tries multiple paths since /etc/os-release is often a symlink.
    """
    container_id = None
    tmp_dir = None
    try:
        # Create a stopped container (no execution)
        result = subprocess.run(
            ["docker", "create", image_name],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            return "unknown"

        container_id = result.stdout.strip()
        tmp_dir = tempfile.mkdtemp()
        dest_path = os.path.join(tmp_dir, "os-release")

        content = ""

        # Try each possible path for os-release
        for src_path in OS_RELEASE_PATHS:
            cp_result = subprocess.run(
                ["docker", "cp", f"{container_id}:{src_path}", dest_path],
                capture_output=True,
                text=True,
                timeout=15
            )

            if cp_result.returncode == 0 and os.path.isfile(dest_path):
                with open(dest_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read().lower()
                if content.strip():
                    break

            # Clean up for next attempt
            if os.path.exists(dest_path):
                try:
                    os.remove(dest_path)
                except Exception:
                    pass

        if "alpine" in content:
            return "alpine"
        if "debian" in content or "ubuntu" in content:
            return "debian"

        return "unknown"

    except Exception:
        return "unknown"

    finally:
        if container_id:
            subprocess.run(
                ["docker", "rm", "-f", container_id],
                capture_output=True,
                timeout=10
            )
        if tmp_dir and os.path.exists(tmp_dir):
            try:
                for fname in os.listdir(tmp_dir):
                    os.remove(os.path.join(tmp_dir, fname))
                os.rmdir(tmp_dir)
            except Exception:
                pass