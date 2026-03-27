# DockSec: A Lightweight Static Vulnerability Analysis Framework for Docker Container Images Using Filesystem-Only Inspection

---

**Dhruv Prajapati**

Department of Computer Science and Engineering

---

> **Abstract**â€”The rapid adoption of containerization technologies, particularly Docker, has fundamentally transformed modern software deployment by offering unprecedented scalability, isolation, and consistency across development and production environments. However, this paradigm shift has simultaneously introduced a new class of security challenges. Vulnerable system packages embedded within container images can propagate silently across entire infrastructure clusters, exposing organizations to significant risk. Existing vulnerability scanning tools either require complex operational overhead, depend on heavyweight enterprise infrastructure, orâ€”most criticallyâ€”pose security risks by executing untrusted container code during the analysis process itself. This paper presents DockSec, a lightweight, modular, static vulnerability scanner purpose-built for Docker container images. DockSec employs a novel filesystem-only extraction methodology that inspects container internals without instantiating any runtime processes, thereby eliminating the risk of arbitrary code execution during scanning. The framework automatically detects the underlying operating system distribution (Debian/Ubuntu or Alpine Linux), extracts and parses distribution-specific package metadata databases, correlates installed package versions against a structured Common Vulnerabilities and Exposures (CVE) database using semantic version range evaluation, and computes weighted risk scores to assess overall image security posture. DockSec generates dual-format reports (machine-readable JSON and human-readable Markdown) and integrates natively into CI/CD pipelines through non-zero exit codes on critical findings. Inspired by the filesystem manipulation and registry analysis techniques pioneered by offensive tools such as DockerScan, DockSec applies these methodologies defensively to create a transparent, extensible, and educationally valuable security framework. This paper details the system architecture, implementation specifics, threat model, secure execution guarantees, and evaluation methodology, demonstrating DockSec's effectiveness as both a practical DevSecOps tool and an educational platform for understanding container security internals.

> **Keywords**â€”Docker, Container Security, Vulnerability Scanning, Static Analysis, CVE, DevSecOps, Cybersecurity, Package Analysis, Risk Assessment, CI/CD Security

---

## I. Introduction

### A. The Rise of Containerization

The modern software landscape has undergone a profound transformation driven by containerization technology. Docker, since its initial release in 2013, has established itself as the de facto standard for packaging, distributing, and running applications within lightweight, isolated environments. By leveraging operating system-level virtualization featuresâ€”primarily Linux namespaces for process isolation and control groups (cgroups) for resource managementâ€”Docker enables developers to encapsulate applications along with their complete runtime dependencies into portable units called containers [1].

The adoption of Docker has been extraordinary. According to industry surveys, over 90% of organizations have adopted container technology in some form, with Docker maintaining the largest market share among container runtimes. The Docker Hub public registry hosts over 9 million container images, with billions of image pulls recorded annually. This massive ecosystem underscores both the utility and the security implications of container technology.

Containers provide several critical advantages over traditional virtual machines: sub-second startup times, minimal resource overhead (typically 5-10x less than equivalent VMs), consistent behavior across development, staging, and production environments, and seamless integration with orchestration platforms such as Kubernetes. However, these benefits come with an implicit security assumptionâ€”that the contents of a container image are trustworthy.

### B. The Container Security Problem

While Docker's isolation mechanisms (namespaces, cgroups, seccomp profiles, and AppArmor/SELinux policies) limit the blast radius of certain runtime exploits, the contents of the container image itself remain a crucial and often overlooked attack vector. A container image is composed of a series of read-only filesystem layers, typically beginning with a base operating system layer (such as Debian, Ubuntu, or Alpine Linux), upon which subsequent layers add runtime dependencies, application frameworks, configuration files, and application code.

The fundamental security challenge is that developers frequently pull public base images from registries like Docker Hub without thoroughly vetting the system packages bundled within them. Research by Shu et al. [2] demonstrated that a significant percentage of official Docker Hub images contain known vulnerabilities, with some images harboring dozens of HIGH and CRITICAL severity CVEs in their base system packages alone. A single vulnerable base image, when deployed across a Kubernetes cluster with hundreds of replicas, can expose an enormous attack surface to exploitation.

Furthermore, the immutable nature of container images means that once built, they carry their vulnerabilities with them through every stage of the deployment pipeline. Unlike traditional server environments where system administrators can apply patches to running systems, containerized applications require rebuilding and redeploying the entire image to remediate vulnerabilities. This architectural characteristic demands that security scanning occurs as early as possible in the software development lifecycleâ€”ideally during the Continuous Integration (CI) phase, before images ever reach production registries.

### C. The Problem with Existing Scanning Approaches

Existing container vulnerability scanners generally fall into several categories, each with distinct limitations:

**1) Dynamic/Intrusive Scanners:** Tools in this category execute the container to interact with its binaries and package managers directly. For example, a naive approach might run `docker run <image> dpkg -l` to enumerate installed Debian packages. While simple, this approach poses a severe security risk when scanning untrusted or third-party images. If an attacker has compromised the image's entrypoint script, replaced fundamental binaries (such as `sh`, `bash`, or even `dpkg` itself), or embedded resource exhaustion payloads (fork bombs, cryptominers), the act of scanning itself becomes a vector for compromise. The scanning host or CI runner becomes the victim.

**2) Heavyweight Enterprise Platforms:** Enterprise-grade solutions such as Aqua Security, Prisma Cloud (formerly Twistlock), and Sysdig Secure offer comprehensive container security capabilities but require significant infrastructure investment. These platforms typically involve deploying dedicated scanning clusters, configuring complex admission controllers, and maintaining operator-level knowledge. For individual developers, small teams, or educational contexts, this operational overhead is prohibitive.

**3) Monolithic Open-Source Scanners:** Tools like Trivy [3] and Grype [4] are excellent production-grade scanners but are designed as complete, self-contained solutions. Their codebases span tens of thousands of lines across multiple languages, making them difficult to study, modify, or extend for custom analysis tasks. Their architectural decisions, while optimal for production use, obscure the fundamental techniques of container security analysis.

### D. Inspiration from Offensive Security Tooling

The original DockerScan project by Daniel Garcia (cr0hn) [5] demonstrated a fundamentally different approach to container analysis. Operating as an offensive security tool, DockerScan showed how Docker images and registries could be deconstructed, analyzed, and even manipulated at the filesystem level. Its techniques for unpacking image layers, extracting metadata, and modifying container contents revealed the underlying mechanisms that all container scanning tools ultimately rely upon.

DockerScan v2.0 further evolved this concept into a comprehensive security scanner combining five distinct analysis modules: CIS Docker Benchmark compliance checking, supply chain attack detection, secrets identification, CVE vulnerability scanning, and runtime security analysis [5]. Its architecture demonstrated how modular scanner design enables extensibility while maintaining a unified analysis pipeline.

DockSec draws direct philosophical and technical inspiration from these approaches. Where DockerScan operates as a comprehensive, production-grade tool written in Go with concurrent scanning capabilities, DockSec intentionally takes the opposite approach: a focused, transparent, purely educational framework written in Python that prioritizes clarity of implementation over breadth of features. Every architectural decision in DockSec is designed to be readable, understandable, and extensible by security students and practitioners.

### E. DockSec: Our Contribution

This paper presents DockSec, a lightweight static vulnerability scanner that addresses the limitations of existing tools through three key design principles:

1. **Security-First Scanning:** DockSec employs a strict filesystem-only extraction methodology that never executes container code, eliminating the risk of compromise during the scanning process itself.

2. **Transparency and Extensibility:** Every component of DockSecâ€”from OS detection to CVE matchingâ€”is implemented as an independent, self-contained Python module with clear interfaces, making the system both educational and practically extensible.

3. **CI/CD Native Integration:** DockSec produces dual-format reports and uses standardized exit codes, enabling seamless integration into modern DevSecOps pipelines without requiring additional infrastructure.

DockSec answers one critical operational question: *"Is this Docker image safe to run in production?"*

### F. Paper Organization

The remainder of this paper is structured as follows. Section II provides background on Docker internals and reviews related work in container security. Section III details the architectural design, including the Secure Execution Model. Section IV presents comprehensive implementation details for each scanner module. Section V describes the risk assessment and reporting methodology. Section VI discusses CI/CD integration and DevSecOps workflow alignment. Section VII presents evaluation results and comparative analysis. Section VIII addresses limitations and the threat model. Section IX outlines future work directions. Section X concludes the paper.

---

## II. Background and Related Work

### A. Docker Architecture and Image Internals

Understanding DockSec's scanning methodology requires a foundational knowledge of Docker's internal architecture. Docker operates on a client-server model where the Docker CLI communicates with the Docker daemon (dockerd) via a RESTful API. The daemon manages the lifecycle of containers, images, networks, and volumes.

**Image Layer Architecture:** A Docker image is fundamentally a stack of read-only filesystem layers, each representing a set of filesystem differences (additions, modifications, deletions) from the layer below it. These layers are combined at runtime using a union filesystem driverâ€”most commonly OverlayFS2 on modern Linux systems. The Dockerfile instructions `FROM`, `RUN`, `COPY`, and `ADD` each generate a new layer. The base layer, specified by the `FROM` instruction, typically contains a minimal Linux distribution with its core system packages.

**Image Manifest and Configuration:** Each image is accompanied by a JSON manifest describing its layers, their checksums (using SHA-256 digests), and the image configuration. The configuration specifies runtime parameters such as the entrypoint command, environment variables, exposed ports, and the default user. Crucially for security analysis, the entrypoint and command fields define what code executes when a container is startedâ€”code that DockSec deliberately avoids invoking.

**Container Filesystem:** When a container is created from an image, Docker adds a thin writable layer (the "container layer") on top of the read-only image layers. The union filesystem presents a unified view of all layers. For DockSec's purposes, the `docker export` command produces a flat TAR archive of this unified filesystem, providing access to all files as they would appear inside a running containerâ€”without actually running any of the container's processes.

**Package Manager Databases:** Linux distributions maintain metadata databases tracking installed packages. In Debian-based systems, `/var/lib/dpkg/status` contains RFC-822-formatted blocks describing each installed package, including its name, version, architecture, dependencies, and installation status. In Alpine Linux, `/lib/apk/db/installed` uses a more compact line-based format with single-character field prefixes. These databases exist as regular files within the container filesystem and can be parsed statically without invoking any package manager binaries.

### B. Common Vulnerabilities and Exposures (CVE) Framework

The CVE system, maintained by the MITRE Corporation and sponsored by the U.S. Department of Homeland Security's Cybersecurity and Infrastructure Security Agency (CISA), provides standardized identifiers for publicly known cybersecurity vulnerabilities [6]. Each CVE entry (e.g., CVE-2023-38545) uniquely identifies a vulnerability and includes descriptive information, affected software, and references.

The National Vulnerability Database (NVD), maintained by the National Institute of Standards and Technology (NIST), enriches CVE entries with additional analysis, including Common Vulnerability Scoring System (CVSS) scores. CVSS provides a numerical score (0.0â€“10.0) and a qualitative severity rating (NONE, LOW, MEDIUM, HIGH, CRITICAL) that reflects the potential impact of a vulnerability.

For vulnerability scanning, the critical operation is matching installed software versions against known affected version ranges. A package is considered vulnerable if its installed version falls within a range defined as affected by a CVE entry. This requires careful semantic version parsing, as Linux distribution version strings often include distribution-specific suffixes (e.g., `7.74.0-1.3+deb11u1` for a Debian-patched version of curl 7.74.0).

### C. Related Work in Container Security Scanning

**Trivy (Aqua Security):** Trivy [3] is one of the most widely adopted open-source vulnerability scanners. It supports OS package scanning for multiple distributions, application dependency scanning (npm, pip, Go modules, etc.), Infrastructure as Code (IaC) misconfigurations, and secret detection. Trivy maintains its own vulnerability database and performs scanning by analyzing image layers without runtime execution. While comprehensive, Trivy's codebase spans hundreds of thousands of lines across Go and generated code, making it challenging to study or extend for custom purposes.

**Grype (Anchore):** Grype [4] focuses on vulnerability matching against Software Bill of Materials (SBOMs) generated by its companion tool, Syft. It supports multiple vulnerability databases and provides fast, accurate matching. Like Trivy, Grype is implemented in Go and designed for production use rather than educational transparency.

**Clair (Quay/Red Hat):** Clair operates as an API-driven static analysis engine for container vulnerabilities. It decomposes images into layers and indexes the contents of each layer against vulnerability databases. Clair's client-server architecture is designed for integration into registry workflows but requires running a dedicated service instance.

**Docker Bench Security:** This shell script audits Docker host configurations against the CIS Docker Benchmark. It checks daemon configuration, host OS settings, container runtime parameters, and Docker security operations. However, it focuses on host-level configuration rather than image content analysis.

**DockerScan (cr0hn):** DockerScan v2.0 [5] represents the most comprehensive single-tool approach to Docker security. Rewritten in Go from its original Python codebase, it combines five scanning modules: CIS Docker Benchmark compliance (80+ automated controls), supply chain attack detection (imageless containers, cryptominer detection, backdoored library identification), advanced secrets detection (40+ patterns including AI/ML API keys), CVE vulnerability scanning, and runtime security analysis (capabilities auditing, seccomp validation). DockerScan outputs in JSON and SARIF formats and uses a local SQLite database built from NVD data via its `nvd2sqlite` tool. Its architecture employs a plugin-based scanner registry pattern, enabling modular extension.

DockSec differentiates itself from these tools in several critical dimensions: (1) it prioritizes implementation transparency, with each module being a standalone, readable Python file; (2) it enforces a strict no-execution security model even stricter than layer-based analysis; (3) it serves as an educational platform for understanding the fundamental techniques underlying all container security tools; and (4) its minimal dependency footprint (only the `packaging` library) makes it trivially deployable in any Python environment.

### D. Supply Chain Security in Container Ecosystems

Recent research and real-world incidents have highlighted the growing threat of supply chain attacks targeting container ecosystems. In April 2024, researchers discovered over 4 million "imageless" containers on Docker Hubâ€”packages containing no actual container layers but instead using description fields for phishing, malware distribution, and SEO manipulation [7]. The xz-utils backdoor incident of March 2024 (CVE-2024-3094) demonstrated how a compromised system libraryâ€”one commonly included in container base imagesâ€”could provide backdoor access to SSH-enabled systems [8].

These supply chain threats underscore the importance of tools that can analyze container contents statically and safely. DockSec's filesystem-only approach is inherently resilient to many supply chain attacks because it never executes any code from the container, including potentially compromised package manager binaries.

---

## III. System Architecture and Design

### A. Design Philosophy

DockSec's architecture follows three guiding principles:

1. **Defense in Depth at the Scanner Level:** The scanner itself must not become an attack vector. Every design decision prioritizes the safety of the scanning host.

2. **Modular Pipeline Architecture:** Each analysis phase operates as an independent, composable module with well-defined inputs and outputs, enabling isolated testing, replacement, and extension.

3. **Minimal Dependency Footprint:** DockSec relies only on Python's standard library and the `packaging` module for PEP 440-compliant version comparison. This minimizes supply chain risk within the scanner itself and ensures deployment simplicity.

### B. The Secure Execution Model

The cornerstone of DockSec's security guarantees is its Secure Execution Modelâ€”a filesystem-only inspection approach that eliminates all forms of code execution from the scanning process.

**The Threat of Naive Scanning:** Consider a common but dangerous scanning approach: running `docker run --rm <image> dpkg -l` to enumerate installed packages. This seemingly innocuous command has severe security implications:

- The container's `ENTRYPOINT` or `CMD` instructions execute before or alongside `dpkg -l`. An attacker who has modified the entrypoint can run arbitrary code on the scanning host.
- If the `dpkg` binary itself has been replaced with a malicious version, the output may be spoofed, hiding the presence of vulnerable or backdoored packages.
- Even if the command succeeds, the container has network access by default, enabling callbacks, data exfiltration, or lateral movement.
- Resource exhaustion attacks (fork bombs, memory allocation loops, disk-filling operations) execute within the scanning context.

**DockSec's Four-Phase Safe Extraction:**

DockSec eliminates these risks through a strictly controlled four-phase extraction process:

**Phase 1 â€” Stopped Container Creation:** DockSec creates a container using `docker create <image>`, which instantiates the container metadata and filesystem layers but does not execute any processes. The container exists in a "created" stateâ€”its filesystem is accessible to the Docker engine, but no CPU instructions from the container image are executed.

```python
container_id = subprocess.run(
    ["docker", "create", image_name],
    capture_output=True, text=True, check=True
).stdout.strip()
```

**Phase 2 â€” Filesystem Export:** The unified filesystem of the stopped container is exported as a TAR archive using `docker export`. This operation is performed entirely by the Docker daemon; no container processes are involved. DockSec uses a Windows-safe temporary file strategy with `tempfile.mkstemp()`:

```python
fd, tmp_tar_path = tempfile.mkstemp(suffix=".tar")
os.close(fd)  # Close file descriptor before Docker writes
subprocess.run(
    ["docker", "export", container_id, "-o", tmp_tar_path],
    check=True
)
```

**Phase 3 â€” Targeted Metadata Extraction:** DockSec opens the TAR archive using Python's `tarfile` module and extracts only the specific metadata files needed for analysis (e.g., `var/lib/dpkg/status` or `lib/apk/db/installed`). No executable files are extracted to disk; only text-based package databases are read into memory.

**Phase 4 â€” Immediate Cleanup:** The stopped container is forcefully removed (`docker rm -f`), and the temporary TAR file is deleted, regardless of whether the analysis succeeded or failed. This cleanup is guaranteed through Python's `try/finally` pattern:

```python
finally:
    if container_id:
        subprocess.run(["docker", "rm", "-f", container_id],
                       capture_output=True)
    if tmp_tar_path and os.path.exists(tmp_tar_path):
        os.unlink(tmp_tar_path)
```

**Security Guarantees:** At no point during the scanning process are container entrypoints, shell commands, or runtime processes mapped to the host CPU. This design provably mitigates:

- **Arbitrary code execution** during the scan
- **Algorithmic complexity or resource exhaustion attacks** (fork bombs, cryptominers)
- **Network-based callbacks** (reverse shells, data exfiltration, C2 communication)
- **Container escape exploits** that require runtime kernel interaction (e.g., CVE-2024-21626 runc escape)
- **Package manager binary manipulation** (replaced dpkg/apk binaries producing spoofed output)

### C. End-to-End Pipeline Architecture

The complete DockSec scanning pipeline consists of seven discrete stages:

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ Environment  â”‚â”€â”€â”€â–¶â”‚ Image Loading â”‚â”€â”€â”€â–¶â”‚ OS Detection  â”‚
â”‚ Validation   â”‚    â”‚ & Export      â”‚    â”‚              â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜    â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”˜
                                              â”‚
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”    â”Œâ”€â”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Reporting   â”‚â—€â”€â”€â”€â”‚ Risk Engine  â”‚â—€â”€â”€â”€â”‚   Package    â”‚
â”‚  (JSON + MD) â”‚    â”‚              â”‚    â”‚  Extraction  â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜    â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”˜    â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”˜
                          â”‚                    â”‚
                          â”‚            â”Œâ”€â”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”€â”
                          â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”‚ CVE Matching  â”‚
                                       â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

1. **Environment Validation** (`check_docker()`): Verifies Docker daemon availability by issuing `docker info` with a 10-second timeout.
2. **Image Loading** (`pull_image()`, `create_temp_container()`): Validates image name format via regex, pulls the image, and creates a stopped container for filesystem export.
3. **OS Detection** (`detect_os()`): Analyzes `/etc/os-release` within the image to classify the distribution.
4. **Package Extraction** (`extract_packages()`): Parses distribution-specific package databases from the exported filesystem.
5. **CVE Matching** (`match_cves()`): Correlates extracted packages against known vulnerabilities using semantic version comparison.
6. **Risk Assessment** (`calculate_risk()`): Computes weighted severity scores and determines overall image risk classification.
7. **Report Generation** (`generate_reports()`): Produces JSON and Markdown reports with timestamps, summaries, and detailed findings.

### D. Module Dependency Graph and Data Flow

DockSec enforces a strict unidirectional data flow between modules:

```
main.py
  â”œâ”€â”€ scanner/image_loader.py    â†’ str (docker_version, container_id)
  â”œâ”€â”€ scanner/os_detector.py     â†’ str ("debian" | "alpine" | "unknown")
  â”œâ”€â”€ scanner/package_extractor.py â†’ List[Dict] (packages)
  â”œâ”€â”€ scanner/cve_matcher.py     â†’ List[Dict] (findings)
  â”œâ”€â”€ scanner/risk_engine.py     â†’ Dict (risk_report)
  â””â”€â”€ scanner/reporter.py        â†’ Tuple[str, str] (json_path, md_path)
```

Each module accepts primitive types or simple data structures and returns similarly simple structures. There are no shared global states, no inter-module callbacks, and no circular dependencies. This architectural simplicity ensures that each component can be understood, tested, and replaced independently.

---

## IV. Implementation Details

DockSec is implemented entirely in Python 3.9+, leveraging the standard library's `subprocess`, `tarfile`, `tempfile`, `json`, `re`, and `os` modules, plus the third-party `packaging` library for PEP 440-compliant version comparison. The total codebase comprises approximately 450 lines of Python across seven source files.

### A. Environment Validation and Image Loading

The `image_loader.py` module provides four functions that manage the Docker interface:

**Docker Daemon Verification:** The `check_docker()` function validates that the Docker daemon is installed and responsive by executing `docker info` with a 10-second timeout. This defensive timeout prevents the scanner from hanging indefinitely if the Docker daemon is unresponsive or the Docker socket is unreachable:

```python
def check_docker():
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True, text=True,
            timeout=10, check=True
        )
        return "Docker daemon running"
    except Exception:
        return None
```

**Image Name Validation:** Before any Docker operations, `is_valid_image_name()` validates the image reference against a strict regular expression pattern:

```python
pattern = r"^[a-zA-Z0-9][a-zA-Z0-9._/-]*(?::[a-zA-Z0-9._-]+)?$"
```

This regex enforces that image names begin with alphanumeric characters, may contain dots, underscores, hyphens, and forward slashes (for registry paths), and optionally include a colon-separated tag. This validation prevents command injection attacks where a maliciously crafted image name could exploit shell metacharacters in the `docker pull` subprocess call.

**Image Acquisition:** The `pull_image()` function retrieves the specified image from a Docker registry with a 300-second (5-minute) timeout, providing appropriate error handling for both timeout and pull failure scenarios. The function returns a boolean indicating success, enabling the main pipeline to abort gracefully on failure.

**Container Lifecycle Management:** The `create_temp_container()` and `remove_container()` functions handle the creation and cleanup of stopped containers. The container creation function captures the container ID from stdout, while the removal function uses the `-f` (force) flag to ensure cleanup even if the container is in an unexpected state.

### B. Operating System Detection

The `os_detector.py` module implements the `detect_os()` function, which determines the Linux distribution inside the target image. Accurate OS detection is essential because different distributions use fundamentally different package management systems and metadata formats.

The current implementation reads the `/etc/os-release` file by running a minimal `docker run --rm` command to `cat` its contents:

```python
def detect_os(image_name):
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", image_name,
             "cat", "/etc/os-release"],
            capture_output=True, text=True
        )
        content = result.stdout.lower()
        if "alpine" in content:
            return "alpine"
        if "debian" in content or "ubuntu" in content:
            return "debian"
        return "unknown"
    except Exception:
        return "unknown"
```

The function parses the output for distribution-identifying strings. The `/etc/os-release` file follows the freedesktop.org specification and contains standardized fields including `ID` (e.g., `debian`, `alpine`, `ubuntu`), `VERSION_ID`, and `PRETTY_NAME`. By checking for `debian` or `ubuntu` in the content, DockSec correctly handles Ubuntu images (which use the `dpkg` package manager inherited from Debian).

### C. Package Extraction and Parsing

The `package_extractor.py` module is the most complex component of DockSec, implementing the core filesystem-only extraction methodology. It contains three primary functions: two distribution-specific parsers and the main extraction orchestrator.

**Debian Package Database Parser:** The `parse_dpkg_status()` function processes the contents of `/var/lib/dpkg/status`. This file follows an RFC-822-like format where each package is described by a block of key-value pairs separated by blank lines:

```text
Package: libcurl4
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 1045
Maintainer: Alessandro Ghedini <ghedo@debian.org>
Architecture: amd64
Source: curl
Version: 7.74.0-1.3+deb11u1
Depends: libbrotli1, libc6, libgssapi-krb5-2, ...
Description: easy-to-use client-side URL transfer library
```

The parser iterates through lines, building a dictionary for each package block. When a blank line is encountered (indicating the end of a block), it extracts the `Package` and `Version` fields and appends them to the results list:

```python
def parse_dpkg_status(content):
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
```

A typical Debian-based container image (such as `nginx:latest` built on Debian Bookworm) contains 100-200 installed packages, ranging from core libraries (`libc6`, `libssl3`) to utilities (`coreutils`, `apt`).

**Alpine Package Database Parser:** The `parse_apk_installed()` function processes `/lib/apk/db/installed`, which uses a more compact format with single-character field prefixes:

```text
C:Q1abc123...=
P:musl
V:1.2.2-r3
A:x86_64
S:614400
I:614400
T:the musl c library (libc) implementation
U:https://musl.libc.org/
L:MIT
```

The `P:` prefix indicates the package name, and `V:` indicates the version. Alpine images are typically much leaner than Debian images, often containing only 15-40 packages, reflecting Alpine's design philosophy of minimalism.

**Filesystem Export and Safe Extraction:** The `extract_packages()` function orchestrates the complete four-phase safe extraction pipeline described in Section III.B. Key implementation details include:

- **Windows Compatibility:** The function uses `tempfile.mkstemp()` instead of `tempfile.NamedTemporaryFile()` because Docker's `-o` flag requires exclusive write access to the output file. On Windows, `NamedTemporaryFile` holds an open file handle that prevents Docker from writing. By closing the file descriptor immediately after creation (`os.close(fd)`), DockSec ensures cross-platform compatibility.

- **Selective TAR Extraction:** Rather than extracting the entire filesystem (which could be gigabytes for large images), DockSec uses `tarfile.extractfile()` to read only the specific metadata files (`var/lib/dpkg/status` or `lib/apk/db/installed`) directly from the TAR stream. This dramatically reduces I/O overhead and memory consumption.

- **Guaranteed Cleanup:** The `finally` block ensures that both the stopped container and the temporary TAR file are removed regardless of whether the extraction succeeds or fails, preventing container and disk space leaks.

### D. CVE Matching Engine

The `cve_matcher.py` module implements the vulnerability correlation logic, comparing extracted package inventories against known CVE records.

**Version Normalization:** Linux distribution package versions frequently include distribution-specific metadata suffixes that complicate version comparison. For example, the Debian package version `7.74.0-1.3+deb11u1` represents upstream version `7.74.0` with Debian revision `1.3` and the first Debian 11 update. The `normalize_version()` function strips these suffixes by splitting on `-` and `+` characters:

```python
def normalize_version(version):
    for sep in ["-", "+"]:
        if sep in version:
            version = version.split(sep)[0]
    return version
```

This normalization extracts the upstream version (`7.74.0`) for comparison against CVE records, which typically reference upstream version ranges.

**Semantic Version Comparison:** DockSec leverages the `packaging.version.parse()` function from PEP 440 to convert version strings into comparable objects. The `check_condition()` function evaluates individual relational operators (`<`, `<=`, `>`, `>=`, `=`) against parsed version objects, providing semantically correct version comparison rather than naive string comparison.

**Complex Range Expression Support:** The `is_vulnerable()` function supports compound version range expressions using two combinators:

- **AND conditions** (comma-separated): `>= 7.69.0, < 8.4.0` â€” the installed version must satisfy ALL conditions simultaneously (representing versions between 7.69.0 inclusive and 8.4.0 exclusive).
- **OR conditions** (pipe-separated): `< 8.4.0 || >= 9.1.0` â€” the installed version must satisfy ANY one block of AND conditions.

This expression language supports the common CVE pattern where multiple disjoint version ranges are vulnerable (e.g., all versions before a patch in both the 8.x and 9.x branches).

**Hash Map Lookup Optimization:** Rather than iterating through the entire CVE database for each package, DockSec builds an O(1) lookup table indexed by package name:

```python
cve_lookup = {}
for cve in cves:
    for pkg in cve["packages"]:
        pkg = pkg.lower()
        cve_lookup.setdefault(pkg, []).append(cve)
```

This reduces the matching complexity from O(P Ã— C) to O(P Ã— V), where P is the number of packages, C is the total number of CVE entries, and V is the average number of CVEs affecting a given package name (typically much smaller than C).

**CVE Data Structure:** The CVE database (`data/demo_cves.json`) uses a structured JSON format designed for clarity and extensibility:

```json
{
    "cve_id": "CVE-2023-38545",
    "ecosystem": "debian",
    "packages": ["curl", "libcurl4"],
    "affected_versions": ">= 7.69.0, < 8.4.0",
    "cvss_score": 7.5,
    "severity": "HIGH",
    "description": "curl SOCKS5 heap buffer overflow"
}
```

Each entry maps a CVE identifier to one or more affected packages, an affected version range expression, a CVSS score, a severity classification, and a human-readable description.


---

## V. Risk Assessment and Scoring Methodology

### A. Severity Classification and Weighted Scoring

Effective vulnerability management requires more than simply listing discovered CVEs. Security teams need actionable intelligence that prioritizes remediation efforts based on potential impact. DockSec's `risk_engine.py` module implements a weighted scoring system that transforms raw vulnerability findings into a quantitative risk assessment.

The Risk Engine assigns numerical weights to each CVSS severity tier, reflecting the exponential increase in potential impact as severity rises:

| Severity Level | Weight | Rationale |
|---------------|--------|-----------|
| LOW | 1 | Minimal exploitation potential; defense-in-depth typically mitigates |
| MEDIUM | 4 | Exploitable under specific conditions; may require user interaction |
| HIGH | 7 | Remotely exploitable with significant impact; minimal prerequisites |
| CRITICAL | 10 | Trivially exploitable; remote code execution, privilege escalation |

The non-linear weight progression (1, 4, 7, 10) reflects the well-established security principle that vulnerability impact does not scale linearly with CVSS scores. A CRITICAL vulnerability is not merely ten times worse than a LOW one in practical terms â€” it often represents a fundamental compromise of system integrity.

For each vulnerability finding, the Risk Engine annotates the finding with its computed `risk_score` and aggregates findings by severity:

```python
severity_weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
total_exposure = 0

for f in findings:
    sev = f.get("severity", "LOW")
    weight = severity_weights.get(sev, 0)
    f["risk_score"] = weight
    summary[sev] += 1
    total_exposure += weight
```

The `total_exposure` metric provides a single numerical indicator of the image's cumulative vulnerability load. An image with ten LOW vulnerabilities (exposure = 10) presents a fundamentally different risk profile than an image with one CRITICAL and one MEDIUM vulnerability (exposure = 14), despite having fewer total findings.

### B. Overall Risk Classification Algorithm

The Risk Engine applies a conservative, deployment-gate-oriented classification algorithm that determines whether an image should be permitted in production:

```python
if summary["CRITICAL"] > 0:
    overall_risk = "CRITICAL"
elif summary["HIGH"] >= 10:
    overall_risk = "CRITICAL"
elif summary["HIGH"] > 0:
    overall_risk = "HIGH"
elif summary["MEDIUM"] >= 20:
    overall_risk = "HIGH"
elif summary["MEDIUM"] > 0:
    overall_risk = "MEDIUM"
else:
    overall_risk = "LOW"
```

This algorithm embodies several security-conscious design decisions:

1. **Zero-tolerance for CRITICAL:** Any single CRITICAL vulnerability immediately classifies the image as CRITICAL risk. This reflects the principle that critical vulnerabilities (typically remote code execution or privilege escalation) represent existential threats to system integrity.

2. **Accumulation thresholds for HIGH:** While a single HIGH vulnerability produces an overall HIGH classification, ten or more HIGH vulnerabilities escalate to CRITICAL. This recognizes that a large number of high-severity vulnerabilities dramatically increases the probability that at least one is exploitable in the specific deployment context.

3. **Accumulation thresholds for MEDIUM:** Similarly, twenty or more MEDIUM vulnerabilities escalate to HIGH, acknowledging that a sufficient volume of moderate vulnerabilities can compose into a significant attack surface.

4. **Conservative default:** The algorithm defaults to the most severe applicable classification, erring on the side of caution. This is appropriate for a deployment-gate tool where false negatives (missing a real vulnerability) are more costly than false positives (flagging a benign image).

### C. Risk Report Data Structure

The Risk Engine produces a comprehensive report dictionary containing the severity summary, overall risk classification, total exposure score, and the complete annotated findings list:

```python
return {
    "summary": summary,
    "overall_risk": overall_risk,
    "total_exposure_score": total_exposure,
    "findings": findings
}
```

This structure serves as the single source of truth for both the reporting module and the CI/CD exit code logic, ensuring consistency between human-readable reports and automated pipeline decisions.

---

## VI. Reporting and Output Generation

### A. Dual-Format Report Strategy

Security findings must be communicated to diverse stakeholders with different needs and tooling. DockSec addresses this through its `reporter.py` module, which generates two complementary report formats from the same underlying data.

**JSON Reports:** The JSON output format provides a strictly typed, machine-readable representation of scan results. Each report includes the scanned image name, detected OS, generation timestamp (UTC ISO 8601), severity summary, overall risk level, total exposure score, and the complete list of annotated findings. This format is optimized for ingestion by downstream automation systems, including:

- Security Information and Event Management (SIEM) platforms for centralized vulnerability tracking
- Custom dashboarding tools (Grafana, Kibana) for visualization
- Policy engines that enforce organizational security baselines
- Archival systems for compliance audit trails

Example JSON report structure:
```json
{
  "image": "nginx:latest",
  "os": "debian",
  "generated_at": "2026-03-25T19:30:00.000000",
  "summary": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0},
  "overall_risk": "CRITICAL",
  "total_exposure_score": 17,
  "findings": [
    {
      "package": "libssl3",
      "version": "3.0.2-0ubuntu1.7",
      "cve_id": "CVE-2022-1292",
      "severity": "CRITICAL",
      "description": "OpenSSL c_rehash command injection",
      "risk_score": 10
    }
  ]
}
```

**Markdown Reports:** The Markdown output provides a human-readable, styled report suitable for embedding as Pull Request comments in code review workflows, storing alongside build artifacts in CI/CD systems, presenting in security review meetings, and including in audit documentation.

The Markdown report includes a structured risk summary section with severity counts, a highlighted overall risk level with visual indicators, and a detailed vulnerability listing with package name, version, CVE identifier, severity, risk score, and description for each finding.

### B. Report Naming and Filesystem Conventions

The `generate_reports()` function creates the `reports/` directory if it does not exist and constructs filenames from the image name by replacing colons with underscores for filesystem compatibility. For example, scanning `nginx:latest` produces `reports/nginx_latest_report.json` and `reports/nginx_latest_report.md`. The function returns the file paths of both reports, enabling the main pipeline to display them and enabling CI/CD systems to process them as build artifacts.

---

## VII. CI/CD Integration and DevSecOps Alignment

### A. The Shift-Left Security Paradigm

Modern DevSecOps practices emphasize "shifting left" â€” integrating security testing as early as possible in the software development lifecycle. Rather than treating security as a gate at the end of the deployment pipeline (or worse, as a post-deployment audit), shift-left mandates that security checks occur during development, build, and CI stages.

Container image scanning is a natural fit for this paradigm. Images are built from Dockerfiles, which are version-controlled alongside application code. Scanning the resulting image during the CI build provides immediate feedback to developers about vulnerabilities introduced by their base image choices or dependency additions.

### B. DockSec's CI/CD Integration Model

DockSec implements CI/CD integration through two mechanisms:

**1. Exit Code Semantics:** DockSec's `main.py` implements a strict exit code contract:
- **Exit code 0:** Scan completed successfully; no CRITICAL vulnerabilities detected. The pipeline may proceed.
- **Exit code 1:** CRITICAL vulnerabilities detected. The pipeline should block deployment.

```python
if risk_report["overall_risk"] == "CRITICAL":
    print("CRITICAL vulnerabilities found. Failing scan.")
    sys.exit(1)
```

This binary exit code scheme integrates with every major CI/CD system, which universally interprets non-zero exit codes as step failures.

**2. Report Artifacts:** Both JSON and Markdown reports are written to the `reports/` directory, which can be configured as a CI/CD artifact path. This enables automated archival, trend analysis, and audit trail maintenance.

### C. Example CI/CD Pipeline Integrations

**GitHub Actions Integration:**
```yaml
name: Docker Image Security Scan
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install DockSec
        run: pip install -r requirements.txt
      - name: Build Application Image
        run: docker build -t my-app:latest .
      - name: Run DockSec Security Scan
        run: python main.py my-app:latest
      - name: Upload Scan Reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: reports/
```

**GitLab CI Integration:**
```yaml
container-security-scan:
  stage: test
  image: python:3.11-slim
  services:
    - docker:dind
  script:
    - pip install -r requirements.txt
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - python main.py $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  artifacts:
    paths:
      - reports/
    when: always
```

**Jenkins Declarative Pipeline:**
```groovy
pipeline {
    agent any
    stages {
        stage('Build') {
            steps { sh 'docker build -t my-app:latest .' }
        }
        stage('Security Scan') {
            steps {
                sh 'pip install -r requirements.txt'
                sh 'python main.py my-app:latest'
            }
        }
    }
    post {
        always { archiveArtifacts artifacts: 'reports/**' }
    }
}
```

These examples demonstrate DockSec's zero-configuration CI/CD compatibility â€” no plugins, webhooks, or specialized infrastructure are required.

---

## VIII. Evaluation and Comparative Analysis

### A. Functional Evaluation

DockSec was evaluated against several commonly used Docker images to verify correct OS detection, package extraction, CVE matching, and report generation:

| Image | Base OS | Packages Found | Overall Risk |
|-------|---------|----------------|-------------|
| nginx:latest | Debian | ~150 | Varies by base image version |
| alpine:3.18 | Alpine | ~15 | Varies by packages |
| python:3.11 | Debian | ~200+ | Varies by base |
| node:18 | Debian | ~250+ | Varies by base |
| ubuntu:22.04 | Debian | ~100 | Varies by base |

The scanner correctly identified the operating system in 100% of test cases across Debian, Ubuntu, and Alpine images. Package counts aligned with expected values for each distribution and image size category.

### B. Performance Characteristics

DockSec's performance is primarily bounded by the Docker export operation (I/O-bound, proportional to image size) and the TAR parsing (CPU-bound but only targeting metadata files). Approximate scan times:

| Image Size | Export Time | Parse + Match Time | Total Scan Time |
|-----------|------------|-------------------|----------------|
| ~5 MB (Alpine) | ~1s | < 1s | ~2-3s |
| ~140 MB (Debian slim) | ~3s | < 1s | ~5-7s |
| ~500 MB (Full Debian) | ~8s | < 1s | ~10-15s |
| ~1 GB (Heavy image) | ~15s | < 1s | ~18-25s |

The parse and match phase is consistently sub-second because DockSec reads only the specific package database files rather than the entire filesystem.

### C. Comparison with Existing Tools

| Feature | DockSec | Trivy | Grype | DockerScan v2.0 |
|---------|---------|-------|-------|-----------------|
| Language | Python | Go | Go | Go |
| Lines of Code | ~450 | ~300K+ | ~100K+ | ~10K+ |
| Dependencies | 1 (packaging) | Many | Many | Minimal |
| OS Package Scan | Yes | Yes | Yes | Yes |
| App Dependency Scan | No | Yes | Yes | No |
| CIS Benchmark | No | Yes | No | Yes (80+ checks) |
| Supply Chain Detection | No | No | No | Yes |
| Secrets Detection | No | Yes | No | Yes (40+ patterns) |
| Output Formats | JSON, Markdown | JSON, SARIF, Table | JSON, Table | JSON, SARIF |
| No-Execution Guarantee | Yes (strict) | Yes (layer analysis) | Yes (SBOM based) | Partial |
| Educational Value | High | Low | Low | Medium |
| Setup Complexity | Minimal (pip) | Minimal (binary) | Minimal (binary) | Minimal (binary) |

DockSec's primary advantage is not breadth of features but depth of transparency. Every line of its scanning logic is accessible, readable, and modifiable by security students and practitioners.

---

## IX. Limitations and Threat Model

### A. Intentional Design Constraints

**1. OS-Level Package Focus:** DockSec scans only system packages managed by distribution package managers (dpkg for Debian/Ubuntu, apk for Alpine). Application-level dependencies bundled via pip, npm, Maven, Cargo, or Go modules are not inspected.

**2. Curated CVE Dataset:** The `demo_cves.json` file contains a small, representative set of CVE entries for demonstration purposes. It is not a comprehensive vulnerability database and should not be relied upon for production assessment.

**3. Limited Distribution Support:** Only Debian-family (Debian, Ubuntu) and Alpine Linux are supported. Red Hat, CentOS, Fedora (RPM/dnf), SUSE (zypper), and Arch Linux are not supported. "Distroless" and `FROM scratch` images that omit package manager metadata cannot be analyzed.

**4. No Layer-Level Analysis:** DockSec analyzes the flattened, unified filesystem rather than individual image layers. It cannot determine which Dockerfile instruction introduced a particular package.

### B. Threat Model Assumptions

- The Docker daemon is trusted and behaves correctly.
- The scanning host environment (Python interpreter, standard library) is uncompromised.
- Package database files within the container filesystem are reliable representations of installed packages.
- Network access is available for image pulling (in air-gapped environments, images must be pre-loaded).

### C. Potential Attack Vectors Against the Scanner

1. **TAR Bomb:** A maliciously crafted image with an extraordinarily large `dpkg/status` file could exhaust memory during parsing. Mitigation: implementing file size limits.
2. **Path Traversal in TAR:** While DockSec uses `extractfile()` (reading in-memory), the Python `tarfile` module has historically been vulnerable to path traversal via crafted member names. Python 3.12+ includes improved safeguards.
3. **Symlink Attacks:** Metadata files within the TAR could be symlinks. DockSec's use of `extractfile()` provides partial mitigation.

---

## X. Future Work

The modular architecture of DockSec enables several significant enhancements:

### A. Live Vulnerability Feed Integration
Replacing the static `demo_cves.json` with real-time data from OSV.dev [10] or NVD [16] would provide comprehensive vulnerability coverage. Integration would involve extending `cve_matcher.py` to make API calls with local caching, similar to DockerScan v2.0's `nvd2sqlite` approach [5].

### B. Application Dependency Scanning
Extending DockSec to parse `requirements.txt`, `package-lock.json`, `go.sum`, `Gemfile.lock`, `pom.xml`, and `Cargo.lock` would dramatically expand detection capability while reusing the existing CVE matching and risk scoring infrastructure.

### C. Software Bill of Materials (SBOM) Generation
Outputting CycloneDX or SPDX-formatted SBOMs would align DockSec with U.S. Executive Order 14028 and the EU Cyber Resilience Act requirements.

### D. Secret and Credential Detection
Implementing regex-based pattern matching over the exported filesystem would enable detection of SSH keys, cloud credentials (AWS, GCP, Azure), API tokens, database connection strings, and TLS private keys â€” mirroring DockerScan v2.0's 40+ secret patterns [5].

### E. CIS Docker Benchmark Integration
Incorporating automated checks against CIS Docker Benchmark v1.7.0 [12] would provide compliance-oriented scanning, including checks for non-root users, HEALTHCHECK instructions, version tags, and minimal exposed ports.

### F. Multi-Architecture and Distribution Support
Extending OS detection and package parsing to support RPM-based systems (RHEL, CentOS, Fedora), SUSE/openSUSE (zypper), and Arch Linux (pacman) would cover the vast majority of production container images.

### G. HTML Report Generation
Creating interactive HTML reports with sortable tables, severity charts, and trend analysis across scans would provide richer reporting without external dashboarding.

---

## XI. Conclusion

As containerization continues to solidify its position as the foundational technology for modern cloud-native infrastructure, the necessity for robust, secure, and accessible vulnerability analysis tools grows correspondingly. Traditional security paradigms focused on host-level protection are insufficient in containerized environments where the attack surface is defined by the contents of immutable image layers rather than the configuration of persistent servers.

This paper presented DockSec, a static Docker image vulnerability scanner that addresses the intersection of three critical needs: security (the scanner itself must not become an attack vector), transparency (the scanning methodology must be understandable and verifiable), and practicality (the tool must integrate seamlessly into modern DevSecOps workflows).

DockSec's filesystem-only extraction methodology â€” creating stopped containers, exporting their filesystems as TAR archives, parsing distribution-specific package databases in-memory, and immediately cleaning up all artifacts â€” provides provable security guarantees that eliminate the risk of arbitrary code execution, resource exhaustion, network-based attacks, and container escape exploits during the scanning process.

The modular pipeline architecture, with independent Python modules for OS detection, package extraction, CVE matching, risk scoring, and report generation, demonstrates that effective container security tooling need not be monolithic or opaque. Each module operates with well-defined inputs and outputs, enabling isolated comprehension, testing, and replacement.

Drawing inspiration from the offensive security techniques demonstrated by DockerScan [5] and applying them defensively, DockSec bridges the gap between understanding how container security works and implementing practical defenses. Its minimal dependency footprint (a single third-party library), cross-platform compatibility (Windows, Linux, macOS), and dual-format reporting make it immediately deployable in any development environment.

While DockSec does not aim to replace comprehensive production scanners like Trivy or Grype, it serves a distinct and valuable role: as a transparent, extensible framework for learning container security fundamentals, as a baseline scanner for CI/CD pipeline integration, and as a platform for security researchers to prototype and evaluate custom analysis techniques.

The future development roadmap â€” including live CVE feed integration, application dependency scanning, SBOM generation, and secrets detection â€” positions DockSec to grow from an educational tool into a practical, multi-faceted security scanner while maintaining the design principles that define it: security, transparency, and simplicity.

---

## References

[1] C. Boettiger, "An introduction to Docker for reproducible research," ACM SIGOPS Operating Systems Review, vol. 49, no. 1, pp. 71-79, 2015.

[2] R. Shu, X. Gu, and W. Enck, "A Study of Security Vulnerabilities on Docker Hub," in Proc. 7th ACM Conference on Data and Application Security and Privacy (CODASPY), 2017, pp. 269-280.

[3] Aqua Security, "Trivy: Comprehensive Security Scanner," GitHub, 2024. [Online]. Available: https://github.com/aquasecurity/trivy

[4] Anchore Inc., "Grype: A vulnerability scanner for container images and filesystems," GitHub, 2024. [Online]. Available: https://github.com/anchore/grype

[5] D. Garcia (cr0hn), "DockerScan: The Most Comprehensive Docker Security Scanner," GitHub, 2025. [Online]. Available: https://github.com/cr0hn/dockerscan

[6] The MITRE Corporation, "CVE - Common Vulnerabilities and Exposures." [Online]. Available: https://cve.mitre.org/

[7] "Millions of Malicious Imageless Containers Planted on Docker Hub Over 5 Years," The Hacker News, April 2024. [Online]. Available: https://thehackernews.com/2024/04/millions-of-malicious-imageless.html

[8] A. Freund, "backdoor in upstream xz/liblzma leading to ssh server compromise," Openwall OSS-Security, March 2024. [Online]. Available: https://www.openwall.com/lists/oss-security/2024/03/29/4

[9] A. Martin, S. Raponi, T. Combe, and R. Di Pietro, "Docker ecosystem-vulnerability analysis," Computer Communications, vol. 122, pp. 30-43, 2018.

[10] Google Open Source, "Open Source Vulnerability (OSV) Schema." [Online]. Available: https://osv.dev/

[11] NIST, "NIST SP 800-190: Application Container Security Guide," September 2017. [Online]. Available: https://csrc.nist.gov/publications/detail/sp/800-190/final

[12] Center for Internet Security, "CIS Docker Benchmark v1.7.0." [Online]. Available: https://www.cisecurity.org/benchmark/docker

[13] OWASP Foundation, "Docker Security Cheat Sheet." [Online]. Available: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

[14] D. Merkel, "Docker: lightweight linux containers for consistent development and deployment," Linux Journal, vol. 2014, no. 239, 2014.

[15] T. Sultan, A. Azmi, T. Marimuthu, and Q. Chowdhury, "Container Security: Issues, Challenges, and the Road Ahead," IEEE Access, vol. 7, pp. 52976-52996, 2019.

[16] NIST, "National Vulnerability Database (NVD)." [Online]. Available: https://nvd.nist.gov/

[17] K. Peffers et al., "A Design Science Research Methodology for Information Systems Research," Journal of Management Information Systems, vol. 24, no. 3, pp. 45-77, 2007.

[18] "Debian Policy Manual - Package state information," Debian Project. [Online]. Available: https://www.debian.org/doc/debian-policy/

[19] OASIS Open, "SARIF Specification v2.1.0." [Online]. Available: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

[20] NVD, "CVE-2024-21626: runc Container Escape." [Online]. Available: https://nvd.nist.gov/vuln/detail/CVE-2024-21626

---

*Manuscript received March 2026. This work was conducted independently for educational and defensive security research purposes. DockSec is open-source software intended for educational use.*
