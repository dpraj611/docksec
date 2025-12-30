# DockSec Scan 🐳🔐

A lightweight Docker image vulnerability scanner that inspects container internals, inventories installed packages, matches them against known CVEs, calculates risk scores, and generates security reports — inspired by tools like Trivy and Grype, but built from scratch for learning and extensibility.

---

## 🚀 Why DockSec Scan?

Modern applications rely heavily on container images. A single vulnerable base image can introduce critical risks across environments.

DockSec Scan helps answer one key question:

> **“Is this Docker image safe to run in production?”**

It does this by:
- Inspecting container internals without running services
- Extracting installed system packages
- Matching them against known vulnerabilities
- Producing actionable security reports

---

## 🧠 How It Works (High-Level Workflow)

Docker Image  
→ Temporary Container (read-only inspection)  
→ OS Detection (Debian / Alpine)  
→ Package Inventory (dpkg / apk)  
→ CVE Matching (local database)  
→ Risk Scoring  
→ JSON + Markdown Security Reports  

---

## ✨ Features

- 🐳 Docker image inspection (no persistent containers)
- 🧠 Automatic OS detection (Debian / Alpine)
- 📦 Installed package extraction
- 🚨 CVE matching with severity classification
- 📊 Risk scoring and overall image risk assessment
- 📄 JSON + Markdown report generation
- ⚙️ CLI-based usage
- 🔁 CI/CD ready (fail on CRITICAL vulnerabilities)
- 🪟 Windows, Linux, macOS compatible

---

## 📦 Requirements

- Docker Desktop / Docker Engine
- Python 3.9+

Install dependencies:
```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

Scan any Docker image:

    python main.py nginx:latest

If no image is provided:

    python main.py

Output:

    Usage: python main.py <docker-image>
    Example: python main.py nginx:latest

---

## 📄 Example Output

    📦 Found 150 installed packages

    📄 Reports generated:
      - reports/nginx_latest_report.json
      - reports/nginx_latest_report.md

    🔥 Overall Image Risk: LOW

---

## 🧾 Reports

After a scan, reports are generated in the `reports/` directory:

- **JSON report** → Machine-readable (CI/CD, automation)
- **Markdown report** → Human-readable (GitHub, audits)

Example:

    reports/nginx_latest_report.md

---
## 🔐 CVE Data Source

DockSec currently uses a **small, curated demo CVE dataset** located in `data/demo_cves.json`.

This dataset is intentionally limited and exists to demonstrate:

- CVE matching logic
- Version range evaluation
- Risk scoring and reporting
- Scanner architecture

It is **not** a complete or real-time vulnerability database and should not be used
for production-grade vulnerability assessment.

The scanner architecture is designed so this dataset can later be replaced with
live sources such as **OSV.dev** or **NVD** without major refactoring.

---

## 🔐 CI/CD Integration

DockSec Scan exits with a **non-zero exit code** if **CRITICAL vulnerabilities** are detected.

This allows easy integration into pipelines:

    python main.py my-image:latest || exit 1

---

## ⚠️ Limitations (By Design)

- Uses a **local CVE dataset** (for learning and reproducibility)
- Focuses on **system packages**, not application dependencies
- Not intended to replace full enterprise scanners (yet)

These trade-offs keep the tool:
- Simple
- Understandable
- Easy to extend

---

## 🛡️ Secure Execution Model

DockSec **never executes untrusted containers**.

To eliminate the risk of malicious container behavior, the scanner inspects Docker
images using a **filesystem-only approach**:

- Containers are created in a stopped state using `docker create`
- Image filesystems are extracted using `docker export`
- Package metadata is parsed directly from filesystem data
- Containers are immediately removed after inspection

At no point are container entrypoints, commands, or runtime processes executed.

This design prevents:
- Arbitrary code execution
- Resource exhaustion attacks
- Network-based abuse
- Container escape via runtime exploitation

---

## 🧩 Project Structure

    docksec-scan/
    ├── main.py
    ├── scanner/
    │   ├── image_loader.py
    │   ├── os_detector.py
    │   ├── package_extractor.py
    │   ├── cve_matcher.py
    │   ├── risk_engine.py
    │   └── reporter.py
    ├── data/
    │   └── demo_cves.json
    ├── reports/
    ├── requirements.txt
    └── README.md

---

## 🚀 Future Improvements

- Live CVE feeds (OSV / NVD)
- SBOM generation
- Application dependency scanning
- GitHub Actions workflow
- HTML reports
- Multi-image scanning

---

## 🧑‍💻 Author

Built by **Dhruv Prajapati**  
Focused on security engineering, DevSecOps, and offensive security tooling.

---

## 📜 Disclaimer

This tool is for **educational and defensive security purposes only**.
