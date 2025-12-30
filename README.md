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

---

## ▶️ Usage

Scan any Docker image:

```bash
python main.py nginx:latest
