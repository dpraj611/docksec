# 🐳 DockSec — How to Run & Test

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| **Python** | 3.9+ | Scanner engine & web server |
| **Docker Desktop** | Latest | Container image inspection |
| **pip** | Latest | Python package manager |

> ⚠️ **Docker Desktop must be running** before starting a scan. The scanner creates temporary containers for inspection.

---

## 1. Installation

```bash
# Clone or navigate to the project
cd docksec

# Install Python dependencies
pip install -r requirements.txt
```

The `requirements.txt` installs:
- `packaging` — version comparison for CVE matching
- `flask` — web server for the frontend UI

---

## 2. Running DockSec

### Option A: Web UI (Recommended)

```bash
python server.py
```

Open **http://localhost:5000** in your browser.

The web UI provides:
- 🔍 **Scanner** — Enter a Docker image name and click "Scan Image"
- 🌐 **NVD Live Search** — Query the National Vulnerability Database in real time
- 📄 **Reports** — View past scan reports

### Option B: CLI Mode

```bash
python main.py <docker-image>
```

Example:
```bash
python main.py nginx:latest
```

---

## 3. Test Inputs

### Recommended Docker Images for Testing

| Image | OS | Expected Findings | Why |
|-------|----|--------------------|-----|
| `nginx:latest` | Debian | LOW–MEDIUM | Modern base, few known CVEs |
| `ubuntu:22.04` | Debian | MEDIUM–HIGH | Older base, glibc/openssl CVEs |
| `alpine:3.18` | Alpine | LOW–MEDIUM | Minimal image, busybox CVEs |
| `python:3.11-slim` | Debian | MEDIUM | Includes openssl, curl, glibc |
| `node:20-slim` | Debian | MEDIUM | Similar to python-slim |
| `debian:bullseye` | Debian | HIGH | Older Debian, many affected packages |
| `ubuntu:20.04` | Debian | HIGH | Older Ubuntu with known CVEs |

### Quick Test via CLI

```bash
# Test 1: Modern NGINX image
python main.py nginx:latest

# Test 2: Older Ubuntu (expect more findings)
python main.py ubuntu:22.04

# Test 3: Minimal Alpine
python main.py alpine:3.18
```

### Quick Test via Web UI

1. Open http://localhost:5000
2. Click any **Quick Scan** button (e.g., `nginx:latest`)
3. Watch the progress steps animate
4. Review the risk assessment, severity breakdown, and vulnerability table

### Testing NVD Live Search

1. Go to the **NVD Live Search** tab
2. Enter a package name: `openssl`, `curl`, `nginx`, `glibc`, `linux kernel`
3. Or enter a specific CVE ID: `CVE-2023-38545`, `CVE-2024-21626`
4. Results are fetched live from the NVD API (may take a few seconds)

> 💡 The NVD API has rate limits: ~5 requests/30 seconds without an API key. The scanner automatically handles this with built-in delays.

---

## 4. Understanding the Output

### Risk Levels

| Level | Meaning | CI/CD Action |
|-------|---------|-------------|
| 🟢 **LOW** | No significant vulnerabilities | ✅ Safe to deploy |
| 🟡 **MEDIUM** | Some medium-severity issues | ⚠️ Review before deploy |
| 🟠 **HIGH** | High-severity vulnerabilities found | 🚫 Recommend blocking |
| 🔴 **CRITICAL** | Critical vulnerabilities detected | ❌ Fails CI/CD (exit code 1) |

### Reports

After each scan, two reports are generated in the `reports/` directory:

- `reports/<image>_report.json` — Machine-readable (for CI/CD pipelines)
- `reports/<image>_report.md` — Human-readable (for audits and reviews)

---

## 5. CVE Database

DockSec uses **two sources** for CVE data:

1. **Local Database** (`data/demo_cves.json`) — 20 curated CVEs covering common Docker packages
2. **NVD Live API** — Real-time search via the NVD API 2.0 (available in the web UI)

### Packages Covered by Local Database

`curl`, `openssl`, `nginx`, `glibc`, `expat`, `tar`, `openssh`, `zlib`, `gcc`, `perl`, `busybox`, `runc`, `kerberos`, `openldap`

---

## 6. API Endpoints (For Integration)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | Start a scan. Body: `{"image": "nginx:latest"}` |
| `GET` | `/api/scan/<id>` | Poll scan status and results |
| `GET` | `/api/reports` | List all generated reports |
| `GET` | `/api/reports/<filename>` | Get a specific report (JSON) |
| `GET` | `/api/nvd/search?keyword=<pkg>` | Search NVD for CVEs by keyword |
| `GET` | `/api/nvd/cve/<CVE-ID>` | Fetch a specific CVE from NVD |
| `GET` | `/api/nvd/recent?days=30` | Recent critical CVEs from NVD |
| `GET` | `/api/health` | Server and Docker health check |

---

## 7. Troubleshooting

| Issue | Solution |
|-------|----------|
| `Docker not found` | Install and start Docker Desktop |
| `Failed to pull image` | Check image name, ensure internet connection |
| `ModuleNotFoundError: flask` | Run `pip install -r requirements.txt` |
| `Port 5000 in use` | Change port in `server.py` or kill the process using port 5000 |
| `NVD search slow` | NVD API rate limiting — wait a few seconds between searches |
| `No vulnerabilities found` | Image may be very recent/patched, or packages not in local CVE database |

---

## 8. Project Structure

```
docksec/
├── main.py                  # CLI entry point
├── server.py                # Web server (Flask API)
├── requirements.txt         # Python dependencies
├── scanner/
│   ├── image_loader.py      # Docker image pull + validation
│   ├── os_detector.py       # OS detection (Debian/Alpine)
│   ├── package_extractor.py # Package inventory extraction
│   ├── cve_matcher.py       # CVE matching against local database
│   ├── risk_engine.py       # Risk scoring algorithm
│   ├── reporter.py          # JSON + Markdown report generation
│   └── nvd_fetcher.py       # NVD API 2.0 live CVE fetching
├── frontend/
│   ├── index.html           # Web UI dashboard
│   ├── style.css            # Dark theme styles
│   └── app.js               # Frontend application logic
├── data/
│   └── demo_cves.json       # Curated CVE database (20 entries)
├── reports/                 # Generated scan reports
└── HOW_TO_RUN.md            # This file
```
