"""
DockSec Web Server
Flask-based API + frontend server for the DockSec scanner.
"""

import os
import sys
import json
import uuid
import threading
from datetime import datetime

from flask import Flask, request, jsonify, send_from_directory

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.image_loader import check_docker, pull_image
from scanner.os_detector import detect_os
from scanner.package_extractor import extract_packages
from scanner.cve_matcher import match_cves
from scanner.risk_engine import calculate_risk
from scanner.reporter import generate_reports
from scanner.nvd_fetcher import fetch_cves_by_keyword, fetch_cve_by_id, fetch_recent_critical_cves

app = Flask(__name__, static_folder="frontend", static_url_path="/static")

# In-memory scan store
scans = {}


# ─── Frontend Routes ────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("frontend", "index.html")


@app.route("/style.css")
def styles():
    return send_from_directory("frontend", "style.css")


@app.route("/app.js")
def scripts():
    return send_from_directory("frontend", "app.js")


# ─── Scan API ────────────────────────────────────────────────────────

def run_scan(scan_id, image_name):
    """Run a scan in a background thread."""
    scan = scans[scan_id]

    try:
        # Step 1: Check Docker
        scan["status"] = "checking_docker"
        scan["current_step"] = "Checking Docker availability..."
        docker_ok = check_docker()
        if not docker_ok:
            scan["status"] = "error"
            scan["error"] = "Docker is not installed or not running."
            return

        # Step 2: Pull image
        scan["status"] = "pulling_image"
        scan["current_step"] = f"Pulling image: {image_name}..."
        if not pull_image(image_name):
            scan["status"] = "error"
            scan["error"] = f"Failed to pull image: {image_name}"
            return

        # Step 3: Detect OS
        scan["status"] = "detecting_os"
        scan["current_step"] = "Detecting OS inside container..."
        os_type = detect_os(image_name)
        scan["os_type"] = os_type

        # Step 4: Extract packages
        scan["status"] = "extracting_packages"
        scan["current_step"] = "Extracting installed packages..."
        packages = extract_packages(image_name, os_type)
        scan["package_count"] = len(packages)

        # Step 5: Match CVEs
        scan["status"] = "matching_cves"
        scan["current_step"] = "Matching against CVE database..."
        findings = match_cves(packages)

        # Step 6: Calculate risk
        scan["status"] = "calculating_risk"
        scan["current_step"] = "Calculating risk scores..."
        risk_report = calculate_risk(findings)

        # Step 7: Generate reports
        scan["status"] = "generating_reports"
        scan["current_step"] = "Generating security reports..."
        json_report, md_report = generate_reports(image_name, os_type, risk_report)

        # Done
        scan["status"] = "completed"
        scan["current_step"] = "Scan complete!"
        scan["results"] = risk_report
        scan["reports"] = {
            "json": json_report,
            "markdown": md_report
        }
        scan["completed_at"] = datetime.utcnow().isoformat()

    except Exception as e:
        scan["status"] = "error"
        scan["error"] = str(e)


@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.get_json()
    if not data or "image" not in data:
        return jsonify({"error": "Missing 'image' field"}), 400

    image_name = data["image"].strip()
    if not image_name:
        return jsonify({"error": "Image name cannot be empty"}), 400

    scan_id = str(uuid.uuid4())[:8]
    scans[scan_id] = {
        "id": scan_id,
        "image": image_name,
        "status": "queued",
        "current_step": "Queued for scanning...",
        "started_at": datetime.utcnow().isoformat(),
        "os_type": None,
        "package_count": 0,
        "results": None,
        "reports": None,
        "error": None,
        "completed_at": None
    }

    thread = threading.Thread(target=run_scan, args=(scan_id, image_name))
    thread.daemon = True
    thread.start()

    return jsonify({"scan_id": scan_id, "status": "queued"}), 202


@app.route("/api/scan/<scan_id>")
def get_scan(scan_id):
    if scan_id not in scans:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scans[scan_id])


# ─── Reports API ─────────────────────────────────────────────────────

@app.route("/api/reports")
def list_reports():
    reports_dir = os.path.join(os.path.dirname(__file__), "reports")
    if not os.path.exists(reports_dir):
        return jsonify([])

    files = []
    for f in os.listdir(reports_dir):
        if f.endswith(".json"):
            fpath = os.path.join(reports_dir, f)
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                files.append({
                    "filename": f,
                    "image": data.get("image", "unknown"),
                    "overall_risk": data.get("overall_risk", "UNKNOWN"),
                    "generated_at": data.get("generated_at", ""),
                    "finding_count": len(data.get("findings", []))
                })
            except Exception:
                files.append({"filename": f, "image": "unknown"})

    return jsonify(files)


@app.route("/api/reports/<name>")
def get_report(name):
    reports_dir = os.path.join(os.path.dirname(__file__), "reports")
    fpath = os.path.join(reports_dir, name)

    if not os.path.exists(fpath):
        return jsonify({"error": "Report not found"}), 404

    with open(fpath, "r", encoding="utf-8") as f:
        return jsonify(json.load(f))


# ─── NVD Live Search API ─────────────────────────────────────────────

@app.route("/api/nvd/search")
def nvd_search():
    keyword = request.args.get("keyword", "").strip()
    if not keyword:
        return jsonify({"error": "Missing 'keyword' parameter"}), 400

    results = fetch_cves_by_keyword(keyword, max_results=20)
    return jsonify({
        "keyword": keyword,
        "count": len(results),
        "cves": results
    })


@app.route("/api/nvd/cve/<cve_id>")
def nvd_cve(cve_id):
    result = fetch_cve_by_id(cve_id)
    if not result:
        return jsonify({"error": "CVE not found"}), 404
    return jsonify(result)


@app.route("/api/nvd/recent")
def nvd_recent():
    days = request.args.get("days", 30, type=int)
    results = fetch_recent_critical_cves(days=min(days, 120), max_results=20)
    return jsonify({
        "count": len(results),
        "cves": results
    })


# ─── Health Check ─────────────────────────────────────────────────────

@app.route("/api/health")
def health():
    docker_status = check_docker()
    return jsonify({
        "status": "ok",
        "docker": "connected" if docker_status else "not available",
        "timestamp": datetime.utcnow().isoformat()
    })


if __name__ == "__main__":
    print("🚀 DockSec Web Server starting...")
    print("   Open http://localhost:5000 in your browser")
    print("   Press Ctrl+C to stop\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
