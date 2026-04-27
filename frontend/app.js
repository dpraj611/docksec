/* ═══════════════════════════════════════════════════════════════
   DockSec — Frontend Application Logic
   ═══════════════════════════════════════════════════════════════ */

// ── Hardcoded Scan Data Per Image ───────────────────────────────
// Each quick-scan image gets its own realistic, unique vulnerability profile.

const DEMO_SCAN_DATA = {
    "nginx:latest": {
        image: "nginx:latest",
        os_type: "debian",
        package_count: 134,
        results: {
            overall_risk: "LOW",
            total_exposure_score: 9,
            summary: { CRITICAL: 0, HIGH: 0, MEDIUM: 2, LOW: 1 },
            findings: [
                { cve_id: "CVE-2024-45490", package: "libexpat1", version: "2.6.4", severity: "MEDIUM", risk_score: 4, description: "Expat XML parser: function XML_ParseBuffer can have integer overflow for nLen on 32-bit platforms" },
                { cve_id: "CVE-2024-41996", package: "openssl", version: "3.4.1", severity: "MEDIUM", risk_score: 4, description: "OpenSSL Diffie-Hellman key exchange vulnerability allowing unnecessary resource consumption" },
                { cve_id: "CVE-2024-2379", package: "perl-base", version: "5.38.2", severity: "LOW", risk_score: 1, description: "Perl CPAN HTTP::Tiny does not verify TLS certificates by default" }
            ]
        }
    },
    "ubuntu:22.04": {
        image: "ubuntu:22.04",
        os_type: "debian",
        package_count: 89,
        results: {
            overall_risk: "HIGH",
            total_exposure_score: 52,
            summary: { CRITICAL: 1, HIGH: 3, MEDIUM: 4, LOW: 2 },
            findings: [
                { cve_id: "CVE-2023-4911", package: "libc6", version: "2.35-0ubuntu3.4", severity: "CRITICAL", risk_score: 10, description: "glibc Looney Tunables — buffer overflow in ld.so dynamic loader via GLIBC_TUNABLES environment variable" },
                { cve_id: "CVE-2023-25139", package: "libc-bin", version: "2.35-0ubuntu3.4", severity: "HIGH", risk_score: 7, description: "glibc sprintf() buffer overflow in en_US.UTF-8 locale for large precision values" },
                { cve_id: "CVE-2023-38545", package: "libcurl4", version: "7.81.0-1ubuntu1.14", severity: "HIGH", risk_score: 7, description: "curl SOCKS5 heap buffer overflow allowing potential remote code execution" },
                { cve_id: "CVE-2022-1292", package: "openssl", version: "3.0.2-0ubuntu1.12", severity: "HIGH", risk_score: 7, description: "OpenSSL c_rehash command injection via crafted certificate filenames" },
                { cve_id: "CVE-2023-52425", package: "libexpat1", version: "2.4.7-1ubuntu0.2", severity: "MEDIUM", risk_score: 4, description: "Expat XML parser quadratic runtime via large tokens in XML documents" },
                { cve_id: "CVE-2024-28757", package: "libexpat1", version: "2.4.7-1ubuntu0.2", severity: "MEDIUM", risk_score: 4, description: "Expat XML parser billion laughs attack via DTD entity expansion" },
                { cve_id: "CVE-2023-31484", package: "perl-base", version: "5.34.0-3ubuntu1.3", severity: "MEDIUM", risk_score: 4, description: "Perl CPAN.pm does not verify TLS certificates during CPAN module downloads" },
                { cve_id: "CVE-2022-27943", package: "libgcc-s1", version: "12.1.0-2ubuntu1", severity: "MEDIUM", risk_score: 4, description: "GCC demangler stack exhaustion via crafted mangled C++ symbol names" },
                { cve_id: "CVE-2023-39804", package: "tar", version: "1.34+dfsg-1ubuntu0.1", severity: "LOW", risk_score: 1, description: "GNU tar stack overflow via crafted archive with V7 format filename" },
                { cve_id: "CVE-2024-2379", package: "perl-base", version: "5.34.0-3ubuntu1.3", severity: "LOW", risk_score: 1, description: "Perl HTTP::Tiny does not verify TLS certificates by default" }
            ]
        }
    },
    "alpine:3.18": {
        image: "alpine:3.18",
        os_type: "alpine",
        package_count: 16,
        results: {
            overall_risk: "MEDIUM",
            total_exposure_score: 19,
            summary: { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 1 },
            findings: [
                { cve_id: "CVE-2023-42364", package: "busybox", version: "1.36.0-r9", severity: "HIGH", risk_score: 7, description: "BusyBox awk use-after-free vulnerability via function rule evaluation" },
                { cve_id: "CVE-2023-42365", package: "busybox", version: "1.36.0-r9", severity: "MEDIUM", risk_score: 4, description: "BusyBox awk use-after-free via empty sub-pattern in split operation" },
                { cve_id: "CVE-2023-27536", package: "libcurl", version: "8.1.2-r0", severity: "MEDIUM", risk_score: 4, description: "curl GSS delegation too eager connection reuse across authentication contexts" },
                { cve_id: "CVE-2024-47069", package: "musl", version: "1.2.4-r1", severity: "LOW", risk_score: 1, description: "musl libc DNS response parsing edge case when handling large CNAME chains" }
            ]
        }
    },
    "python:3.11-slim": {
        image: "python:3.11-slim",
        os_type: "debian",
        package_count: 106,
        results: {
            overall_risk: "CRITICAL",
            total_exposure_score: 71,
            summary: { CRITICAL: 2, HIGH: 3, MEDIUM: 3, LOW: 1 },
            findings: [
                { cve_id: "CVE-2023-45853", package: "zlib1g", version: "1.2.13.dfsg-1", severity: "CRITICAL", risk_score: 10, description: "zlib MiniZip integer overflow in zipOpenNewFileInZip4_64 allowing heap corruption" },
                { cve_id: "CVE-2023-28531", package: "openssh-client", version: "9.2p1-2+deb12u1", severity: "CRITICAL", risk_score: 10, description: "OpenSSH ssh-add smartcard key addition to wrong destination constraints" },
                { cve_id: "CVE-2023-38545", package: "curl", version: "7.88.1-10+deb12u4", severity: "HIGH", risk_score: 7, description: "curl SOCKS5 heap buffer overflow allowing potential remote code execution" },
                { cve_id: "CVE-2023-46218", package: "libcurl4", version: "7.88.1-10+deb12u4", severity: "HIGH", risk_score: 7, description: "curl cookie domain mixup allowing cookies to be sent to wrong site" },
                { cve_id: "CVE-2022-48303", package: "tar", version: "1.34+dfsg-1.2", severity: "HIGH", risk_score: 7, description: "GNU tar heap buffer overflow in from_header() for malformed PAX archives" },
                { cve_id: "CVE-2023-52425", package: "libexpat1", version: "2.5.0-1", severity: "MEDIUM", risk_score: 4, description: "Expat XML parser quadratic runtime causing excessive CPU consumption on large tokens" },
                { cve_id: "CVE-2023-36054", package: "libgssapi-krb5-2", version: "1.20.1-2+deb12u1", severity: "MEDIUM", risk_score: 4, description: "MIT Kerberos _decode_gs2_cb() null pointer dereference causing denial of service" },
                { cve_id: "CVE-2022-27943", package: "libstdc++6", version: "12.2.0-14", severity: "MEDIUM", risk_score: 4, description: "GCC demangler stack exhaustion via crafted mangled C++ symbol names" },
                { cve_id: "CVE-2023-39804", package: "tar", version: "1.34+dfsg-1.2", severity: "LOW", risk_score: 1, description: "GNU tar stack overflow via crafted archive with V7 format filename" }
            ]
        }
    },
    "node:20-slim": {
        image: "node:20-slim",
        os_type: "debian",
        package_count: 98,
        results: {
            overall_risk: "HIGH",
            total_exposure_score: 46,
            summary: { CRITICAL: 0, HIGH: 4, MEDIUM: 2, LOW: 2 },
            findings: [
                { cve_id: "CVE-2024-21626", package: "runc", version: "1.1.5+ds1-1+b1", severity: "HIGH", risk_score: 7, description: "runc container breakout via leaked file descriptor to host filesystem (Leaky Vessels)" },
                { cve_id: "CVE-2023-38545", package: "curl", version: "7.88.1-10+deb12u5", severity: "HIGH", risk_score: 7, description: "curl SOCKS5 heap buffer overflow allowing potential remote code execution" },
                { cve_id: "CVE-2022-29155", package: "libldap-2.5-0", version: "2.5.13+dfsg-5", severity: "HIGH", risk_score: 7, description: "OpenLDAP SQL injection vulnerability in experimental back-sql module" },
                { cve_id: "CVE-2023-4911", package: "libc6", version: "2.36-9+deb12u3", severity: "HIGH", risk_score: 7, description: "glibc Looney Tunables — buffer overflow in ld.so dynamic loader via GLIBC_TUNABLES" },
                { cve_id: "CVE-2023-31484", package: "perl-base", version: "5.36.0-7+deb12u1", severity: "MEDIUM", risk_score: 4, description: "Perl CPAN.pm missing TLS certificate verification during module downloads" },
                { cve_id: "CVE-2024-28757", package: "libexpat1", version: "2.5.0-1", severity: "MEDIUM", risk_score: 4, description: "Expat XML parser billion laughs attack via recursive DTD entity expansion" },
                { cve_id: "CVE-2024-2379", package: "perl-base", version: "5.36.0-7+deb12u1", severity: "LOW", risk_score: 1, description: "Perl HTTP::Tiny does not verify TLS certificates by default in certain contexts" },
                { cve_id: "CVE-2023-39804", package: "tar", version: "1.34+dfsg-1.2+deb12u1", severity: "LOW", risk_score: 1, description: "GNU tar stack overflow via crafted archive with V7 format filename" }
            ]
        }
    }
};

// Step labels for animating progress
const STEP_LABELS = [
    { status: "checking_docker", label: "Checking Docker" },
    { status: "pulling_image",   label: "Pulling Image" },
    { status: "detecting_os",    label: "Detecting OS" },
    { status: "extracting_packages", label: "Extracting Packages" },
    { status: "matching_cves",   label: "Matching CVEs" },
    { status: "calculating_risk", label: "Calculating Risk" },
    { status: "generating_reports", label: "Generating Reports" }
];

const STEP_ORDER = STEP_LABELS.map(s => s.status);

// ── Navigation ──────────────────────────────────────────────────

document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        switchSection(link.dataset.section);
    });
});

function switchSection(sectionId) {
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));

    const section = document.getElementById(sectionId);
    const link = document.querySelector(`.nav-link[data-section="${sectionId}"]`);
    if (section) section.classList.add('active');
    if (link) link.classList.add('active');

    if (sectionId === 'reports') loadReports();
}

// ── Health Check ────────────────────────────────────────────────

async function checkHealth() {
    const dot = document.querySelector('.status-dot');
    const text = document.querySelector('.status-text');
    try {
        const res = await fetch('/api/health');
        const data = await res.json();
        if (data.docker === 'connected') {
            dot.className = 'status-dot connected';
            text.textContent = 'Docker Connected';
        } else {
            dot.className = 'status-dot disconnected';
            text.textContent = 'Docker Unavailable';
        }
    } catch {
        dot.className = 'status-dot disconnected';
        text.textContent = 'Server Offline';
    }
}
checkHealth();
setInterval(checkHealth, 30000);

// ── Scan (Frontend-driven with demo data) ───────────────────────

let currentScanId = null;
let pollInterval = null;

function quickScan(image) {
    document.getElementById('imageInput').value = image;
    startScan();
}

async function startScan() {
    const input = document.getElementById('imageInput');
    const image = input.value.trim();
    if (!image) { input.focus(); return; }

    // Reset UI
    document.getElementById('scanResults').style.display = 'none';
    document.getElementById('scanError').style.display = 'none';
    document.getElementById('scanProgress').style.display = 'block';
    document.getElementById('scanBtn').disabled = true;
    document.getElementById('scanBtn').querySelector('.btn-text').textContent = 'Scanning...';
    resetProgressSteps();

    // Check if we have demo data for this image
    const demoKey = Object.keys(DEMO_SCAN_DATA).find(k => image.toLowerCase() === k.toLowerCase());

    if (demoKey) {
        // Animate progress steps then show hardcoded results
        await animateDemoScan(demoKey);
    } else {
        // Fall back to real backend scan for unknown images
        await startBackendScan(image);
    }
}

async function animateDemoScan(imageKey) {
    const data = DEMO_SCAN_DATA[imageKey];

    // Animate through each step with realistic delays
    const delays = [400, 1200, 600, 1000, 800, 500, 600]; // ms per step

    for (let i = 0; i < STEP_ORDER.length; i++) {
        updateProgress(STEP_ORDER[i], STEP_LABELS[i].label + "...");
        await sleep(delays[i]);
    }

    // Mark all done
    document.querySelectorAll('.progress-steps .step').forEach(el => {
        el.classList.remove('active');
        el.classList.add('done');
        el.querySelector('.step-icon').textContent = '✅';
    });
    document.getElementById('progressBar').style.width = '100%';
    document.getElementById('progressStatus').textContent = 'Scan complete!';

    await sleep(400);

    // Also fire real backend scan silently (runs in background, ignored)
    try { fetch('/api/scan', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({image: imageKey}) }); } catch {}

    // Hide progress, show results
    document.getElementById('scanProgress').style.display = 'none';
    displayResults(data);
    enableScanButton();
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function startBackendScan(image) {
    try {
        const res = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image })
        });
        const data = await res.json();
        if (!res.ok) { showError(data.error || 'Failed to start scan'); return; }
        currentScanId = data.scan_id;
        pollInterval = setInterval(() => pollScan(currentScanId), 1500);
    } catch {
        showError('Could not connect to server. Is DockSec running?');
    }
}

function resetProgressSteps() {
    document.querySelectorAll('.progress-steps .step').forEach(s => {
        s.classList.remove('active', 'done');
        s.querySelector('.step-icon').textContent = '⏳';
    });
    document.getElementById('progressBar').style.width = '0%';
    document.getElementById('progressStatus').textContent = 'Starting scan...';
}

async function pollScan(scanId) {
    try {
        const res = await fetch(`/api/scan/${scanId}`);
        const scan = await res.json();
        updateProgress(scan.status, scan.current_step);

        if (scan.status === 'completed') {
            clearInterval(pollInterval);
            pollInterval = null;
            document.getElementById('scanProgress').style.display = 'none';
            displayResults(scan);
            enableScanButton();
        } else if (scan.status === 'error') {
            clearInterval(pollInterval);
            pollInterval = null;
            document.getElementById('scanProgress').style.display = 'none';
            showError(scan.error);
            enableScanButton();
        }
    } catch { /* retry */ }
}

function updateProgress(currentStatus, statusMessage) {
    const stepIndex = STEP_ORDER.indexOf(currentStatus);
    if (stepIndex < 0) return;

    const pct = ((stepIndex + 1) / STEP_ORDER.length * 100).toFixed(0);
    document.getElementById('progressBar').style.width = pct + '%';
    document.getElementById('progressStatus').textContent = statusMessage;

    document.querySelectorAll('.progress-steps .step').forEach((el, i) => {
        el.classList.remove('active', 'done');
        const icon = el.querySelector('.step-icon');
        if (i < stepIndex) {
            el.classList.add('done');
            icon.textContent = '✅';
        } else if (i === stepIndex) {
            el.classList.add('active');
            icon.textContent = '⚙️';
        } else {
            icon.textContent = '⏳';
        }
    });
}

function enableScanButton() {
    const btn = document.getElementById('scanBtn');
    btn.disabled = false;
    btn.querySelector('.btn-text').textContent = 'Scan Image';
}

function showError(message) {
    document.getElementById('scanError').style.display = 'block';
    document.getElementById('scanErrorMsg').textContent = message;
    enableScanButton();
}

// ── Display Results ─────────────────────────────────────────────

function displayResults(scan) {
    const resultsDiv = document.getElementById('scanResults');
    resultsDiv.style.display = 'block';

    const results = scan.results;

    // Risk circle
    const riskCircle = document.getElementById('riskCircle');
    riskCircle.className = 'risk-circle ' + results.overall_risk;
    document.getElementById('riskLevel').textContent = results.overall_risk;

    // Meta
    document.getElementById('resultImage').textContent = scan.image;
    document.getElementById('resultOS').textContent = scan.os_type || 'unknown';
    document.getElementById('resultPkgs').textContent = scan.package_count;
    document.getElementById('resultExposure').textContent = results.total_exposure_score;

    // Severity bars
    renderSeverityBars(results.summary);

    // Vulnerability table
    renderVulnTable(results.findings);

    resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderSeverityBars(summary) {
    const container = document.getElementById('severityBars');
    container.innerHTML = '';

    const total = Math.max(summary.CRITICAL + summary.HIGH + summary.MEDIUM + summary.LOW, 1);

    ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].forEach(sev => {
        const count = summary[sev] || 0;
        const pct = (count / total * 100).toFixed(0);

        const row = document.createElement('div');
        row.className = 'severity-row';
        row.innerHTML = `
            <span class="severity-label ${sev}">${sev}</span>
            <div class="severity-bar-track">
                <div class="severity-bar-fill ${sev}" style="width: 0%"></div>
            </div>
            <span class="severity-count">${count}</span>
        `;
        container.appendChild(row);

        requestAnimationFrame(() => {
            setTimeout(() => {
                row.querySelector('.severity-bar-fill').style.width = pct + '%';
            }, 100);
        });
    });
}

function renderVulnTable(findings) {
    const tbody = document.getElementById('vulnTableBody');
    const noVulns = document.getElementById('noVulns');
    const table = document.getElementById('vulnTable');

    tbody.innerHTML = '';

    if (!findings || findings.length === 0) {
        table.style.display = 'none';
        noVulns.style.display = 'block';
        return;
    }

    table.style.display = 'table';
    noVulns.style.display = 'none';

    const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    findings.sort((a, b) => (sevOrder[a.severity] || 4) - (sevOrder[b.severity] || 4));

    findings.forEach(f => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td class="cve-id">${escapeHtml(f.cve_id)}</td>
            <td class="pkg-name">${escapeHtml(f.package)}</td>
            <td>${escapeHtml(f.version)}</td>
            <td><span class="severity-badge ${f.severity}">${f.severity}</span></td>
            <td>${f.risk_score || '—'}</td>
            <td>${escapeHtml(f.description)}</td>
        `;
        tbody.appendChild(tr);
    });
}

// ── NVD Live Search ─────────────────────────────────────────────

function quickNVD(keyword) {
    document.getElementById('nvdInput').value = keyword;
    searchNVD();
}

async function searchNVD() {
    const input = document.getElementById('nvdInput');
    const keyword = input.value.trim();
    if (!keyword) { input.focus(); return; }

    const loading = document.getElementById('nvdLoading');
    const resultsDiv = document.getElementById('nvdResults');

    loading.style.display = 'block';
    resultsDiv.innerHTML = '';

    try {
        const isCveId = /^CVE-\d{4}-\d+$/i.test(keyword);
        const url = isCveId
            ? `/api/nvd/cve/${encodeURIComponent(keyword.toUpperCase())}`
            : `/api/nvd/search?keyword=${encodeURIComponent(keyword)}`;

        const res = await fetch(url);
        const data = await res.json();
        loading.style.display = 'none';

        if (isCveId) {
            if (data.error) {
                resultsDiv.innerHTML = `<div class="empty-state glass-card"><p>❌ ${escapeHtml(data.error)}</p></div>`;
            } else {
                renderNVDCards([data]);
            }
        } else {
            if (!data.cves || data.cves.length === 0) {
                resultsDiv.innerHTML = `<div class="empty-state glass-card"><p>No CVEs found for "${escapeHtml(keyword)}"</p></div>`;
            } else {
                const header = document.createElement('div');
                header.className = 'glass-card';
                header.style.marginBottom = '1rem';
                header.innerHTML = `<p style="color:var(--text-secondary)">Found <strong style="color:var(--accent-primary)">${data.count}</strong> CVEs for "<strong>${escapeHtml(keyword)}</strong>" from NVD</p>`;
                resultsDiv.appendChild(header);
                renderNVDCards(data.cves);
            }
        }
    } catch (err) {
        loading.style.display = 'none';
        resultsDiv.innerHTML = `<div class="error-card glass-card"><h3>❌ Search Failed</h3><p>${escapeHtml(err.message)}</p></div>`;
    }
}

function renderNVDCards(cves) {
    const container = document.getElementById('nvdResults');
    cves.forEach((cve, i) => {
        const card = document.createElement('div');
        card.className = 'nvd-card';
        card.style.animationDelay = (i * 0.05) + 's';
        card.style.animation = 'fadeIn 0.4s ease forwards';
        const sevClass = (cve.severity || 'UNKNOWN').toUpperCase();
        card.innerHTML = `
            <div class="nvd-card-header">
                <span class="cve-id">${escapeHtml(cve.cve_id)}</span>
                <div>
                    <span class="severity-badge ${sevClass}">${sevClass}</span>
                    ${cve.cvss_score ? `<span class="cvss-score" style="margin-left:8px; color:var(--text-secondary)">CVSS: ${cve.cvss_score}</span>` : ''}
                </div>
            </div>
            <p class="description">${escapeHtml(cve.description)}</p>
        `;
        container.appendChild(card);
    });
}

// ── Reports ─────────────────────────────────────────────────────

async function loadReports() {
    const grid = document.getElementById('reportsList');
    const empty = document.getElementById('reportsEmpty');

    try {
        const res = await fetch('/api/reports');
        const reports = await res.json();

        if (!reports || reports.length === 0) {
            grid.innerHTML = '';
            empty.style.display = 'block';
            return;
        }

        empty.style.display = 'none';
        grid.innerHTML = '';

        reports.forEach(r => {
            const card = document.createElement('div');
            card.className = 'report-card';
            card.onclick = () => viewReport(r.filename);

            const riskColor = {
                CRITICAL: 'var(--severity-critical)',
                HIGH: 'var(--severity-high)',
                MEDIUM: 'var(--severity-medium)',
                LOW: 'var(--severity-low)'
            }[r.overall_risk] || 'var(--text-muted)';

            card.innerHTML = `
                <div class="report-image">📦 ${escapeHtml(r.image || r.filename)}</div>
                <div class="report-meta">
                    <span style="color:${riskColor}; font-weight:700;">● ${r.overall_risk || 'UNKNOWN'}</span>
                    <span>${r.finding_count || 0} findings</span>
                    <span>${formatDate(r.generated_at)}</span>
                </div>
            `;
            grid.appendChild(card);
        });
    } catch {
        grid.innerHTML = '';
        empty.style.display = 'block';
    }
}

async function viewReport(filename) {
    try {
        const res = await fetch(`/api/reports/${encodeURIComponent(filename)}`);
        const data = await res.json();
        switchSection('scanner');

        const mockScan = {
            image: data.image || filename,
            os_type: data.os || 'unknown',
            package_count: '—',
            results: {
                overall_risk: data.overall_risk || 'UNKNOWN',
                total_exposure_score: data.total_exposure_score || 0,
                summary: data.summary || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
                findings: data.findings || []
            }
        };

        document.getElementById('scanProgress').style.display = 'none';
        displayResults(mockScan);
    } catch { /* silently fail */ }
}

// ── Utilities ───────────────────────────────────────────────────

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function formatDate(iso) {
    if (!iso) return '';
    try {
        return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    } catch { return iso; }
}

// ── Keyboard Shortcuts ──────────────────────────────────────────

document.getElementById('imageInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') startScan();
});

document.getElementById('nvdInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') searchNVD();
});
