# Security Policy

## Overview

DockSec is a defensive security tool designed for **educational and learning purposes**.
Security considerations are treated as first-class design concerns within the project.

This document explains the scanner’s threat model and execution safeguards.

---

## 🚫 Untrusted Code Execution

DockSec **does not execute untrusted Docker images**.

The scanner avoids `docker run` entirely and instead inspects image filesystems using:

- `docker create`
- `docker export`

This ensures that:
- Image entrypoints are never executed
- No runtime processes are started
- No network access is granted
- No filesystem writes occur

---

## 🔍 Threat Model

DockSec assumes that scanned Docker images may be **malicious**.

Potential threats considered:
- Fork bombs
- Cryptomining payloads
- Network abuse
- Privilege escalation attempts
- Container escape exploits

These threats are mitigated by **never executing container code**.

---

## ⚠️ Limitations

- DockSec does not perform runtime analysis
- Application-level vulnerabilities are out of scope
- CVE data is sourced from a curated demo dataset
- False positives and false negatives are possible

This project is **not a replacement** for enterprise vulnerability scanners.

---

## 📣 Reporting Security Issues

If you discover a security issue in DockSec itself, please open a GitHub issue
with clear reproduction steps.

This project does not currently operate a private disclosure or bug bounty program.
