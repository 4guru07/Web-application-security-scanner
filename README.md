# SecureScan - Web Application Security & Configuration Auditor

SecureScan is a production-ready, non-intrusive **Web Application Security & Configuration Auditor** built with Python, Flask, SQLite, Bootstrap 5, and ReportLab. 

It provides automated security assessments for web applications, inspecting HTTP Security Headers, SSL/TLS certificate integrity, cookie security flags, CSRF form configuration indicators, and `robots.txt` compliance.

---

## Key Features

- **HTTP Security Header Audit**: Evaluates `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.
- **SSL/TLS Inspector**: Validates HTTPS implementation, certificate authority details, and expiration status.
- **Cookie Security Check**: Verifies `HttpOnly` and `Secure` attributes across session cookies.
- **HTML Form & CSRF Auditor**: Detects missing anti-CSRF tokens and unencrypted HTTP form actions.
- **Robots.txt Analysis**: Identifies path exposure risks in public crawler directives.
- **Risk Posture Score**: Automatically calculates a cumulative 0–100 security score and risk grade.
- **PDF Report Generation**: Exports executive PDF reports generated via `ReportLab`.
- **Analytics Dashboard**: Responsive dashboard featuring interactive Chart.js severity breakdowns and scan history management.

---

## Technology Stack

- **Backend**: Python 3, Flask, Flask-SQLAlchemy, SQLite
- **Audit Engine**: `requests`, `beautifulsoup4`, `lxml`, `validators`
- **Report Engine**: `reportlab`
- **Frontend**: HTML5, Bootstrap 5, Chart.js, Vanilla CSS & JS

---

## Installation & Setup

1. **Navigate to project folder**:
   ```bash
   cd C:\Users\GURU\.gemini\antigravity\scratch\SecureScan
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run Flask application**:
   ```bash
   python app.py
   ```

4. **Access the application**:
   Open browser at `http://127.0.0.1:5000`.

---

## Legal & Ethics Notice

SecureScan operates exclusively as a **passive security auditor**. It does not perform active payload injection, brute-forcing, or destructive testing. Always ensure you have authorization before auditing target websites.
