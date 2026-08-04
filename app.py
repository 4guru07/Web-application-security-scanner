import os
import csv
import io
import warnings
from urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings('ignore')

from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file, flash, Response
from database import db, Scan, Finding, HeaderAudit, SslAudit
from scanner import PassiveScanner
from utils import validate_url, extract_domain
from report import generate_pdf_report

app = Flask(__name__)
app.config['SECRET_KEY'] = 'securescan-secret-key-production-auditor'

# Detect Vercel serverless environment (read-only filesystem handling)
IS_VERCEL = os.environ.get('VERCEL') == '1' or os.environ.get('AWS_LAMBDA_FUNCTION_NAME') is not None

if IS_VERCEL:
    BASE_DIR = '/tmp'
else:
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
DB_DIR = os.path.join(BASE_DIR, 'database')

os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(DB_DIR, exist_ok=True)

db_path = os.path.join(DB_DIR, 'securescan.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    db.create_all()

def generate_remediation_snippets(missing_headers):
    """Generates ready-to-use Nginx and Apache configuration snippets."""
    nginx_lines = []
    apache_lines = []

    snippets_map = {
        'Content-Security-Policy': {
            'nginx': 'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\' https:; style-src \'self\' \'unsafe-inline\' https:;" always;',
            'apache': 'Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\' https:; style-src \'self\' \'unsafe-inline\' https:;"'
        },
        'Strict-Transport-Security': {
            'nginx': 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
            'apache': 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"'
        },
        'X-Frame-Options': {
            'nginx': 'add_header X-Frame-Options "SAMEORIGIN" always;',
            'apache': 'Header always set X-Frame-Options "SAMEORIGIN"'
        },
        'X-Content-Type-Options': {
            'nginx': 'add_header X-Content-Type-Options "nosniff" always;',
            'apache': 'Header always set X-Content-Type-Options "nosniff"'
        },
        'Referrer-Policy': {
            'nginx': 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
            'apache': 'Header always set Referrer-Policy "strict-origin-when-cross-origin"'
        },
        'Permissions-Policy': {
            'nginx': 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;',
            'apache': 'Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"'
        }
    }

    for header in missing_headers:
        if header in snippets_map:
            nginx_lines.append(snippets_map[header]['nginx'])
            apache_lines.append(snippets_map[header]['apache'])

    return {
        'nginx': "\n".join(nginx_lines) if nginx_lines else "# All recommended security headers are present!",
        'apache': "\n".join(apache_lines) if apache_lines else "# All recommended security headers are present!"
    }

@app.route('/')
def index():
    recent_scans = Scan.query.order_by(Scan.scan_date.desc()).limit(5).all()
    return render_template('index.html', recent_scans=recent_scans)

@app.route('/scan', methods=['POST'])
def start_scan():
    target_input = request.form.get('url', '').strip()
    is_valid, result = validate_url(target_input)

    if not is_valid:
        flash(result, 'error')
        return redirect(url_for('index'))

    target_url = result
    domain = extract_domain(target_url)

    # Execute Audit
    scanner = PassiveScanner(target_url)
    scan_results = scanner.run_full_scan()

    # Save to SQLite DB
    new_scan = Scan(
        target_url=target_url,
        domain=domain,
        scan_duration=scan_results['scan_duration'],
        risk_score=scan_results['risk_score'],
        risk_grade=scan_results['risk_grade'],
        total_vulnerabilities=scan_results['total_vulnerabilities'],
        high_count=scan_results['high_count'],
        medium_count=scan_results['medium_count'],
        low_count=scan_results['low_count']
    )
    db.session.add(new_scan)
    db.session.commit()

    # Add Findings
    for f in scan_results['findings']:
        finding_obj = Finding(
            scan_id=new_scan.id,
            title=f['title'],
            category=f['category'],
            severity=f['severity'],
            description=f['description'],
            recommendation=f['recommendation'],
            details=f.get('details', '')
        )
        db.session.add(finding_obj)

    # Add Header Audits
    for ha in scan_results['header_audits']:
        ha_obj = HeaderAudit(
            scan_id=new_scan.id,
            header_name=ha['header_name'],
            status=ha['status'],
            header_value=ha.get('header_value'),
            recommendation=ha['recommendation']
        )
        db.session.add(ha_obj)

    # Add SSL Info
    ssl_data = scan_results['ssl_info']
    ssl_obj = SslAudit(
        scan_id=new_scan.id,
        is_https=ssl_data.get('is_https', False),
        certificate_valid=ssl_data.get('certificate_valid', False),
        issuer=ssl_data.get('issuer'),
        expiry_date=ssl_data.get('expiry_date'),
        details=ssl_data.get('details')
    )
    db.session.add(ssl_obj)
    db.session.commit()

    # Generate PDF Report
    pdf_filename = f"report_scan_{new_scan.id}_{int(datetime.utcnow().timestamp())}.pdf"
    pdf_path = os.path.join(REPORTS_DIR, pdf_filename)
    try:
        generate_pdf_report(new_scan, pdf_path)
        new_scan.report_path = pdf_filename
        db.session.commit()
    except Exception:
        pass

    return redirect(url_for('report_view', scan_id=new_scan.id))

@app.route('/report/<int:scan_id>')
def report_view(scan_id):
    scan_obj = Scan.query.get_or_404(scan_id)
    missing_headers = [ha.header_name for ha in scan_obj.header_audits if ha.status == 'Missing']
    remediation_snippets = generate_remediation_snippets(missing_headers)
    return render_template('report.html', scan=scan_obj, snippets=remediation_snippets, missing_count=len(missing_headers))

@app.route('/download-pdf/<int:scan_id>')
def download_pdf(scan_id):
    scan_obj = Scan.query.get_or_404(scan_id)
    if not scan_obj.report_path:
        flash("PDF report not available for this scan.", "error")
        return redirect(url_for('report_view', scan_id=scan_id))

    file_path = os.path.join(REPORTS_DIR, scan_obj.report_path)
    if not os.path.exists(file_path):
        generate_pdf_report(scan_obj, file_path)

    return send_file(file_path, as_attachment=True, download_name=f"SecureScan_Report_{scan_obj.domain}_{scan_obj.id}.pdf")

@app.route('/reports-hub')
def reports_hub():
    query = request.args.get('q', '').strip()
    grade_filter = request.args.get('grade', '').strip()

    scans_query = Scan.query

    if query:
        scans_query = scans_query.filter(Scan.target_url.contains(query) | Scan.domain.contains(query))
    if grade_filter:
        scans_query = scans_query.filter(Scan.risk_grade == grade_filter)

    all_scans = scans_query.order_by(Scan.scan_date.desc()).all()
    total_reports = Scan.query.count()

    return render_template('reports_hub.html', scans=all_scans, total_reports=total_reports, search_q=query, current_grade=grade_filter)

@app.route('/export-csv')
def export_csv():
    scans = Scan.query.order_by(Scan.scan_date.desc()).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Target URL', 'Domain', 'Scan Date', 'Duration (s)', 'Risk Score', 'Grade', 'Total Vulnerabilities', 'High', 'Medium', 'Low'])

    for s in scans:
        writer.writerow([
            s.id, s.target_url, s.domain, s.scan_date.strftime('%Y-%m-%d %H:%M:%S'),
            s.scan_duration, s.risk_score, s.risk_grade, s.total_vulnerabilities,
            s.high_count, s.medium_count, s.low_count
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=SecureScan_Audit_History.csv"}
    )

@app.route('/dashboard')
def dashboard():
    total_scans = Scan.query.count()
    avg_score = db.session.query(db.func.avg(Scan.risk_score)).scalar() or 0
    total_high = db.session.query(db.func.sum(Scan.high_count)).scalar() or 0
    total_med = db.session.query(db.func.sum(Scan.medium_count)).scalar() or 0
    total_low = db.session.query(db.func.sum(Scan.low_count)).scalar() or 0

    recent_scans = Scan.query.order_by(Scan.scan_date.desc()).all()

    stats = {
        'total_scans': total_scans,
        'avg_score': round(avg_score, 1),
        'total_high': total_high,
        'total_med': total_med,
        'total_low': total_low
    }

    return render_template('dashboard.html', stats=stats, scans=recent_scans)

@app.route('/delete-scan/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    scan_obj = Scan.query.get_or_404(scan_id)
    db.session.delete(scan_obj)
    db.session.commit()
    flash("Scan record deleted successfully.", "info")
    return redirect(url_for('reports_hub'))

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
