import os
import warnings
from urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings('ignore')

from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file, flash

from database import db, Scan, Finding, HeaderAudit, SslAudit
from scanner import PassiveScanner
from utils import validate_url, extract_domain
from report import generate_pdf_report

app = Flask(__name__)
app.config['SECRET_KEY'] = 'securescan-secret-key-production-auditor'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'database', 'securescan.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

REPORTS_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'reports')
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'database'), exist_ok=True)

with app.app_context():
    db.create_all()

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
    generate_pdf_report(new_scan, pdf_path)

    new_scan.report_path = pdf_filename
    db.session.commit()

    return redirect(url_for('report_view', scan_id=new_scan.id))

@app.route('/report/<int:scan_id>')
def report_view(scan_id):
    scan_obj = Scan.query.get_or_404(scan_id)
    return render_template('report.html', scan=scan_obj)

@app.route('/download-pdf/<int:scan_id>')
def download_pdf(scan_id):
    scan_obj = Scan.query.get_or_404(scan_id)
    if not scan_obj.report_path:
        flash("PDF report not available for this scan.", "error")
        return redirect(url_for('report_view', scan_id=scan_id))

    file_path = os.path.join(REPORTS_DIR, scan_obj.report_path)
    if not os.path.exists(file_path):
        # Regenerate if missing
        generate_pdf_report(scan_obj, file_path)

    return send_file(file_path, as_attachment=True, download_name=f"SecureScan_Report_{scan_obj.domain}_{scan_obj.id}.pdf")

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
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
