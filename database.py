from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Scan(db.Model):
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500), nullable=False)
    target_name = db.Column(db.String(255), nullable=True, default='N/A')
    target_ip = db.Column(db.String(100), nullable=True, default='N/A')
    domain = db.Column(db.String(255), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    scan_duration = db.Column(db.Float, default=0.0) # in seconds
    risk_score = db.Column(db.Integer, default=100) # 0 to 100
    risk_grade = db.Column(db.String(50), default="Excellent")
    total_vulnerabilities = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    report_path = db.Column(db.String(500), nullable=True)

    findings = db.relationship('Finding', backref='scan', lazy=True, cascade="all, delete-orphan")
    header_audits = db.relationship('HeaderAudit', backref='scan', lazy=True, cascade="all, delete-orphan")
    ssl_audit = db.relationship('SslAudit', backref='scan', uselist=False, lazy=True, cascade="all, delete-orphan")

class Finding(db.Model):
    __tablename__ = 'findings'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False) # High, Medium, Low, Info
    description = db.Column(db.Text, nullable=False)
    recommendation = db.Column(db.Text, nullable=False)
    details = db.Column(db.Text, nullable=True)

class HeaderAudit(db.Model):
    __tablename__ = 'header_audits'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    header_name = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), nullable=False) # Present / Missing
    header_value = db.Column(db.Text, nullable=True)
    recommendation = db.Column(db.Text, nullable=False)

class SslAudit(db.Model):
    __tablename__ = 'ssl_audits'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    is_https = db.Column(db.Boolean, default=False)
    certificate_valid = db.Column(db.Boolean, default=False)
    issuer = db.Column(db.String(255), nullable=True)
    expiry_date = db.Column(db.String(100), nullable=True)
    details = db.Column(db.Text, nullable=True)
