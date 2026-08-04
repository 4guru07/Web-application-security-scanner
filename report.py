import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

def generate_pdf_report(scan_obj, output_path):
    """
    Generates a PDF security report using ReportLab for ScanForge.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    doc = SimpleDocTemplate(output_path, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)

    styles = getSampleStyleSheet()
    
    # Custom Palette
    PRIMARY = colors.HexColor("#0F172A") # Slate dark
    SECONDARY = colors.HexColor("#0284C7") # Cyan / Blue
    HIGH_COLOR = colors.HexColor("#DC2626")
    MED_COLOR = colors.HexColor("#D97706")
    LOW_COLOR = colors.HexColor("#059669")
    BG_LIGHT = colors.HexColor("#F8FAFC")

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=24,
        leading=28,
        textColor=PRIMARY,
        spaceAfter=10
    )

    h2_style = ParagraphStyle(
        'DocH2',
        parent=styles['Heading2'],
        fontSize=14,
        leading=18,
        textColor=SECONDARY,
        spaceBefore=12,
        spaceAfter=8
    )

    body_style = ParagraphStyle(
        'DocBody',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#334155")
    )

    story = []

    # Title & Metadata Header
    story.append(Paragraph("ScanForge - Executive Security Audit Report", title_style))
    story.append(HRFlowable(width="100%", thickness=2, color=SECONDARY, spaceAfter=15))

    meta_data = [
        [Paragraph(f"<b>Target URL:</b> {scan_obj.target_url}", body_style), Paragraph(f"<b>Scan Date:</b> {scan_obj.scan_date.strftime('%Y-%m-%d %H:%M:%S UTC')}", body_style)],
        [Paragraph(f"<b>Host / Domain:</b> {getattr(scan_obj, 'target_name', scan_obj.domain)}", body_style), Paragraph(f"<b>Target IP:</b> {getattr(scan_obj, 'target_ip', 'N/A')}", body_style)],
        [Paragraph(f"<b>Risk Score:</b> {scan_obj.risk_score} / 100 ({scan_obj.risk_grade})", body_style), Paragraph(f"<b>Total Findings:</b> {scan_obj.total_vulnerabilities}", body_style)]
    ]
    meta_table = Table(meta_data, colWidths=[270, 270])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), BG_LIGHT),
        ('PADDING', (0,0), (-1,-1), 8),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#E2E8F0")),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 15))

    # Executive Summary Table
    story.append(Paragraph("Vulnerability Severity Breakdown", h2_style))
    summary_data = [
        ["Severity Level", "Count", "Risk Level"],
        ["High Severity", str(scan_obj.high_count), "Immediate Action Needed" if scan_obj.high_count > 0 else "Clean"],
        ["Medium Severity", str(scan_obj.medium_count), "Attention Recommended" if scan_obj.medium_count > 0 else "Clean"],
        ["Low Severity", str(scan_obj.low_count), "Informational / Low Impact"]
    ]
    summary_table = Table(summary_data, colWidths=[180, 100, 260])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PRIMARY),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('PADDING', (0,0), (-1,-1), 6),
        ('ALIGN', (1,0), (1,-1), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('TEXTCOLOR', (0,1), (0,1), HIGH_COLOR),
        ('TEXTCOLOR', (0,2), (0,2), MED_COLOR),
        ('TEXTCOLOR', (0,3), (0,3), LOW_COLOR),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 15))

    # Security Headers Summary
    story.append(Paragraph("HTTP Security Headers Matrix", h2_style))
    header_rows = [["Header Name", "Status", "Recommendation"]]
    for ha in scan_obj.header_audits:
        status_text = f"<font color='{'#059669' if ha.status == 'Present' else '#DC2626'}'><b>{ha.status}</b></font>"
        header_rows.append([
            Paragraph(f"<b>{ha.header_name}</b>", body_style),
            Paragraph(status_text, body_style),
            Paragraph(ha.recommendation, body_style)
        ])
    
    header_table = Table(header_rows, colWidths=[160, 80, 300])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1E293B")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('PADDING', (0,0), (-1,-1), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 15))

    # Detailed Findings
    story.append(Paragraph("Detailed Findings & Audit Results", h2_style))
    if not scan_obj.findings:
        story.append(Paragraph("No significant security posture deficiencies or vulnerabilities detected.", body_style))
    else:
        for idx, f in enumerate(scan_obj.findings, 1):
            sev_color = HIGH_COLOR if f.severity == 'High' else (MED_COLOR if f.severity == 'Medium' else LOW_COLOR)
            
            finding_content = [
                [Paragraph(f"<b>#{idx} {f.title}</b>", ParagraphStyle('FTitle', parent=body_style, textColor=PRIMARY, fontSize=11)),
                 Paragraph(f"<font color='{sev_color.hexval()}'><b>[{f.severity.upper()}]</b></font>", ParagraphStyle('FSev', parent=body_style, alignment=2))],
                [Paragraph(f"<b>Category:</b> {f.category}", body_style), ""],
                [Paragraph(f"<b>Description:</b> {f.description}", body_style), ""],
                [Paragraph(f"<b>Recommendation:</b> {f.recommendation}", body_style), ""]
            ]

            f_table = Table(finding_content, colWidths=[400, 140])
            f_table.setStyle(TableStyle([
                ('SPAN', (0,1), (1,1)),
                ('SPAN', (0,2), (1,2)),
                ('SPAN', (0,3), (1,3)),
                ('BACKGROUND', (0,0), (-1,-1), BG_LIGHT),
                ('PADDING', (0,0), (-1,-1), 6),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#CBD5E1")),
            ]))
            story.append(f_table)
            story.append(Spacer(1, 8))

    doc.build(story)
    return output_path
