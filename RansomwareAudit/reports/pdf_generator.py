from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import json

class PDFReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#667eea'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
    
    def generate_executive_summary(self, report_data, output_path='executive_summary.pdf'):
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        story = []
        
        story.append(Paragraph("Ransomware Risk Assessment", self.title_style))
        story.append(Paragraph("Executive Summary Report", self.styles['Heading2']))
        story.append(Spacer(1, 0.3*inch))
        
        scan_date = datetime.fromisoformat(report_data['timestamp']).strftime('%B %d, %Y at %I:%M %p')
        story.append(Paragraph(f"<b>Scan Date:</b> {scan_date}", self.styles['Normal']))
        story.append(Paragraph(f"<b>Target Directory:</b> {report_data['target_directory']}", self.styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        risk_summary = report_data['risk_summary']
        risk_level = risk_summary['risk_level']
        
        risk_colors = {
            'LOW': colors.green,
            'MEDIUM': colors.orange,
            'HIGH': colors.red,
            'CRITICAL': colors.darkred
        }
        
        story.append(Paragraph("RISK ASSESSMENT", self.styles['Heading2']))
        risk_table_data = [
            ['Risk Level', 'Total Score', 'Files Scanned', 'High-Risk Files'],
            [risk_level, f"{risk_summary['total_score']:.2f}", 
             str(report_data['statistics']['total_files_scanned']),
             str(report_data['statistics']['high_risk_file_count'])]
        ]
        
        risk_table = Table(risk_table_data, colWidths=[2*inch, 1.5*inch, 1.5*inch, 1.5*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 0.3*inch))
        
        if risk_summary.get('behavior_reasons'):
            story.append(Paragraph("KEY FINDINGS", self.styles['Heading2']))
            for reason in risk_summary['behavior_reasons'][:5]:
                story.append(Paragraph(f"• {reason}", self.styles['Normal']))
            story.append(Spacer(1, 0.3*inch))
        
        if risk_summary.get('flagged_files'):
            story.append(PageBreak())
            story.append(Paragraph("HIGH-RISK FILES DETECTED", self.styles['Heading2']))
            
            file_table_data = [['File Path', 'Score', 'Reasons']]
            for file_info in risk_summary['flagged_files'][:20]:
                file_table_data.append([
                    file_info['file'][-48:],
                    str(file_info['score']),
                    "; ".join(file_info.get('reasons', []))[:60]
                ])
            
            file_table = Table(file_table_data, colWidths=[3.2*inch, 0.8*inch, 2.5*inch])
            file_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(file_table)
        
        story.append(Spacer(1, 0.5*inch))
        story.append(Paragraph("RECOMMENDATIONS", self.styles['Heading2']))
        
        if risk_level in ['HIGH', 'CRITICAL']:
            recommendations = [
                "Immediate action required: Isolate affected systems",
                "Review and quarantine all high-risk files",
                "Verify backup integrity before proceeding",
                "Consider engaging incident response team",
                "Implement enhanced monitoring on this directory"
            ]
        elif risk_level == 'MEDIUM':
            recommendations = [
                "Review flagged files for false positives",
                "Increase monitoring frequency",
                "Ensure backups are current",
                "Consider implementing auto-quarantine"
            ]
        else:
            recommendations = [
                "Continue regular monitoring",
                "Maintain current security posture",
                "Schedule next scan in 7 days"
            ]
        
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['Normal']))
        
        doc.build(story)
        print(f"[+] PDF report generated: {output_path}")
        return output_path

def generate_pdf_from_json(json_path, output_path='report.pdf'):
    with open(json_path, 'r') as f:
        report_data = json.load(f)
    
    generator = PDFReportGenerator()
    return generator.generate_executive_summary(report_data, output_path)
