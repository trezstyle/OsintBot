"""PDF report generation."""
from datetime import datetime
import shutil
import subprocess

import psutil
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

from config import settings
from services.system import format_compliance, recent_failed_logins

def generate_report():
    try:
        path = str(settings.paths.report_file)
        top_processes = subprocess.run(
            ["ps", "-eo", "pid,pcpu,pmem,args", "--sort=-pcpu"],
            capture_output=True, text=True, timeout=5, check=False
        ).stdout.splitlines()[:6]
        failed_logins = recent_failed_logins(5) or "None"
        doc = SimpleDocTemplate(path, pagesize=A4)
        styles = getSampleStyleSheet()
        els = [Paragraph("Cyber-Volt SOC Report", styles["Title"]),
               Spacer(1, 12),
               Paragraph(f"Generated: {datetime.now()}", styles["Normal"]),
               Spacer(1, 12),
               Paragraph("System Status", styles["Heading2"]),
               Paragraph(f"CPU: {psutil.cpu_percent(interval=0.5)}% | RAM: {psutil.virtual_memory().percent}% | Disk: {shutil.disk_usage(settings.paths.root_path).used/shutil.disk_usage(settings.paths.root_path).total*100:.1f}%", styles["Normal"]),
               Spacer(1, 12),
               Paragraph("Top Processes", styles["Heading2"]),
               Paragraph("\n".join(top_processes).replace("\n", "<br/>"), styles["Normal"]),
               Spacer(1, 12),
               Paragraph("Recent Failed Logins", styles["Heading2"]),
               Paragraph(failed_logins.replace("\n", "<br/>"), styles["Normal"]),
               Spacer(1, 12),
               Paragraph("Compliance Audit", styles["Heading2"]),
               Paragraph(format_compliance().replace("\n", "<br/>"), styles["Normal"])]
        doc.build(els)
        return path
    except Exception as e:
        return f"Report failed: {e}"
