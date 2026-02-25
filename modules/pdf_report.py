from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
import os


def generate_pdf_report(domain, score, reasons):

    # Crea nome file dinamico con dominio
    filename = f"output/{domain.replace('.', '_')}_report.pdf"

    doc = SimpleDocTemplate(filename)
    styles = getSampleStyleSheet()

    elements = []

    elements.append(Paragraph(f"Security Assessment Report", styles["Heading1"]))
    elements.append(Paragraph(f"Domain: {domain}", styles["Heading2"]))
    elements.append(Paragraph(f"Security Score: {score}/100", styles["Heading2"]))

    elements.append(Paragraph("Risk Findings:", styles["Heading3"]))

    if reasons:
        for r in reasons:
            elements.append(Paragraph(f"- {r}", styles["Normal"]))
    else:
        elements.append(Paragraph("No major risks detected.", styles["Normal"]))

    doc.build(elements)

    print("\nPDF report generato:", filename)