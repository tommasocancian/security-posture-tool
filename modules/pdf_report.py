from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
import os


def generate_pdf_report(domain, score, reasons):

    # Genera il nome del file PDF sostituendo i punti nel dominio con underscore
    # (i punti nei nomi file possono causare problemi in alcuni sistemi)
    filename = f"output/{domain.replace('.', '_')}_report.pdf"

    # Crea il documento PDF
    doc = SimpleDocTemplate(filename)

    # Carica gli stili di testo di default per il PDF
    styles = getSampleStyleSheet()

    # Lista degli elementi che comporranno il contenuto del PDF
    elements = []

    # Titolo principale del report
    elements.append(Paragraph(f"Security Assessment Report", styles["Heading1"]))

    # Informazioni base sul dominio analizzato
    elements.append(Paragraph(f"Domain: {domain}", styles["Heading2"]))

    # Punteggio di sicurezza calcolato
    elements.append(Paragraph(f"Security Score: {score}/100", styles["Heading2"]))

    # Sezione dei rischi individuati
    elements.append(Paragraph("Risk Findings:", styles["Heading3"]))

    # Se sono presenti motivazioni di rischio, le aggiunge come lista
    if reasons:
        for r in reasons:
            elements.append(Paragraph(f"- {r}", styles["Normal"]))
    else:
        # Caso in cui non siano stati trovati rischi rilevanti
        elements.append(Paragraph("No major risks detected.", styles["Normal"]))

    # Genera fisicamente il PDF scrivendo tutti gli elementi nel file
    doc.build(elements)

    # Messaggio di conferma a console
    print("\nPDF report generato:", filename)