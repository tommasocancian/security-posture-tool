from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.enums import TA_CENTER
import os


# Determina il colore dello score in base alla fascia di rischio
def get_score_color(score):
    if score >= 70:
        return colors.green      # Sicurezza buona
    elif score >= 40:
        return colors.orange     # Sicurezza media
    return colors.red            # Sicurezza bassa / critica


def generate_pdf_report(
        domain,
        dns_info,
        tls_info,
        shodan_info,
        vt_info,
        crt_info,
        score,
        reasons
):

    # Assicura che la cartella "output" esista prima di generare il PDF
    os.makedirs("output", exist_ok=True)

    # Costruisce il nome file dinamico basato sul dominio
    filename = f"output/{domain.replace('.', '_')}_report.pdf"

    # Inizializza il documento PDF con margini personalizzati
    doc = SimpleDocTemplate(
        filename,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    # Lista degli elementi che verranno inseriti nel PDF
    elements = []

    # ================= STILI =================

    # Stile base per testi normali
    base_style = ParagraphStyle(
        name="base",
        fontSize=12,
        leading=16,
        spaceAfter=8
    )

    # Stile titolo principale del report
    title_style = ParagraphStyle(
        name="title",
        fontSize=26,
        alignment=TA_CENTER,
        textColor=colors.darkblue,
        spaceAfter=20
    )

    # Stile per i titoli delle sezioni
    section_title = ParagraphStyle(
        name="section_title",
        fontSize=18,
        textColor=colors.darkblue,
        spaceBefore=20,
        spaceAfter=10
    )

    # Stile dello score principale (dimensione grande e colore dinamico)
    score_style = ParagraphStyle(
        name="score",
        fontSize=48,
        alignment=TA_CENTER,
        textColor=get_score_color(score),
        spaceAfter=20
    )

    # ================= HEADER =================

    # Titolo principale del report
    elements.append(Paragraph("Security Assessment Report", title_style))

    # Dominio analizzato
    elements.append(Paragraph(f"Domain: {domain}", base_style))

    elements.append(Spacer(1, 10))

    # Visualizzazione del punteggio complessivo
    elements.append(Paragraph(f"{score}/100", score_style))

    # ================= EXECUTIVE SUMMARY =================

    elements.append(Paragraph("Executive Summary", section_title))

    risk_level = "LOW"

    if score < 40:
        risk_level = "HIGH"
    elif score < 70:
        risk_level = "MEDIUM"

    summary_table = Table([
        ["Risk Level", risk_level],
        ["Total Risks Found", len(reasons) if reasons else 0],
        ["DNS SPF", str(dns_info.get("spf"))],
        ["DNS DMARC", str(dns_info.get("dmarc"))],
        ["TLS Valid", str(tls_info.get("valid"))],
        ["SNI Enabled", str(tls_info.get("sni_used", False))]
    ], colWidths=[200, 250])

    summary_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("PADDING", (0, 0), (-1, -1), 10)
    ]))

    elements.append(summary_table)

    # ================= DNS =================

    # Sezione sicurezza DNS
    elements.append(Paragraph("DNS Security", section_title))

    # Tabella stato SPF e DMARC
    dns_table = Table([
        ["SPF", str(dns_info.get("spf"))],
        ["DMARC", str(dns_info.get("dmarc"))]
    ], colWidths=[150, 300])

    # Stile tabella DNS
    dns_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 10),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
    ]))

    elements.append(dns_table)

    # ================= TLS =================

    # Sezione certificato TLS
    elements.append(Paragraph("TLS Certificate", section_title))

    # Tabella informazioni certificato
    tls_table = Table([
        ["Valid", str(tls_info.get("valid"))],
        ["Expiry", str(tls_info.get("expiry_date"))],
        ["Days Left", str(tls_info.get("days_left"))],
        ["Issuer", str(tls_info.get("issuer"))],
        ["SNI Used", str(tls_info.get("sni_used", False))]
    ], colWidths=[150, 300])

    tls_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 10)
    ]))

    elements.append(tls_table)

    # ================= SHODAN =================

    # Sezione intelligence infrastrutturale
    elements.append(Paragraph("Shodan Intelligence", section_title))

    # Tabella dati OSINT da Shodan
    shodan_table = Table([
        ["IP", str(shodan_info.get("ip"))],
        ["Organization", str(shodan_info.get("org"))],
        ["OS", str(shodan_info.get("os"))],
        ["Ports", str(shodan_info.get("ports"))]
    ], colWidths=[150, 300])

    shodan_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 10)
    ]))

    elements.append(shodan_table)

    # ================= VIRUSTOTAL =================

    # Sezione reputazione dominio
    elements.append(Paragraph("VirusTotal Reputation", section_title))

    # Tabella risultati analisi reputazionale
    vt_table = Table([
        ["Malicious", str(vt_info.get("malicious"))],
        ["Suspicious", str(vt_info.get("suspicious"))],
        ["Harmless", str(vt_info.get("harmless"))]
    ], colWidths=[150, 300])

    vt_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 10)
    ]))

    elements.append(vt_table)

    # ================= SUBDOMAINS =================

    # Sezione superficie di attacco (sottodomini)
    elements.append(Paragraph("Subdomains", section_title))

    elements.append(
        Paragraph(
            f"Found {crt_info.get('count')} subdomains",
            base_style
        )
    )

    # ================= RISKS =================

    # Sezione rischi identificati
    elements.append(Paragraph("Risk Findings", section_title))

    # Se esistono rischi, li mostra in box evidenziati
    if reasons:
        for r in reasons:

            # Box contenente la descrizione del rischio
            box = Table([[Paragraph(r, base_style)]], colWidths=[450])

            box.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.whitesmoke),
                ("BOX", (0, 0), (-1, -1), 1, colors.red),
                ("PADDING", (0, 0), (-1, -1), 12)
            ]))

            elements.append(box)
            elements.append(Spacer(1, 10))

    else:
        # Caso in cui non siano stati rilevati rischi significativi
        elements.append(
            Paragraph("No major risks detected.", base_style)
        )

    # ================= BUILD =================

    # Genera fisicamente il documento PDF
    doc.build(elements)

    # Messaggio di conferma su console
    print("\nPDF report generato:", filename)