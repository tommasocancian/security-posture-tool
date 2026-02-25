from modules.dns_analysis import check_spf, check_dmarc
from modules.tls_check import check_tls
from modules.shodan_scan import shodan_lookup
from modules.virustotal_scan import vt_domain_report
from modules.crtsh import get_subdomains
from modules.scoring import calculate_score
from modules.pdf_report import generate_pdf_report


def analyze(domain):

    print(f"\nAnalisi dominio: {domain}")

    # ---------------- DNS ----------------
    spf_status, spf_record = check_spf(domain)
    dmarc_status, dmarc_record = check_dmarc(domain)

    print("\n--- DNS ---")
    print("SPF:", spf_status)
    print("DMARC:", dmarc_status)

    # ---------------- TLS ----------------
    tls_data = check_tls(domain)

    print("\n--- TLS ---")

    if tls_data["valid"]:
        print("Cert valido")
        print("Scadenza:", tls_data["expiry_date"])
        print("Giorni rimanenti:", tls_data["days_left"])
    else:
        print("Errore TLS:", tls_data.get("error"))

    # ---------------- SHODAN ----------------
    shodan_data = shodan_lookup(domain)

    print("\n--- SHODAN ---")

    if shodan_data.get("ip"):
        print("IP:", shodan_data["ip"])
        print("Org:", shodan_data.get("org"))
        print("OS:", shodan_data.get("os"))
        print("Porte:", shodan_data.get("ports"))
    else:
        print("Shodan non ha dati")

    # ---------------- VIRUSTOTAL ----------------
    vt_data = vt_domain_report(domain)

    print("\n--- VIRUSTOTAL ---")

    if vt_data:
        print("Malicious:", vt_data.get("malicious"))
        print("Suspicious:", vt_data.get("suspicious"))
        print("Harmless:", vt_data.get("harmless"))
    else:
        print("Nessun dato VirusTotal")

    # ---------------- CRT.SH ----------------
    print("\n--- SOTTODOMINI CRT.SH ---")

    subs = get_subdomains(domain)

    if subs:
        print(f"Trovati {len(subs)} sottodomini")
        for s in subs[:10]:
            print("-", s)
    else:
        print("Nessun sottodominio trovato")

    # ---------------- SECURITY SCORING ----------------
    print("\n--- SECURITY SCORE ---")

    data = {
        "dns": {
            "spf": spf_status,
            "dmarc": dmarc_status
        },
        "tls": tls_data,
        "vt": vt_data,
        "subdomains": subs
    }

    score, reasons = calculate_score(data)

    print("Score:", score)
    print("Rischi rilevati:")
    for r in reasons:
        print("-", r)

    # ---------------- PDF REPORT ----------------
    generate_pdf_report(domain, score, reasons)


if __name__ == "__main__":
    domain = input("Dominio: ")
    analyze(domain)