from modules.dns_analysis import check_spf, check_dmarc
from modules.tls_check import check_tls
from modules.shodan_scan import shodan_lookup
from modules.virustotal_scan import vt_domain_report
from modules.crtsh import get_subdomains
from modules.scoring import calculate_score
from modules.pdf_report import generate_pdf_report
from modules.history_manager import save_analysis_history
import re

def validate_domain(domain):

    # Regex per validare un nome dominio:
    # - almeno un sottodominio
    # - solo lettere, numeri e trattini
    # - TLD finale di almeno 2 caratteri
    pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"

    # Controlla se il dominio rispetta il formato atteso
    if re.match(pattern, domain):
        return True

    # Dominio non valido
    return False

def analyze(domain):

    # Avvia l'analisi completa del dominio inserito
    print(f"\nAnalisi dominio: {domain}")

    # ---------------- DNS ----------------
    # Controlla i record di sicurezza email DNS
    spf_status, spf_record = check_spf(domain)
    dmarc_status, dmarc_record = check_dmarc(domain)

    print("\n--- DNS ---")
    print("SPF:", spf_status)
    print("DMARC:", dmarc_status)

    # ---------------- TLS ----------------
    # Analizza la sicurezza del certificato TLS del dominio
    tls_data = check_tls(domain)

    print("\n--- TLS ---")

    if tls_data["valid"]:
        # Mostra informazioni sul certificato se valido
        print("Cert valido")
        print("Scadenza:", tls_data["expiry_date"])
        print("Giorni rimanenti:", tls_data["days_left"])
    else:
        # Mostra l'errore se il controllo TLS fallisce
        print("Errore TLS:", tls_data.get("error"))

    # ---------------- SHODAN ----------------
    # Recupera informazioni di intelligence sulle infrastrutture esposte
    shodan_data = shodan_lookup(domain)

    print("\n--- SHODAN ---")

    if shodan_data.get("ip"):
        # Mostra informazioni sull'host trovato
        print("IP:", shodan_data["ip"])
        print("Org:", shodan_data.get("org"))
        print("OS:", shodan_data.get("os"))
        print("Porte:", shodan_data.get("ports"))
    else:
        print("Shodan non ha dati")

    # ---------------- VIRUSTOTAL ----------------
    # Analizza la reputazione del dominio
    vt_data = vt_domain_report(domain)

    print("\n--- VIRUSTOTAL ---")

    if vt_data:
        print("Malicious:", vt_data.get("malicious"))
        print("Suspicious:", vt_data.get("suspicious"))
        print("Harmless:", vt_data.get("harmless"))
    else:
        print("Nessun dato VirusTotal")

    # ---------------- CRT.SH ----------------
    # Recupera sottodomini pubblicamente indicizzati
    print("\n--- SOTTODOMINI CRT.SH ---")

    subs = get_subdomains(domain)

    if subs:
        print(f"Trovati {len(subs)} sottodomini")

        # Mostra solo i primi 10 sottodomini per evitare output troppo lungo
        for s in subs[:10]:
            print("-", s)
    else:
        print("Nessun sottodominio trovato")

    # ---------------- SECURITY SCORING ----------------
    # Aggrega tutti i dati raccolti per calcolare il punteggio di sicurezza
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

    # Calcola il punteggio di sicurezza e le relative motivazioni
    score, reasons = calculate_score(data)

    print("Score:", score)
    print("Rischi rilevati:")
    for r in reasons:
        print("-", r)

    # ---------------- PDF REPORT ----------------
    # Genera report PDF con i risultati dell'analisi
    generate_pdf_report(
        domain,
        dns_info={
            "spf": spf_status,
            "dmarc": dmarc_status
        },
        tls_info=tls_data,
        shodan_info=shodan_data,
        vt_info=vt_data,
        crt_info={"count": len(subs)},
        score=score,
        reasons=reasons
    )

    save_analysis_history(domain, data)


if __name__ == "__main__":
    # Input interattivo dell'utente
    domain = input("Dominio: ")
    if not validate_domain(domain):
        print("Dominio non valido")
        exit()
        
    analyze(domain)