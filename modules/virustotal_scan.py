import requests
from config import VIRUSTOTAL_API_KEY


def vt_domain_report(domain):

    # Se la chiave API non è configurata, non esegue la scansione
    if not VIRUSTOTAL_API_KEY:
        return {}

    try:
        # Endpoint API di VirusTotal per analizzare un dominio
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"

        # Header richiesto per l'autenticazione con l'API
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }

        # Effettua la richiesta HTTP verso VirusTotal
        r = requests.get(url, headers=headers)

        # Se la risposta non è OK, restituisce dati vuoti
        if r.status_code != 200:
            return {}

        data = r.json()

        # Estrae le statistiche dell'ultima analisi di sicurezza
        stats = data["data"]["attributes"]["last_analysis_stats"]

        # Restituisce solo le metriche di sicurezza rilevanti
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0)
        }

    except:
        # Gestione errori di rete, parsing JSON o API
        return {}