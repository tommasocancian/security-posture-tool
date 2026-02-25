import requests


def get_subdomains(domain):
    try:
        # Query al servizio crt.sh per recuperare certificati pubblici associati al dominio
        # %25 è l'encoding di "%" per effettuare una ricerca wildcard
        url = f"https://crt.sh/?q=%25.{domain}&output=json"

        # Timeout per evitare blocchi in caso di rete lenta o servizio non raggiungibile
        r = requests.get(url, timeout=10)

        # Se la richiesta fallisce, restituisce una lista vuota
        if r.status_code != 200:
            return []

        data = r.json()

        # Usa un set per evitare duplicati nei sottodomini trovati
        subs = set()

        # Estrae i nomi dei sottodomini dai risultati dei certificati
        for entry in data:
            # Alcuni record possono contenere più domini separati da newline
            names = entry["name_value"].split("\n")

            for n in names:
                subs.add(n.strip())

        # Converte il set in lista prima del ritorno
        return list(subs)

    except:
        # Gestione errori di rete, parsing JSON o risposta non valida
        return []