import shodan
import socket
from config import SHODAN_API_KEY


def shodan_lookup(domain):
    try:
        # Risolve il nome dominio in indirizzo IP tramite DNS
        ip = socket.gethostbyname(domain)

        # Inizializza il client Shodan con la chiave API configurata
        api = shodan.Shodan(SHODAN_API_KEY)

        # Recupera informazioni di intelligence sull'host tramite IP
        host = api.host(ip)

        return {
            "ip": ip,
            # Porte esposte trovate sul sistema
            "ports": host.get("ports", []),
            # Organizzazione associata all'IP
            "org": host.get("org"),
            # Sistema operativo (se disponibile)
            "os": host.get("os")
        }

    except Exception as e:
        # Gestione errori (DNS, API Shodan, connessione, ecc.)
        return {
            "ip": None,
            "error": str(e)
        }