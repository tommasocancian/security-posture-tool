import ssl
import socket
from datetime import datetime


def check_tls(domain):
    try:
        # Crea un contesto SSL sicuro con le impostazioni di default del sistema
        context = ssl.create_default_context()

        # Stabilisce una connessione TCP verso la porta HTTPS (443)
        with socket.create_connection((domain, 443), timeout=5) as sock:

            # Avvolge la connessione TCP in un layer TLS cifrato
            with context.wrap_socket(sock, server_hostname=domain) as ssock:

                # Recupera il certificato TLS del server
                cert = ssock.getpeercert()

        # Converte la data di scadenza del certificato in oggetto datetime
        expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')

        # Calcola i giorni rimanenti prima della scadenza del certificato
        days_left = (expiry_date - datetime.utcnow()).days

        # Recupera l'autorità emittente del certificato
        issuer = cert.get("issuer")

        return {
            "valid": True,
            "expiry_date": str(expiry_date),
            "days_left": days_left,
            "issuer": issuer
        }

    except Exception as e:
        # Gestisce errori di connessione, TLS o certificato non valido
        return {
            "valid": False,
            "error": str(e)
        }