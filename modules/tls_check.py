import ssl
import socket
from datetime import datetime, timezone


def check_tls(domain):
    try:
        # Crea un contesto SSL sicuro con le impostazioni di default del sistema
        context = ssl.create_default_context()

        # Stabilisce una connessione TCP verso la porta HTTPS (443)
        with socket.create_connection((domain, 443), timeout=5) as sock:

            # Attiva TLS con SNI (Server Name Indication)
            with context.wrap_socket(sock, server_hostname=domain) as ssock:

                # Recupera il certificato TLS del server
                cert = ssock.getpeercert()

        # Controllo presenza data di scadenza
        if 'notAfter' not in cert:
            return {
                "valid": False,
                "error": "Certificato senza data di scadenza",
                "sni_used": True
            }

        # Converte la data di scadenza in oggetto datetime (UTC)
        expiry_date = datetime.strptime(
            cert['notAfter'],
            '%b %d %H:%M:%S %Y %Z'
        ).replace(tzinfo=timezone.utc)

        # Calcola giorni rimanenti
        days_left = (expiry_date - datetime.now(timezone.utc)).days

        # Recupera autorità emittente
        issuer = cert.get("issuer")

        return {
            "valid": True,
            "expiry_date": str(expiry_date),
            "days_left": days_left,
            "issuer": issuer,
            "sni_used": True
        }

    except Exception as e:
        return {
            "valid": False,
            "error": str(e),
            "sni_used": True
        }