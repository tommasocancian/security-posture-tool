import ssl
import socket
from datetime import datetime


def check_tls(domain):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_left = (expiry_date - datetime.utcnow()).days

        issuer = cert.get("issuer")

        return {
            "valid": True,
            "expiry_date": str(expiry_date),
            "days_left": days_left,
            "issuer": issuer
        }

    except Exception as e:
        return {
            "valid": False,
            "error": str(e)
        }