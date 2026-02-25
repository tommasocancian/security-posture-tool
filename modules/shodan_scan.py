import shodan
import socket
from config import SHODAN_API_KEY


def shodan_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)

        api = shodan.Shodan(SHODAN_API_KEY)
        host = api.host(ip)

        return {
            "ip": ip,
            "ports": host.get("ports", []),
            "org": host.get("org"),
            "os": host.get("os")
        }

    except Exception as e:
        return {
            "ip": None,
            "error": str(e)
        }