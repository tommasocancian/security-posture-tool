import requests
from config import VIRUSTOTAL_API_KEY


def vt_domain_report(domain):

    if not VIRUSTOTAL_API_KEY:
        return {}

    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"

        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }

        r = requests.get(url, headers=headers)

        if r.status_code != 200:
            return {}

        data = r.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0)
        }

    except:
        return {}