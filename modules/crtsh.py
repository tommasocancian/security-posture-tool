import requests


def get_subdomains(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"

        r = requests.get(url, timeout=10)

        if r.status_code != 200:
            return []

        data = r.json()
        subs = set()

        for entry in data:
            names = entry["name_value"].split("\n")
            for n in names:
                subs.add(n.strip())

        return list(subs)

    except:
        return []