def calculate_score(data):

    score = 100
    reasons = []

    # DNS Security
    if not data["dns"]["spf"]:
        score -= 10
        reasons.append("SPF mancante")

    if not data["dns"]["dmarc"]:
        score -= 15
        reasons.append("DMARC mancante")

    # TLS Security
    if not data["tls"]["valid"]:
        score -= 30
        reasons.append("Certificato TLS non valido")

    if data["tls"].get("days_left", 999) < 30:
        score -= 15
        reasons.append("Certificato in scadenza")

    # Reputation
    vt = data["vt"]

    if vt.get("malicious", 0) > 0:
        score -= 30
        reasons.append("Presenza malware rilevata")

    # Surface attack
    if len(data["subdomains"]) > 200:
        score -= 10
        reasons.append("Troppi sottodomini pubblici")

    return max(score, 0), reasons