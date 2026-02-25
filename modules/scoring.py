def calculate_score(data):

    # Punteggio iniziale massimo
    score = 100

    # Lista delle motivazioni che spiegano la riduzione del punteggio
    reasons = []

    # ---------------- DNS Security ----------------
    # Controlla la presenza dei record SPF e DMARC per la sicurezza email
    if not data["dns"]["spf"]:
        # SPF aiuta a prevenire spoofing delle email
        score -= 10
        reasons.append("SPF mancante")

    if not data["dns"]["dmarc"]:
        # DMARC rafforza la protezione contro phishing e email fraudolente
        score -= 15
        reasons.append("DMARC mancante")

    # ---------------- TLS Security ----------------
    tls = data["tls"]

    # Verifica validità del certificato TLS
    if not tls.get("valid"):
        score -= 30
        reasons.append("Certificato TLS non valido")

    # Giorni rimanenti alla scadenza del certificato
    days_left = tls.get("days_left", 999)

    # Penalizzazioni progressive in base alla vicinanza della scadenza
    if days_left < 7:
        score -= 15
        reasons.append("Certificato in scadenza entro 7 giorni")

    elif days_left < 30:
        score -= 10
        reasons.append("Certificato in scadenza entro 30 giorni")

    elif days_left < 60:
        score -= 5
        reasons.append("Certificato in scadenza entro 60 giorni")

    # ---------------- Reputation Analysis ----------------
    # Analizza la reputazione del dominio tramite VirusTotal o servizi simili
    vt = data["vt"]

    # Numero di segnalazioni malevole e sospette
    malicious = vt.get("malicious", 0)
    suspicious = vt.get("suspicious", 0)

    # Penalizzazione proporzionale alla gravità delle segnalazioni
    score -= malicious * 10
    score -= suspicious * 5

    # Se esistono indicatori di malware, aggiunge una motivazione
    if malicious > 0:
        reasons.append("Indicatori malware rilevati")

    # ---------------- Attack Surface ----------------
    # Analizza la superficie d'attacco tramite numero di sottodomini pubblici
    subdomains = len(data["subdomains"])

    # Penalizzazioni progressive basate sulla quantità di sottodomini esposti
    if subdomains > 300:
        score -= 15
        reasons.append("Elevata superficie di attacco")

    elif subdomains > 150:
        score -= 10
        reasons.append("Molti sottodomini pubblici")

    elif subdomains > 50:
        score -= 5
        reasons.append("Alcuni sottodomini pubblici")

    # Restituisce punteggio non negativo e lista dei rischi
    return max(score, 0), reasons