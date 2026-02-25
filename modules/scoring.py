def calculate_score(data):

    # Punteggio di sicurezza iniziale (massimo possibile)
    score = 100
    
    # Lista delle motivazioni che spiegano la riduzione del punteggio
    reasons = []

    # DNS Security
    # Controlla la presenza dei record DNS di sicurezza base
    if not data["dns"]["spf"]:
        # SPF serve a prevenire spoofing delle email
        score -= 10
        reasons.append("SPF mancante")

    if not data["dns"]["dmarc"]:
        # DMARC migliora la protezione contro phishing e email fraudolente
        score -= 15
        reasons.append("DMARC mancante")

    # TLS Security
    # Verifica che il certificato TLS sia valido (connessione cifrata sicura)
    if not data["tls"]["valid"]:
        score -= 30
        reasons.append("Certificato TLS non valido")

    # Controlla i giorni rimanenti alla scadenza del certificato
    # Se la scadenza è vicina, la sicurezza viene considerata più debole
    if data["tls"].get("days_left", 999) < 30:
        score -= 15
        reasons.append("Certificato in scadenza")

    # Reputation
    # Analizza la reputazione tramite VirusTotal o servizio simile
    vt = data["vt"]

    # Se vengono trovati indicatori di malware, il punteggio viene ridotto
    if vt.get("malicious", 0) > 0:
        score -= 30
        reasons.append("Presenza malware rilevata")

    # Surface attack
    # Più sottodomini pubblici sono esposti, maggiore è la superficie d'attacco
    if len(data["subdomains"]) > 200:
        score -= 10
        reasons.append("Troppi sottodomini pubblici")

    # Restituisce il punteggio minimo 0 e la lista delle motivazioni
    return max(score, 0), reasons