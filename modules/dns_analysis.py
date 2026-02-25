import dns.resolver

def check_spf(domain):
    try:
        # Interroga i record TXT del dominio per trovare il record SPF
        # SPF serve per verificare quali server sono autorizzati a inviare email per il dominio
        answers = dns.resolver.resolve(domain, 'TXT')
        for r in answers:
            record = r.to_text()
            # Controlla se il record contiene la stringa SPF standard
            if "v=spf1" in record:
                return True, record
        # Se nessun record SPF è stato trovato
        return False, None
    except:
        # In caso di errori DNS (dominio inesistente, timeout, ecc.)
        return False, None


def check_dmarc(domain):
    try:
        # DMARC è pubblicato come sottodominio speciale: _dmarc.dominio
        # Serve per politiche anti-phishing e report sulle email fraudolente
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for r in answers:
            # Restituisce il primo record DMARC trovato
            return True, r.to_text()
        # Nessun record DMARC trovato
        return False, None
    except:
        # Gestione errori DNS o mancanza del record
        return False, None