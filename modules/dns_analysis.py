import dns.resolver

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for r in answers:
            record = r.to_text()
            if "v=spf1" in record:
                return True, record
        return False, None
    except:
        return False, None


def check_dmarc(domain):
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for r in answers:
            return True, r.to_text()
        return False, None
    except:
        return False, None