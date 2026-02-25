# Security Posture Assessment Tool

## Descrizione
Questo progetto consiste nello sviluppo di un tool di analisi della postura di sicurezza di un dominio internet utilizzando tecniche OSINT.

Il sistema permette di analizzare diversi aspetti della sicurezza, tra cui:

- Configurazione DNS (SPF, DMARC, DKIM)
- Sicurezza dei certificati TLS
- Reputazione del dominio tramite VirusTotal
- Esposizione dell’infrastruttura tramite Shodan
- Analisi della superficie di attacco tramite crt.sh
- Analisi delle tecnologie web
- Generazione di report in formato PDF

## Tecnologie utilizzate

- Python
- Requests
- dnspython
- Shodan API
- VirusTotal API
- ReportLab
- python-dotenv

## Funzionalità principali

- Analisi automatizzata della sicurezza di un dominio
- Calcolo del security score
- Generazione report PDF
- Versionamento del codice tramite Git

## Come eseguire il progetto

1. Installare le dipendenze
2. Attivare l'ambiente virtuale
3. Eseguire:
   python main.py

## Autore
Progetto sviluppato come esercitazione di sicurezza informatica.