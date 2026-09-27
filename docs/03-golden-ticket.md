# 03 – Golden Ticket

> TODO: Voraussetzungen, Durchführung (Lab), Nachweis & Erkennung.

## Voraussetzungen
- Hash (NTLM/AES) des `krbtgt`-Kontos
- Domänen-SID

## Durchführung (nur im Lab)
- TODO: Schritte dokumentieren

## Erkennung / Gegenmaßnahmen
- `krbtgt`-Passwort zweimal rotieren
- AES statt RC4, PAC-Validierung
- Anomalie-Detection auf TGT-Nutzung
