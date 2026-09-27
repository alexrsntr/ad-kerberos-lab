# 05 – Detection & Hardening

> TODO: Der defensive Kern des Repos.

## Relevante Event-IDs
- 4768 — TGT angefordert
- 4769 — Service-Ticket angefordert
- 4624 — Anmeldung
- 4672 — Zuweisung von Sonderrechten

## Detection-Ideen
- TGS ohne vorheriges TGT (Silver-Ticket-Indikator)
- Ungewöhnliche Ticket-Lebensdauer / RC4-Nutzung

## Härtungs-Checkliste
- [ ] `krbtgt` regelmäßig (und nach Vorfall doppelt) rotieren
- [ ] RC4 deaktivieren, AES erzwingen
- [ ] Tiering / Privileged Access Management
- [ ] Überwachung & Alerting (SIEM)
